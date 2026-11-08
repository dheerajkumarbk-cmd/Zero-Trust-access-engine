package dev.dwarpal.console;

import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A real device passkey (WebAuthn, W3C level 2), checked with nothing but the JDK. The person's own device (Windows Hello,
 * a phone, a security key) holds a private key that never leaves it; the console keeps only the public key and asks the
 * device to sign a fresh challenge each time.
 *
 * <p>What is checked, for a sign-in and for a registration: the challenge is the one issued to this person a moment ago and
 * is used once; the origin is this console's own address and the relying party is {@code rpId} (so a look-alike page cannot
 * collect a signature that works here); the device says the person was present and verified (PIN or biometrics); and the
 * signature is good for the stored key. A signature counter that goes backwards is refused. The attestation statement is not
 * evaluated: the console trusts a new key because the person gave their password and PIN to register it, not because of
 * what kind of device it is.
 *
 * <p>Wrong answers share the same growing wait as wrong typed passkeys ({@link ConsoleAuth#unlockWith}).
 */
public final class WebAuthnStepUp implements PasskeyStepUp {

    /** What the browser needs to ask the device to sign. */
    public record Options(String challenge, String rpId, List<String> credentialIds, int timeoutMs) {
        public Options {
            credentialIds = List.copyOf(credentialIds);
        }
    }

    /** What the browser needs to ask the device to make a new passkey. */
    public record Registration(String challenge, String rpId, String userId, String userName, String displayName, int timeoutMs) {
    }

    private enum Purpose { GET, CREATE }

    private record Pending(byte[] challenge, Purpose purpose, Instant expires) {
    }

    private static final Duration CHALLENGE_LIFE = Duration.ofMinutes(2);
    private static final int TIMEOUT_MS = 120_000;
    private static final byte UP = 0x01;
    private static final byte UV = 0x04;
    private static final byte AT = 0x40;
    private static final int ES256 = -7;
    private static final int RS256 = -257;

    private final ConsoleAuth auth;
    private final PasskeyStore store;
    private final String rpId;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private volatile String origin;

    /**
     * @param origin the address the browser shows for this console, such as {@code https://localhost:8443}; set again with
     *               {@link #expectOrigin} when the port is only known after the server has started
     */
    WebAuthnStepUp(ConsoleAuth auth, PasskeyStore store, String rpId, String origin, Clock clock) {
        this.auth = auth;
        this.store = store;
        this.rpId = rpId;
        this.origin = origin;
        this.clock = clock;
    }

    /** A step-up that keeps its public keys in the file (owner-only); the file is created at the first registration. */
    public static WebAuthnStepUp open(ConsoleAuth auth, java.nio.file.Path file, String rpId, String origin, Clock clock) throws IOException {
        return new WebAuthnStepUp(auth, PasskeyStore.open(file), rpId, origin, clock);
    }

    public void expectOrigin(String value) {
        this.origin = value;
    }

    @Override
    public String kind() {
        return "webauthn";
    }

    @Override
    public Optional<Boolean> isSet(String personId) {
        return Optional.of(!store.of(personId).isEmpty());
    }

    // ---- challenges ---------------------------------------------------------------------------------------------------

    private String issue(String person, Purpose purpose) {
        byte[] c = new byte[32];
        random.nextBytes(c);
        pending.put(person, new Pending(c, purpose, clock.instant().plus(CHALLENGE_LIFE)));
        return b64(c);
    }

    /** The challenge issued to this person for this purpose, once: asking again finds nothing. */
    private Optional<byte[]> take(String person, Purpose purpose) {
        Pending p = pending.remove(person);
        if (p == null || p.purpose() != purpose || clock.instant().isAfter(p.expires())) {
            return Optional.empty();
        }
        return Optional.of(p.challenge());
    }

    /** A new challenge for signing in; the person's registered passkeys are the ones allowed to answer. */
    public Options assertionOptions(String person) {
        List<String> ids = new ArrayList<>();
        store.of(person).forEach(c -> ids.add(c.id()));
        return new Options(issue(person, Purpose.GET), rpId, ids, TIMEOUT_MS);
    }

    /** A new challenge for registering a passkey. */
    public Registration registrationOptions(String person, String displayName) {
        return new Registration(issue(person, Purpose.CREATE), rpId, b64(person.getBytes(StandardCharsets.UTF_8)), person,
                displayName, TIMEOUT_MS);
    }

    // ---- the one function the console calls ---------------------------------------------------------------------------

    @Override
    public ConsoleAuth.Authenticated verify(String personId, String evidence, String source) {
        return auth.unlockWith(personId, source, () -> assertionGood(personId, evidence));
    }

    @Override
    public ConsoleAuth.Changed register(ConsoleAuth unused, String subject, String password, String pin, String evidence, String source) {
        ConsoleAuth.Changed proof = auth.proveOwner(subject, password, pin, source);
        if (proof.status() != ConsoleAuth.Change.OK) {
            return proof;
        }
        Optional<PasskeyStore.Credential> made = attestation(subject, evidence);
        if (made.isEmpty()) {
            return ConsoleAuth.Changed.of(ConsoleAuth.Change.WEAK);
        }
        try {
            store.replace(made.get());
        } catch (IOException e) {
            return ConsoleAuth.Changed.of(ConsoleAuth.Change.UNAVAILABLE);
        }
        return ConsoleAuth.Changed.of(ConsoleAuth.Change.OK);
    }

    // ---- signing in ---------------------------------------------------------------------------------------------------

    private boolean assertionGood(String person, String evidence) {
        try {
            JsonValue.JObject j = object(new JsonReader().read(evidence));
            Optional<PasskeyStore.Credential> cred = store.find(person, text(j, "id"));
            Optional<byte[]> challenge = take(person, Purpose.GET);
            byte[] clientData = bytes(j, "clientDataJSON");
            byte[] authData = bytes(j, "authenticatorData");
            byte[] signature = bytes(j, "signature");
            if (cred.isEmpty() || challenge.isEmpty() || !clientDataGood("webauthn.get", clientData, challenge.get())) {
                return false;
            }
            long counter = flagsAndCounter(authData);
            if (counter < 0) {
                return false;
            }
            ByteBuffer signed = ByteBuffer.allocate(authData.length + 32);
            signed.put(authData).put(sha256(clientData));
            PublicKey key = KeyFactory.getInstance(cred.get().alg() == ES256 ? "EC" : "RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(cred.get().publicKey())));
            Signature check = Signature.getInstance(cred.get().alg() == ES256 ? "SHA256withECDSA" : "SHA256withRSA");
            check.initVerify(key);
            check.update(signed.array());
            if (!check.verify(signature)) {
                return false;
            }
            // a counter that stands still or goes back says the key was copied; devices that keep no counter send 0 every time
            if ((counter != 0 || cred.get().signCount() != 0) && counter <= cred.get().signCount()) {
                return false;
            }
            store.counter(cred.get(), counter);
            return true;
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            return false;
        }
    }

    // ---- registering --------------------------------------------------------------------------------------------------

    private Optional<PasskeyStore.Credential> attestation(String person, String evidence) {
        try {
            JsonValue.JObject j = object(new JsonReader().read(evidence));
            String id = text(j, "id");
            Optional<byte[]> challenge = take(person, Purpose.CREATE);
            byte[] clientData = bytes(j, "clientDataJSON");
            if (challenge.isEmpty() || !clientDataGood("webauthn.create", clientData, challenge.get()) || store.taken(id)) {
                return Optional.empty();
            }
            Object top = Cbor.decode(bytes(j, "attestationObject"));
            if (!(top instanceof Map<?, ?> m) || !(m.get("authData") instanceof byte[] authData)) {
                return Optional.empty();
            }
            if (flagsAndCounter(authData) < 0 || (authData[32] & AT) == 0 || authData.length < 55) {
                return Optional.empty();
            }
            int idLength = ((authData[53] & 0xff) << 8) | (authData[54] & 0xff);
            if (idLength < 16 || idLength > 1023 || authData.length < 55 + idLength) {
                return Optional.empty();
            }
            byte[] credId = new byte[idLength];
            System.arraycopy(authData, 55, credId, 0, idLength);
            if (!MessageDigest.isEqual(credId, Base64.getUrlDecoder().decode(id))) {
                return Optional.empty();
            }
            Cbor.Read key = Cbor.decodePrefix(authData, 55 + idLength);
            if (!(key.value() instanceof Map<?, ?> cose) || !(cose.get(3L) instanceof Long alg)) {
                return Optional.empty();
            }
            byte[] spki = alg == ES256 ? ecKey(cose) : alg == RS256 ? rsaKey(cose) : null;
            if (spki == null) {
                return Optional.empty();
            }
            long counter = ByteBuffer.wrap(authData, 33, 4).getInt() & 0xffffffffL;
            return Optional.of(new PasskeyStore.Credential(person, id, alg.intValue(), Base64.getEncoder().encodeToString(spki),
                    counter, clock.instant()));
        } catch (GeneralSecurityException | RuntimeException e) {
            return Optional.empty();
        }
    }

    private static byte[] ecKey(Map<?, ?> cose) throws GeneralSecurityException {
        if (!Long.valueOf(2).equals(cose.get(1L)) || !Long.valueOf(1).equals(cose.get(-1L))
                || !(cose.get(-2L) instanceof byte[] x) || !(cose.get(-3L) instanceof byte[] y) || x.length != 32 || y.length != 32) {
            return null;
        }
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec curve = params.getParameterSpec(ECParameterSpec.class);
        BigInteger px = new BigInteger(1, x);
        BigInteger py = new BigInteger(1, y);
        BigInteger p = ((java.security.spec.ECFieldFp) curve.getCurve().getField()).getP();
        BigInteger left = py.multiply(py).mod(p);
        BigInteger right = px.multiply(px).multiply(px).add(curve.getCurve().getA().multiply(px)).add(curve.getCurve().getB()).mod(p);
        if (!left.equals(right)) {
            return null;
        }
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(px, py), curve)).getEncoded();
    }

    private static byte[] rsaKey(Map<?, ?> cose) throws GeneralSecurityException {
        if (!Long.valueOf(3).equals(cose.get(1L)) || !(cose.get(-1L) instanceof byte[] n) || !(cose.get(-2L) instanceof byte[] e)) {
            return null;
        }
        BigInteger modulus = new BigInteger(1, n);
        if (modulus.bitLength() < 2048) {
            return null;
        }
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, new BigInteger(1, e))).getEncoded();
    }

    // ---- what both directions share -----------------------------------------------------------------------------------

    /** The type, the challenge and the origin in the client data, which the device signs over. */
    private boolean clientDataGood(String type, byte[] clientData, byte[] challenge) {
        JsonValue.JObject cd = object(new JsonReader().read(new String(clientData, StandardCharsets.UTF_8)));
        Optional<JsonValue> cross = cd.get("crossOrigin");
        return type.equals(text(cd, "type"))
                && MessageDigest.isEqual(b64(challenge).getBytes(StandardCharsets.UTF_8), text(cd, "challenge").getBytes(StandardCharsets.UTF_8))
                && MessageDigest.isEqual(origin.getBytes(StandardCharsets.UTF_8), text(cd, "origin").getBytes(StandardCharsets.UTF_8))
                && (cross.isEmpty() || cross.get().equals(JsonValue.bool(false)));
    }

    /**
     * Checks the relying party hash and the flags of the authenticator data (the person was present and verified) and returns
     * the signature counter, or -1 when something is wrong.
     */
    private long flagsAndCounter(byte[] authData) {
        if (authData.length < 37 || !MessageDigest.isEqual(sha256(rpId.getBytes(StandardCharsets.UTF_8)),
                java.util.Arrays.copyOfRange(authData, 0, 32))) {
            return -1;
        }
        byte flags = authData[32];
        if ((flags & UP) == 0 || (flags & UV) == 0) {
            return -1;
        }
        return ByteBuffer.wrap(authData, 33, 4).getInt() & 0xffffffffL;
    }

    private static JsonValue.JObject object(JsonValue v) {
        if (v instanceof JsonValue.JObject o) {
            return o;
        }
        throw new IllegalArgumentException("an object was expected");
    }

    private static String text(JsonValue.JObject o, String key) {
        if (o.get(key).orElse(null) instanceof JsonValue.JString s) {
            return s.value();
        }
        throw new IllegalArgumentException(key + " must be text");
    }

    private static byte[] bytes(JsonValue.JObject o, String key) {
        return Base64.getUrlDecoder().decode(text(o, key));
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(byte[] in) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(in);
    }
}
