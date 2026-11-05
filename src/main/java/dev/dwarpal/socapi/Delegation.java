package dev.dwarpal.socapi;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.Validate;

import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * "Acting on behalf of an analyst", signed per request. The console server logs the analyst in and then calls the
 * SOC API; instead of holding every analyst's certificate it presents <i>its own</i> certificate and, with each
 * request, a short assertion naming the analyst, signed with a key that the key ring trusts for exactly this
 * purpose ({@link KeyPurpose#CONSOLE_DELEGATE}). This is the same idea as OAuth 2.0 token exchange (RFC 8693) and
 * OpenID Connect on-behalf-of flows, with the signature bound to the call:
 *
 * <ul>
 *   <li>the method, the path and the SHA-256 of the body are signed, so an assertion cannot be reused for another
 *       call or have its body swapped;</li>
 *   <li>it lives at most {@value #MAX_LIFETIME_SECONDS} seconds and each one can be used once (a bounded replay
 *       store that refuses new assertions when full, never forgets old ones early);</li>
 *   <li>the SOC API still decides what the analyst may do, exactly as for a direct certificate.</li>
 * </ul>
 *
 * Header: {@code Dwarpal-On-Behalf-Of: v1;analyst=<id>;iat=<instant>;exp=<instant>;jti=<id>;kid=<key id>;sig=<base64>}.
 */
public final class Delegation {

    public static final String HEADER = "Dwarpal-On-Behalf-Of";
    public static final int MAX_LIFETIME_SECONDS = 60;
    public static final int MAX_HEADER = 600;
    private static final Pattern JTI = Pattern.compile("[A-Za-z0-9_-]{22,43}");
    private static final Pattern B64 = Pattern.compile("[A-Za-z0-9+/=]{64,120}");

    private Delegation() {
    }

    /** What the console holds: the signing key and the id the key ring knows it by. */
    public static final class Issuer {
        private final PrivateKey key;
        private final String keyId;
        private final Clock clock;
        private final SecureRandom random = new SecureRandom();

        public Issuer(PrivateKey key, String keyId, Clock clock) {
            this.key = Objects.requireNonNull(key, "key");
            this.keyId = Validate.id(keyId, "keyId");
            this.clock = Objects.requireNonNull(clock, "clock");
        }

        /** The header value for one call; {@code body} is the exact request body ({@code null} or empty for a GET). */
        public String header(String analystId, String method, String target, byte[] body) {
            Validate.id(analystId, "analystId");
            Instant iat = clock.instant();
            Instant exp = iat.plusSeconds(MAX_LIFETIME_SECONDS);
            byte[] r = new byte[18];
            random.nextBytes(r);
            String jti = Base64.getUrlEncoder().withoutPadding().encodeToString(r);
            byte[] message = SignedMessages.consoleDelegation(analystId, iat, exp, jti, method, target, sha(body));
            String sig = Ed25519.sign(key, message);
            return "v1;analyst=" + analystId + ";iat=" + iat + ";exp=" + exp + ";jti=" + jti + ";kid=" + keyId + ";sig=" + sig;
        }
    }

    /** Why an assertion was accepted or refused; the reason is for the audit trail, not for the caller. */
    public record Verdict(Optional<String> analystId, String reason) {
        static Verdict refuse(String reason) {
            return new Verdict(Optional.empty(), reason);
        }
    }

    /** What the SOC API holds: the key ring and a bounded store of the identifiers already used. */
    public static final class Verifier {
        private final KeyRing keys;
        private final Clock clock;
        private final int capacity;
        private final Map<String, Instant> used = new LinkedHashMap<>();

        public Verifier(KeyRing keys, Clock clock, int replayCapacity) {
            this.keys = Objects.requireNonNull(keys, "keys");
            this.clock = Objects.requireNonNull(clock, "clock");
            if (replayCapacity < 100 || replayCapacity > 1_000_000) {
                throw new IllegalArgumentException("replay capacity is 100 to 1,000,000");
            }
            this.capacity = replayCapacity;
        }

        public Verdict verify(String header, String method, String target, byte[] body) {
            if (header == null || header.length() > MAX_HEADER) {
                return Verdict.refuse("no assertion, or too long");
            }
            String[] parts = header.split(";", -1);
            if (parts.length != 7 || !parts[0].equals("v1")) {
                return Verdict.refuse("malformed assertion");
            }
            String analyst = field(parts[1], "analyst");
            String iatText = field(parts[2], "iat");
            String expText = field(parts[3], "exp");
            String jti = field(parts[4], "jti");
            String kid = field(parts[5], "kid");
            String sig = field(parts[6], "sig");
            if (analyst == null || iatText == null || expText == null || jti == null || kid == null || sig == null) {
                return Verdict.refuse("malformed assertion");
            }
            if (!JTI.matcher(jti).matches() || !B64.matcher(sig).matches()) {
                return Verdict.refuse("malformed assertion");
            }
            try {
                Validate.id(analyst, "analyst");
                Validate.id(kid, "kid");
            } catch (IllegalArgumentException e) {
                return Verdict.refuse("malformed assertion");
            }
            Instant iat;
            Instant exp;
            try {
                iat = Instant.parse(iatText);
                exp = Instant.parse(expText);
            } catch (java.time.format.DateTimeParseException e) {
                return Verdict.refuse("malformed assertion");
            }
            Instant now = clock.instant();
            if (!exp.isAfter(iat) || Duration.between(iat, exp).getSeconds() > MAX_LIFETIME_SECONDS) {
                return Verdict.refuse("assertion lifetime out of range");
            }
            if (now.isAfter(exp) || iat.isAfter(now.plus(KeyRing.MAX_CLOCK_SKEW))) {
                return Verdict.refuse("assertion expired or dated in the future");
            }
            byte[] message = SignedMessages.consoleDelegation(analyst, iat, exp, jti, method, target, sha(body));
            KeyRing.Result r = keys.verify(KeyPurpose.CONSOLE_DELEGATE, "console", new SignatureProof(kid, iat, sig),
                    message, now, Duration.ofSeconds(MAX_LIFETIME_SECONDS).plus(KeyRing.MAX_CLOCK_SKEW));
            if (!r.valid()) {
                return Verdict.refuse("assertion not verified: " + r.reason());
            }
            synchronized (used) {
                used.values().removeIf(e -> e.isBefore(now));
                if (used.containsKey(jti)) {
                    return Verdict.refuse("assertion already used");
                }
                if (used.size() >= capacity) {
                    return Verdict.refuse("too many assertions in the replay store: refusing new ones");
                }
                used.put(jti, exp);
            }
            return new Verdict(Optional.of(analyst), "verified by " + r.key().keyId());
        }

        private static String field(String part, String name) {
            return part.startsWith(name + "=") ? part.substring(name.length() + 1) : null;
        }
    }

    private static String sha(byte[] body) {
        return Digests.sha256Hex(body == null ? new byte[0] : body);
    }
}
