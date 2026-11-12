package dev.dwarpal.console;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * A software stand-in for a person's device (Windows Hello, a phone, a security key) for the tests: it makes a key pair and
 * answers the way a real authenticator does (CBOR attestation object, authenticator data, signature), so the console's own
 * checks run on real bytes. Each method takes what a test wants to break: the origin, the relying party, the flags, the counter.
 */
final class SoftAuthenticator {

    static final byte UP = 0x01;
    static final byte UV = 0x04;
    static final byte AT = 0x40;

    private final KeyPair pair;
    private final boolean rsa;
    final byte[] credentialId = new byte[32];

    SoftAuthenticator(boolean rsa) throws Exception {
        this.rsa = rsa;
        new SecureRandom().nextBytes(credentialId);
        KeyPairGenerator g = KeyPairGenerator.getInstance(rsa ? "RSA" : "EC");
        if (rsa) {
            g.initialize(2048);
        } else {
            g.initialize(new ECGenParameterSpec("secp256r1"));
        }
        pair = g.generateKeyPair();
    }

    String id() {
        return b64(credentialId);
    }

    // ---- the answers ----------------------------------------------------------------------------------------------------

    /** The evidence for registering: the JSON text the browser would send after navigator.credentials.create(). */
    String attestation(String origin, String rpId, String challenge, byte flags, long counter) throws Exception {
        byte[] clientData = clientData("webauthn.create", origin, challenge);
        ByteArrayOutputStream auth = new ByteArrayOutputStream();
        auth.write(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
        auth.write(flags);
        auth.write(ByteBuffer.allocate(4).putInt((int) counter).array());
        auth.write(new byte[16]);
        auth.write(new byte[]{(byte) (credentialId.length >> 8), (byte) credentialId.length});
        auth.write(credentialId);
        auth.write(coseKey());
        ByteArrayOutputStream obj = new ByteArrayOutputStream();
        obj.write(0xa3);
        obj.write(text("fmt"));
        obj.write(text("none"));
        obj.write(text("attStmt"));
        obj.write(0xa0);
        obj.write(text("authData"));
        obj.write(bytes(auth.toByteArray()));
        return "{\"id\":\"" + id() + "\",\"clientDataJSON\":\"" + b64(clientData) + "\",\"attestationObject\":\"" + b64(obj.toByteArray())
                + "\"}";
    }

    /** The evidence for signing in: the JSON text the browser would send after navigator.credentials.get(). */
    String assertion(String origin, String rpId, String challenge, byte flags, long counter) throws Exception {
        return assertion(origin, rpId, challenge, flags, counter, pair);
    }

    /** The same, signed with another key (a device that is not the registered one). */
    String assertion(String origin, String rpId, String challenge, byte flags, long counter, KeyPair signer) throws Exception {
        byte[] clientData = clientData("webauthn.get", origin, challenge);
        ByteArrayOutputStream auth = new ByteArrayOutputStream();
        auth.write(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
        auth.write(flags);
        auth.write(ByteBuffer.allocate(4).putInt((int) counter).array());
        byte[] authData = auth.toByteArray();
        Signature s = Signature.getInstance(rsa ? "SHA256withRSA" : "SHA256withECDSA");
        s.initSign(signer.getPrivate());
        s.update(authData);
        s.update(sha256(clientData));
        return "{\"id\":\"" + id() + "\",\"clientDataJSON\":\"" + b64(clientData) + "\",\"authenticatorData\":\"" + b64(authData)
                + "\",\"signature\":\"" + b64(s.sign()) + "\"}";
    }

    static KeyPair anotherEcKey() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    // ---- bytes ----------------------------------------------------------------------------------------------------------

    private static byte[] clientData(String type, String origin, String challenge) {
        return ("{\"type\":\"" + type + "\",\"challenge\":\"" + challenge + "\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private byte[] coseKey() throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if (rsa) {
            RSAPublicKey k = (RSAPublicKey) pair.getPublic();
            o.write(0xa4);
            o.write(0x01);
            o.write(0x03);
            o.write(0x03);
            o.write(new byte[]{0x39, 0x01, 0x00});
            o.write(0x20);
            o.write(bytes(unsigned(k.getModulus(), 256)));
            o.write(0x21);
            o.write(bytes(unsigned(k.getPublicExponent(), 3)));
        } else {
            ECPublicKey k = (ECPublicKey) pair.getPublic();
            o.write(0xa5);
            o.write(0x01);
            o.write(0x02);
            o.write(0x03);
            o.write(0x26);
            o.write(0x20);
            o.write(0x01);
            o.write(0x21);
            o.write(bytes(unsigned(k.getW().getAffineX(), 32)));
            o.write(0x22);
            o.write(bytes(unsigned(k.getW().getAffineY(), 32)));
        }
        return o.toByteArray();
    }

    private static byte[] unsigned(BigInteger v, int length) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[length];
        int copy = Math.min(raw.length, length);
        System.arraycopy(raw, raw.length - copy, out, length - copy, copy);
        return out;
    }

    private static byte[] text(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x60 | b.length);
        o.writeBytes(b);
        return o.toByteArray();
    }

    private static byte[] bytes(byte[] b) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if (b.length < 24) {
            o.write(0x40 | b.length);
        } else if (b.length < 256) {
            o.write(0x58);
            o.write(b.length);
        } else {
            o.write(0x59);
            o.write(b.length >> 8);
            o.write(b.length & 0xff);
        }
        o.writeBytes(b);
        return o.toByteArray();
    }

    static byte[] sha256(byte[] in) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(in);
    }

    static String b64(byte[] in) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(in);
    }
}
