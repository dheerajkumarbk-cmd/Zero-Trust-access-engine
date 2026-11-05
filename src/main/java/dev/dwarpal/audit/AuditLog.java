package dev.dwarpal.audit;

import dev.dwarpal.crypto.Canonical;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Tamper-evident audit trail: an HMAC-SHA256 hash chain.
 *
 * <pre>
 *   mac_n = HMAC(key, canonical(seq_n, at_n, type_n, actor_n, payload_n, mac_{n-1}))
 * </pre>
 * Changing, deleting, inserting or reordering any record breaks every MAC after it. Because the
 * chain is keyed, an attacker with write access to the log but not the key cannot rebuild it.
 *
 * <p>Two limits, both handled operationally: removing records from the <em>end</em> is not visible
 * from the chain alone, so the latest {@link #head()} is periodically copied somewhere the log
 * writer cannot alter (the SIEM); and the key must live outside the log's storage (a KMS or
 * environment secret, never in the repository).
 */
public final class AuditLog {

    public static final String GENESIS = "0".repeat(64);
    public static final int MIN_KEY_BYTES = 32;
    private static final String DOMAIN = "dwarpal/audit/v1";

    private final SecretKey key;
    private final AuditSink sink;
    private long sequence;
    private String lastMac = GENESIS;

    public AuditLog(SecretKey key, AuditSink sink) {
        this.key = requireStrongKey(key);
        this.sink = Objects.requireNonNull(sink, "sink");
    }

    /**
     * Continues a trail that already exists, after a restart: the next record gets
     * {@code resumeFrom.sequence() + 1} and links to {@code resumeFrom.mac()}. The head must come from the
     * verified store itself (for example {@code EncryptedAuditStore.head()}, which checked every record on
     * open) or from a trusted anchor, never from an unauthenticated place: a wrong head is refused by a store
     * that checks continuity, so the writer fails closed rather than forking the chain.
     */
    public AuditLog(SecretKey key, AuditSink sink, Head resumeFrom) {
        this(key, sink);
        Objects.requireNonNull(resumeFrom, "resumeFrom");
        if (resumeFrom.sequence() < 0) {
            throw new IllegalArgumentException("sequence must not be negative");
        }
        if (resumeFrom.mac() == null || !resumeFrom.mac().matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("mac must be 64 lower-case hex characters");
        }
        if (resumeFrom.sequence() == 0 && !GENESIS.equals(resumeFrom.mac())) {
            throw new IllegalArgumentException("an empty trail starts at the genesis MAC");
        }
        this.sequence = resumeFrom.sequence();
        this.lastMac = resumeFrom.mac();
    }

    /** Position of the newest record, for anchoring outside the log. */
    public record Head(long sequence, String mac) {
    }

    public synchronized Head head() {
        return new Head(sequence, lastMac);
    }

    /**
     * Appends one event. The chain only advances after the sink accepted the record, so a failed
     * write leaves no gap; the caller sees the exception and must fail closed.
     */
    public synchronized AuditRecord append(String type, String actor, Instant at, Map<String, String> fields) {
        long next = sequence + 1;
        String payload = Json.object(fields);
        String mac = mac(key, next, at, type, actor, payload, lastMac);
        AuditRecord record = new AuditRecord(next, at, type, actor, payload, lastMac, mac);
        sink.write(record);
        sequence = next;
        lastMac = mac;
        return record;
    }

    /** Result of checking a trail; {@code firstBadSequence} is -1 when the trail is intact. */
    public record Verification(boolean intact, long firstBadSequence, String reason) {
    }

    /**
     * Checks a complete trail from record 1. If {@code expectedHead} is given (from the external
     * anchor), also detects records removed from the end.
     */
    public static Verification verify(List<AuditRecord> records, SecretKey key, Head expectedHead) {
        requireStrongKey(key);
        String prev = GENESIS;
        long expectedSeq = 1;
        for (AuditRecord r : records) {
            if (r.sequence() != expectedSeq) {
                return new Verification(false, expectedSeq, "expected sequence " + expectedSeq + ", found " + r.sequence());
            }
            if (!r.previousMac().equals(prev)) {
                return new Verification(false, r.sequence(), "chain link broken");
            }
            String recomputed = mac(key, r.sequence(), r.at(), r.type(), r.actor(), r.payloadJson(), r.previousMac());
            // Constant-time comparison: no timing side channel on MAC checks.
            if (!MessageDigest.isEqual(recomputed.getBytes(StandardCharsets.US_ASCII),
                    r.mac().getBytes(StandardCharsets.US_ASCII))) {
                return new Verification(false, r.sequence(), "MAC mismatch: record altered");
            }
            prev = r.mac();
            expectedSeq++;
        }
        if (expectedHead != null && (expectedHead.sequence() != expectedSeq - 1 || !expectedHead.mac().equals(prev))) {
            return new Verification(false, expectedSeq, "trail does not reach the anchored head (truncated?)");
        }
        return new Verification(true, -1, "intact");
    }

    /** Whether one record's MAC is right for its own content and link (used by {@link AuditCursor}). */
    static boolean macValid(SecretKey key, AuditRecord r) {
        String recomputed = mac(requireStrongKey(key), r.sequence(), r.at(), r.type(), r.actor(), r.payloadJson(),
                r.previousMac());
        return MessageDigest.isEqual(recomputed.getBytes(StandardCharsets.US_ASCII),
                r.mac().getBytes(StandardCharsets.US_ASCII));
    }

    private static String mac(SecretKey key, long seq, Instant at, String type, String actor, String payload, String prev) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(key);
            return HexFormat.of().formatHex(m.doFinal(
                    Canonical.encode(DOMAIN, Long.toString(seq), at.toString(), type, actor, payload, prev)));
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("unusable audit key", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private static SecretKey requireStrongKey(SecretKey key) {
        Objects.requireNonNull(key, "audit key");
        byte[] encoded = key.getEncoded();
        if (encoded == null || encoded.length < MIN_KEY_BYTES) {
            throw new IllegalArgumentException("audit key must be at least " + MIN_KEY_BYTES + " bytes");
        }
        java.util.Arrays.fill(encoded, (byte) 0);
        return key;
    }
}
