package dev.dwarpal.casb;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The result of looking inside some content: the findings, or the fact that the content could not be
 * read (too large, or not text). The decoded text stays inside this object so that a redacted copy can
 * be made; {@link #toString()} never prints it.
 *
 * <p>Text is read as UTF-8, or as UTF-16 when it starts with a byte order mark or is mostly ASCII
 * written as 16-bit units (Windows "Unicode" files); a redacted copy is written in the same encoding.
 * Anything else, such as binary data or text with stray NUL bytes, cannot be cleared and is
 * "uninspectable".
 */
public final class Inspection {

    /** Largest content inspected; larger content counts as uninspectable. */
    public static final int MAX_BYTES = 8 * 1024 * 1024;

    private final List<Finding> findings;
    private final String text;
    private final Charset charset;
    private final boolean truncated;

    private Inspection(List<Finding> findings, String text, Charset charset, boolean truncated) {
        this.findings = List.copyOf(findings);
        this.text = text;
        this.charset = charset;
        this.truncated = truncated;
    }

    private static Inspection unreadable() {
        return new Inspection(List.of(), null, null, false);
    }

    /** Decodes {@code content} as text and runs every detector over it. */
    public static Inspection of(byte[] content) {
        Objects.requireNonNull(content, "content");
        if (content.length > MAX_BYTES) {
            return unreadable();
        }
        Charset cs = detect(content);
        if (cs == null) {
            return unreadable();
        }
        String text;
        try {
            text = cs.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(content)).toString();
        } catch (CharacterCodingException e) {
            return unreadable();
        }
        Detectors.Scan scan = Detectors.scanAll(text);
        return new Inspection(scan.findings(), text, cs, scan.truncated());
    }

    /** UTF-8, or UTF-16 by byte order mark or by the pattern of zero bytes; {@code null} if neither fits. */
    static Charset detect(byte[] c) {
        if (c.length >= 2 && (c[0] & 0xFF) == 0xFF && (c[1] & 0xFF) == 0xFE) {
            return StandardCharsets.UTF_16LE;
        }
        if (c.length >= 2 && (c[0] & 0xFF) == 0xFE && (c[1] & 0xFF) == 0xFF) {
            return StandardCharsets.UTF_16BE;
        }
        int nuls = 0;
        int oddNuls = 0;
        for (int i = 0; i < c.length; i++) {
            if (c[i] == 0) {
                nuls++;
                oddNuls += i & 1;
            }
        }
        if (nuls == 0) {
            return StandardCharsets.UTF_8;
        }
        if (nuls * 4L < c.length) {
            return null; // a few NUL bytes: binary, not text
        }
        if (oddNuls * 10L >= nuls * 9L) {
            return StandardCharsets.UTF_16LE; // ASCII in 16-bit little-endian units: zero high byte at odd offsets
        }
        if ((nuls - oddNuls) * 10L >= nuls * 9L) {
            return StandardCharsets.UTF_16BE;
        }
        return null;
    }

    public boolean inspectable() {
        return text != null;
    }

    public List<Finding> findings() {
        return findings;
    }

    /**
     * True if a type had more findings than the detectors keep, so {@link #findings()} is not
     * complete. Redaction from an incomplete list would leave sensitive values behind.
     */
    public boolean truncated() {
        return truncated;
    }

    /** The text with every finding replaced by {@code [REDACTED:TYPE]}; empty if it could not be read. */
    public Optional<String> redacted() {
        if (text == null) {
            return Optional.empty();
        }
        StringBuilder sb = new StringBuilder(text.length());
        int pos = 0;
        for (Finding f : merged()) {
            if (f.start() > pos) {
                sb.append(text, pos, f.start());
            }
            sb.append("[REDACTED:").append(f.type()).append(']');
            pos = Math.max(pos, f.end());
        }
        sb.append(text, Math.min(pos, text.length()), text.length());
        return Optional.of(sb.toString());
    }

    /** {@link #redacted()} in the encoding the content came in. */
    public Optional<byte[]> redactedBytes() {
        return redacted().map(r -> r.getBytes(charset));
    }

    /** Overlapping findings joined, so one value is never half-redacted. */
    private List<Finding> merged() {
        List<Finding> out = new ArrayList<>();
        for (Finding f : findings) {
            if (!out.isEmpty() && f.start() < out.get(out.size() - 1).end()) {
                Finding last = out.remove(out.size() - 1);
                out.add(new Finding(last.type(), last.start(), Math.max(last.end(), f.end())));
            } else {
                out.add(f);
            }
        }
        return out;
    }

    @Override
    public String toString() {
        return "Inspection[inspectable=" + inspectable() + ", truncated=" + truncated + ", findings=" + findings + "]";
    }
}
