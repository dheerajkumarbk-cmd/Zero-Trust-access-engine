package dev.dwarpal.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Unambiguous byte encoding of the things we sign or MAC.
 *
 * <p>Two rules prevent whole classes of signature attacks:
 * <ul>
 *   <li><b>Length prefixes.</b> Naively concatenating "ab"+"c" and "a"+"bc" gives the same bytes,
 *       so a signature over one would verify for the other. Each field is written as a 4-byte
 *       big-endian length followed by its UTF-8 bytes.</li>
 *   <li><b>Domain separation.</b> The first field names the message type and version
 *       (e.g. {@code dwarpal/device-posture/v1}), so a signature made for one purpose can never be
 *       replayed as another.</li>
 * </ul>
 */
public final class Canonical {

    private Canonical() {
    }

    public static byte[] encode(String domain, String... fields) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        write(out, Objects.requireNonNull(domain, "domain"));
        for (String f : fields) {
            write(out, Objects.requireNonNull(f, "field"));
        }
        return out.toByteArray();
    }

    private static void write(ByteArrayOutputStream out, String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        out.writeBytes(ByteBuffer.allocate(4).putInt(bytes.length).array());
        out.writeBytes(bytes);
    }
}
