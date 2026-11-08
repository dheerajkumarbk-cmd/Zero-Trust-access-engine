package dev.dwarpal.console;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small, strict reader for the part of CBOR (RFC 8949) that WebAuthn uses: whole numbers, byte strings, text strings,
 * arrays and maps with definite lengths, and the simple values. Anything else, anything nested too deep, anything too large
 * for what is left of the input, and a number too big for a long is refused with an {@link IllegalArgumentException}.
 * Numbers come back as Long, byte strings as byte[], text as String, arrays as List, maps as Map (keys keep their order).
 */
final class Cbor {

    private static final int MAX_DEPTH = 8;
    private static final int MAX_ITEMS = 64;

    /** A value and the offset just after it (the COSE key sits in the middle of the authenticator data). */
    record Read(Object value, int end) {
    }

    private Cbor() {
    }

    static Object decode(byte[] data) {
        Read r = decodePrefix(data, 0);
        if (r.end() != data.length) {
            throw new IllegalArgumentException("trailing bytes after the value");
        }
        return r.value();
    }

    static Read decodePrefix(byte[] data, int offset) {
        int[] pos = {offset};
        Object v = item(data, pos, 0);
        return new Read(v, pos[0]);
    }

    private static Object item(byte[] d, int[] pos, int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("nested too deep");
        }
        int initial = next(d, pos);
        int major = initial >> 5;
        int info = initial & 0x1f;
        if (major == 7) {
            return switch (info) {
                case 20 -> Boolean.FALSE;
                case 21 -> Boolean.TRUE;
                case 22 -> null;
                default -> throw new IllegalArgumentException("simple value not allowed");
            };
        }
        long n = argument(d, pos, info);
        switch (major) {
            case 0:
                return n;
            case 1:
                return -1 - n;
            case 2: {
                byte[] out = new byte[length(d, pos, n)];
                System.arraycopy(d, pos[0], out, 0, out.length);
                pos[0] += out.length;
                return out;
            }
            case 3: {
                int len = length(d, pos, n);
                String s = new String(d, pos[0], len, StandardCharsets.UTF_8);
                pos[0] += len;
                return s;
            }
            case 4: {
                int count = count(n, d, pos);
                List<Object> out = new ArrayList<>();
                for (int i = 0; i < count; i++) {
                    out.add(item(d, pos, depth + 1));
                }
                return out;
            }
            case 5: {
                int count = count(n, d, pos);
                Map<Object, Object> out = new LinkedHashMap<>();
                for (int i = 0; i < count; i++) {
                    Object k = item(d, pos, depth + 1);
                    if (!(k instanceof Long) && !(k instanceof String)) {
                        throw new IllegalArgumentException("a map key must be a number or text");
                    }
                    if (out.containsKey(k)) {
                        throw new IllegalArgumentException("a key appears twice");
                    }
                    out.put(k, item(d, pos, depth + 1));
                }
                return out;
            }
            default:
                throw new IllegalArgumentException("tags are not allowed");
        }
    }

    private static int next(byte[] d, int[] pos) {
        if (pos[0] >= d.length) {
            throw new IllegalArgumentException("ends too soon");
        }
        return d[pos[0]++] & 0xff;
    }

    private static long argument(byte[] d, int[] pos, int info) {
        if (info < 24) {
            return info;
        }
        int bytes = switch (info) {
            case 24 -> 1;
            case 25 -> 2;
            case 26 -> 4;
            case 27 -> 8;
            default -> throw new IllegalArgumentException("indefinite lengths are not allowed");
        };
        long v = 0;
        for (int i = 0; i < bytes; i++) {
            v = (v << 8) | next(d, pos);
        }
        if (v < 0) {
            throw new IllegalArgumentException("number too large");
        }
        return v;
    }

    private static int length(byte[] d, int[] pos, long n) {
        if (n > d.length - pos[0]) {
            throw new IllegalArgumentException("longer than the input");
        }
        return (int) n;
    }

    private static int count(long n, byte[] d, int[] pos) {
        if (n > MAX_ITEMS || n > d.length - pos[0]) {
            throw new IllegalArgumentException("too many items");
        }
        return (int) n;
    }
}
