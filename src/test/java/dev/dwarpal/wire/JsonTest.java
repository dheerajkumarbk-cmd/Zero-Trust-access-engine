package dev.dwarpal.wire;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The strict JSON reader and writer. Test documents are built with {@code q()} (a quote) and {@code bs()}
 * (a backslash) instead of escape literals, so this file contains no escape sequences.
 */
class JsonTest {

    private static final String Q = String.valueOf((char) 0x22);
    private static final String BS = String.valueOf((char) 0x5C);
    private final JsonReader reader = new JsonReader();

    private static String q(String s) {
        return Q + s + Q;
    }

    private JsonValue read(String s) {
        return reader.read(s.getBytes(StandardCharsets.UTF_8));
    }

    private void rejects(String doc, String why) {
        assertThrows(JsonException.class, () -> read(doc), why);
    }

    @Test
    void readsOrdinaryDocuments() {
        JsonValue.JObject o = (JsonValue.JObject) read("{" + q("a") + ":1, " + q("b") + ":[true,false,null," + q("x") + "],"
                + q("c") + ":{" + q("d") + ":-0.5e+2}}");
        assertEquals(List.of("a", "b", "c"), o.keys(), "member order is kept");
        assertEquals(1, ((JsonValue.JNumber) o.get("a").orElseThrow()).asLong());
        JsonValue.JArray b = (JsonValue.JArray) o.get("b").orElseThrow();
        assertEquals(4, b.size());
        assertEquals(new JsonValue.JString("x"), b.get(3));
        JsonValue.JObject c = (JsonValue.JObject) o.get("c").orElseThrow();
        assertEquals(-50.0, ((JsonValue.JNumber) c.get("d").orElseThrow()).asDouble());
        assertInstanceOf(JsonValue.JNull.class, read(" null "));
    }

    @Test
    void escapesAreDecodedIncludingSurrogatePairs() {
        String doc = q(BS + "u0041" + BS + "n" + BS + "t" + BS + Q + BS + BS + BS + "/" + BS + "ud83d" + BS + "ude00");
        String s = ((JsonValue.JString) read(doc)).value();
        assertEquals("A" + (char) 0x0A + (char) 0x09 + Q + BS + "/" + new String(Character.toChars(0x1F600)), s);
    }

    @Test
    void duplicateKeysAreRejected() {
        rejects("{" + q("role") + ":" + q("user") + "," + q("role") + ":" + q("admin") + "}",
                "two parsers keeping different duplicates is a smuggling bug");
    }

    @Test
    void malformedDocumentsAreRejected() {
        for (String bad : List.of("", "{", "}", "[1,]", "{" + q("a") + ":1,}", "{" + q("a") + " 1}", "[1 2]",
                "tru", "nul", "01", "1.", ".5", "1e", "-", "+1", "NaN", "Infinity", "[1]x", q("a") + q("b"),
                "{'a':1}", q("abc"), "[" + q("a" + (char) 0x0A + "b") + "]", q(BS + "x"), q(BS + "u12"),
                q(BS + "u00zz"), q(BS + "ud83d"), q(BS + "ude00"), q(BS + "ud83dA"), q(BS + "u0000"))) {
            if (bad.equals(q("abc"))) {
                continue; // valid control case, checked below
            }
            rejects(bad, "should reject: " + bad.replace((char) 0x0A, '|'));
        }
        assertEquals("abc", ((JsonValue.JString) read(q("abc"))).value());
    }

    @Test
    void invalidUtf8AndByteOrderMarksAreRejected() {
        assertThrows(JsonException.class, () -> reader.read(new byte[]{'"', (byte) 0xC3, '"'}), "truncated sequence");
        assertThrows(JsonException.class, () -> reader.read(new byte[]{'"', (byte) 0xC0, (byte) 0xAF, '"'}), "overlong '/'");
        assertThrows(JsonException.class, () -> reader.read(new byte[]{'"', (byte) 0xED, (byte) 0xA0, (byte) 0x80, '"'}),
                "encoded surrogate");
        assertThrows(JsonException.class, () -> reader.read(new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, '1'}), "BOM");
    }

    @Test
    void everyLimitHolds() {
        JsonReader small = new JsonReader(new JsonLimits(100, 3, 5, 2, 2, 4, 6));
        assertThrows(JsonException.class, () -> small.read("[" + "1,".repeat(60) + "1]"), "size");
        assertThrows(JsonException.class, () -> small.read("[[[[1]]]]"), "depth");
        small.read("[[[1]]]");
        assertThrows(JsonException.class, () -> small.read(q("abcdef")), "string length");
        assertThrows(JsonException.class, () -> small.read("{" + q("a") + ":1," + q("b") + ":2," + q("c") + ":3}"), "members");
        assertThrows(JsonException.class, () -> small.read("[1,2,3]"), "elements");
        assertThrows(JsonException.class, () -> small.read("12345"), "number length");
        assertThrows(JsonException.class, () -> small.read("[[1,1],[1,1]]"), "total values");
    }

    @Test
    void deepNestingCannotOverflowTheStack() {
        String deep = "[".repeat(100_000) + "]".repeat(100_000);
        JsonReader big = new JsonReader(new JsonLimits(1_000_000, 16, 10, 10, 10, 10, 1_000_000));
        assertThrows(JsonException.class, () -> big.read(deep), "refused at depth 17, long before the stack ends");
    }

    @Test
    void hugeNumbersAreRefusedAndConversionsAreStrict() {
        JsonReader big = new JsonReader(new JsonLimits(1_000_000, 16, 10, 10, 10, 32, 100));
        assertThrows(JsonException.class, () -> big.read("1" + "0".repeat(100_000)), "a million-digit number");
        assertThrows(JsonException.class, () -> ((JsonValue.JNumber) read("1e400")).asDouble(), "infinite");
        assertThrows(JsonException.class, () -> ((JsonValue.JNumber) read("1.5")).asLong(), "not an integer");
        assertThrows(JsonException.class, () -> ((JsonValue.JNumber) read("99999999999999999999")).asLong(), "overflow");
    }

    @Test
    void theWriterEscapesEverythingDangerousAndRoundTrips() {
        String nasty = "a" + Q + BS + (char) 0x0A + (char) 0x0D + (char) 0x00 + (char) 0x1B + (char) 0x2028 + (char) 0x202E
                + (char) 0x2066 + (char) 0xFEFF + "z" + new String(Character.toChars(0x1F600));
        JsonValue doc = JsonValue.object().put("k", nasty).put("n", JsonValue.num(-7)).put("b", JsonValue.bool(true))
                .put("x", JsonValue.nul()).put("arr", new JsonValue.JArray(List.of(JsonValue.str("y")))).build();
        String out = JsonWriter.write(doc);
        for (char bad : new char[]{0x0A, 0x0D, 0x00, 0x1B, 0x2028, 0x202E, 0x2066, 0xFEFF}) {
            assertFalse(out.indexOf(bad) >= 0, "raw control/bidi character in output: " + (int) bad);
        }
        JsonValue back = new JsonReader().read(out.replace(BS + "u0000", ""));
        assertEquals(nasty.replace(String.valueOf((char) 0), ""),
                ((JsonValue.JString) ((JsonValue.JObject) back).get("k").orElseThrow()).value());
        assertThrows(JsonException.class, () -> JsonValue.object().put("k", "1").put("k", "2"), "no duplicate keys out");
    }

    @Test
    void randomBytesNeverCrashTheReader() {
        Random rnd = new Random(42);
        String alphabet = "{}[]:,-+.0123456789eEtrufalsn " + Q + BS;
        int ok = 0;
        for (int i = 0; i < 20_000; i++) {
            StringBuilder sb = new StringBuilder();
            int len = rnd.nextInt(40);
            for (int j = 0; j < len; j++) {
                sb.append(alphabet.charAt(rnd.nextInt(alphabet.length())));
            }
            try {
                read(sb.toString());
                ok++;
            } catch (JsonException expected) {
                // the only exception allowed
            }
        }
        byte[] junk = new byte[256];
        for (int i = 0; i < 5_000; i++) {
            rnd.nextBytes(junk);
            try {
                reader.read(junk);
            } catch (JsonException expected) {
                // fine
            }
        }
        assertTrue(ok >= 0);
    }
}
