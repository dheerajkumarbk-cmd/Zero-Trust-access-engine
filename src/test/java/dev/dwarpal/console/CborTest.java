package dev.dwarpal.console;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** The strict CBOR reader: what WebAuthn needs is read exactly, and everything else is refused rather than guessed. */
class CborTest {

    private static byte[] b(int... v) {
        byte[] out = new byte[v.length];
        for (int i = 0; i < v.length; i++) {
            out[i] = (byte) v[i];
        }
        return out;
    }

    @Test
    void readsNumbersTextBytesArraysMapsAndSimpleValues() {
        assertEquals(10L, Cbor.decode(b(0x0a)));
        assertEquals(1000L, Cbor.decode(b(0x19, 0x03, 0xe8)));
        assertEquals(-7L, Cbor.decode(b(0x26)));
        assertEquals(-257L, Cbor.decode(b(0x39, 0x01, 0x00)));
        assertEquals("none", Cbor.decode(b(0x64, 'n', 'o', 'n', 'e')));
        assertArrayEquals(b(1, 2, 3), (byte[]) Cbor.decode(b(0x43, 1, 2, 3)));
        assertEquals(List.of(1L, 2L), Cbor.decode(b(0x82, 0x01, 0x02)));
        assertEquals(Map.of(1L, 2L, "a", true), Cbor.decode(b(0xa2, 0x01, 0x02, 0x61, 'a', 0xf5)));
        assertNull(Cbor.decode(b(0xf6)));
    }

    @Test
    void reportsWhereTheValueEndsSoAKeyInsideAuthenticatorDataCanBeCut() {
        Cbor.Read r = Cbor.decodePrefix(b(9, 9, 0xa1, 0x01, 0x02, 7, 7), 2);
        assertEquals(Map.of(1L, 2L), r.value());
        assertEquals(5, r.end());
    }

    @Test
    void refusesWhatItDoesNotUnderstandOrCannotTrust() {
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(b(0x5f, 0x41, 1, 0xff)), "indefinite length");
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(b(0xc1, 0x01)), "a tag");
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(b(0xf7)), "undefined");
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(b(0xfa, 0, 0, 0, 0)), "a float");
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(b(0x01, 0x02)), "trailing bytes");
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(b(0x43, 1, 2)), "a byte string longer than the input");
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(b(0x19, 0x01)), "ends too soon");
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(b(0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)), "too big a number");
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(b(0xa2, 0x01, 0x02, 0x01, 0x03)), "a key twice");
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(b(0xa1, 0x41, 0x01, 0x02)), "a byte string as a key");
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(b(0x9b, 0, 0, 0, 0, 0, 0, 0x10, 0)), "a huge count");
    }

    @Test
    void refusesNestingThatIsTooDeep() {
        byte[] deep = new byte[20];
        for (int i = 0; i < 19; i++) {
            deep[i] = (byte) 0x81;
        }
        deep[19] = 0x01;
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(deep));
    }
}
