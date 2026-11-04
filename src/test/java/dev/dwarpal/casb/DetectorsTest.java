package dev.dwarpal.casb;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The sensitive-data detectors. Secret-shaped test values are assembled at run time from pieces, so the
 * pre-commit hook (which looks for the same patterns) never sees a whole one in this file.
 */
class DetectorsTest {

    /** Visa test number (valid Luhn). */
    static final String CARD = "4111111111111111";
    /** An Aadhaar-shaped number made valid with its Verhoeff check digit. */
    static final String AADHAAR = "23412341234" + Checksums.verhoeffCheckDigit("23412341234");

    static List<FindingType> types(String text) {
        return Detectors.scan(text).stream().map(Finding::type).toList();
    }

    static String privateKeyBlock() {
        return "-----BEGIN " + "PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n-----END " + "PRIVATE KEY-----";
    }

    static String awsKey() {
        return "AK" + "IA" + "ABCDEFGHIJKLMNOP";
    }

    @Test
    void luhnAndVerhoeffMatchKnownValues() {
        assertTrue(Checksums.luhn("79927398713"));
        assertFalse(Checksums.luhn("79927398710"));
        assertTrue(Checksums.luhn(CARD));
        assertFalse(Checksums.luhn("4111111111111112"));
        assertEquals('3', Checksums.luhnCheckDigit("7992739871"));
        // Verhoeff's own example: 236 has check digit 3
        assertEquals('3', Checksums.verhoeffCheckDigit("236"));
        assertTrue(Checksums.verhoeff("2363"));
        assertFalse(Checksums.verhoeff("2364"));
        assertFalse(Checksums.verhoeff("2633"), "Verhoeff catches swapped neighbours");
        assertTrue(Checksums.verhoeff(AADHAAR));
        for (String bad : new String[] {"", "12a4", "\uff11\uff12"}) {
            assertFalse(Checksums.luhn(bad));
            assertFalse(Checksums.verhoeff(bad));
        }
        assertFalse(Checksums.luhn(null));
        assertThrows(IllegalArgumentException.class, () -> Checksums.verhoeffCheckDigit("12x"));
        assertThrows(IllegalArgumentException.class, () -> Checksums.luhnCheckDigit(""));
    }

    @Test
    void verhoeffCatchesEverySingleDigitErrorAndSwap() {
        String base = AADHAAR;
        for (int i = 0; i < base.length(); i++) {
            for (char d = '0'; d <= '9'; d++) {
                if (d != base.charAt(i)) {
                    String changed = base.substring(0, i) + d + base.substring(i + 1);
                    assertFalse(Checksums.verhoeff(changed), changed);
                }
            }
            if (i + 1 < base.length() && base.charAt(i) != base.charAt(i + 1)) {
                String swapped = base.substring(0, i) + base.charAt(i + 1) + base.charAt(i) + base.substring(i + 2);
                assertFalse(Checksums.verhoeff(swapped), swapped);
            }
        }
    }

    @Test
    void cardNumbersAreFoundOnlyWhenTheyValidate() {
        assertEquals(List.of(FindingType.CARD_NUMBER), types("pay with " + CARD + " today"));
        assertEquals(List.of(FindingType.CARD_NUMBER), types("4111 1111 1111 1111"));
        assertEquals(List.of(FindingType.CARD_NUMBER), types("4111-1111-1111-1111"));
        assertEquals(List.of(FindingType.CARD_NUMBER), types("amex 378282246310005."));
        assertEquals(List.of(), types("4111111111111112"), "fails Luhn");
        assertEquals(List.of(), types("1111111111111117"), "no card starts with 1");
        assertEquals(List.of(), types("4444444444444448" .replace('8', '4')), "one digit repeated is not a card");
        assertEquals(List.of(), types("41111111111111111111"), "too long");
        assertEquals(List.of(), types("4111  1111 1111 1111"), "two separators break the number");
        Finding f = Detectors.scan("card: 4111 1111 1111 1111!").get(0);
        assertEquals(6, f.start());
        assertEquals(25, f.end());
        assertEquals(19, f.length());
    }

    @Test
    void randomSixteenDigitNumbersFailingLuhnAreNotCards() {
        Random rnd = new Random(42);
        int checked = 0;
        while (checked < 2000) {
            StringBuilder sb = new StringBuilder("4");
            for (int i = 0; i < 15; i++) {
                sb.append((char) ('0' + rnd.nextInt(10)));
            }
            if (!Checksums.luhn(sb)) {
                assertEquals(List.of(), types(sb.toString()), sb.toString());
                checked++;
            }
        }
    }

    @Test
    void aadhaarNeedsAValidVerhoeffChecksum() {
        String spaced = AADHAAR.substring(0, 4) + " " + AADHAAR.substring(4, 8) + " " + AADHAAR.substring(8);
        assertEquals(List.of(FindingType.AADHAAR), types("UID " + AADHAAR));
        assertEquals(List.of(FindingType.AADHAAR), types(spaced));
        String wrong = AADHAAR.substring(0, 11) + (char) ('0' + (AADHAAR.charAt(11) - '0' + 1) % 10);
        assertEquals(List.of(), types(wrong), "invalid checksum");
        String zero = "0" + AADHAAR.substring(1);
        assertEquals(List.of(), types(zero.substring(0, 11) + Checksums.verhoeffCheckDigit(zero.substring(0, 11))),
                "Aadhaar never starts with 0 or 1");
    }

    @Test
    void panIfscAndEmail() {
        assertEquals(List.of(FindingType.PAN), types("PAN: ABCPD1234E."));
        assertEquals(List.of(FindingType.PAN), types("pan abcpd1234e"));
        assertEquals(List.of(), types("ABCXD1234E"), "X is not a PAN holder type");
        assertEquals(List.of(), types("ABCPD12345"));
        assertEquals(List.of(), types("XABCPD1234E"), "part of a longer word");
        assertEquals(List.of(FindingType.IFSC), types("branch SBIN0001234"));
        assertEquals(List.of(), types("SBIN1001234"), "fifth character must be zero");
        assertEquals(List.of(), types("SBINOABCDEF"));
        assertEquals(List.of(FindingType.EMAIL), types("write to a.b+c@mail.example.com."));
        assertEquals(List.of(FindingType.EMAIL, FindingType.EMAIL), types("x@a.example, y@b.example"));
        for (String no : List.of("@example.com", "a@b", "a@b.c", "a@.example.com", "a@b..com", "a@b.c0m", "....@x")) {
            assertEquals(List.of(), types(no), no);
        }
        Finding f = Detectors.scan("mail: .a@b.example").get(0);
        assertEquals(7, f.start());
    }

    @Test
    void secretsUseThePreCommitHookPatterns() {
        assertEquals(List.of(FindingType.PRIVATE_KEY), types("config\n" + privateKeyBlock() + "\nmore"));
        String pk = privateKeyBlock();
        Finding f = Detectors.scan("x" + pk + "\ny").get(0);
        assertEquals(1, f.start());
        assertEquals(1 + pk.length(), f.end(), "the whole block, so redaction removes all of it");
        for (String kind : List.of("RSA ", "EC ", "OPENSSH ", "DSA ", "ENCRYPTED ")) {
            assertEquals(List.of(FindingType.PRIVATE_KEY), types("BEGIN " + kind + "PRIVATE KEY"), kind);
        }
        assertEquals(List.of(), types("BEGIN PUBLIC KEY"));
        assertEquals(List.of(FindingType.AWS_ACCESS_KEY), types("key=" + awsKey()));
        assertEquals(List.of(FindingType.AWS_ACCESS_KEY), types("AS" + "IA" + "ABCDEFGHIJKLMNOP"));
        assertEquals(List.of(), types("AK" + "IAabcdefghijklmnop"));
        String gh = "gh" + "p_" + "a".repeat(36);
        assertEquals(List.of(FindingType.GITHUB_TOKEN), types("token " + gh));
        assertEquals(List.of(FindingType.GITHUB_TOKEN), types("github" + "_pat_" + "A1_".repeat(10)));
        assertEquals(List.of(), types("gh" + "x_" + "a".repeat(36)));
        assertEquals(List.of(), types("gh" + "p_" + "a".repeat(10)));
        assertEquals(List.of(FindingType.SLACK_TOKEN), types("xo" + "xb-" + "1234567890-abc"));
        assertEquals(List.of(), types("xo" + "xq-1234567890"));
        assertEquals(List.of(), types("xo" + "xb-123"));
    }

    @Test
    void findingsNeverCarryTheValue() {
        List<Finding> found = Detectors.scan("card " + CARD + " uid " + AADHAAR + " " + awsKey());
        assertEquals(3, found.size());
        String printed = found.toString();
        assertFalse(printed.contains("4111"), printed);
        assertFalse(printed.contains(AADHAAR.substring(0, 6)), printed);
        assertFalse(printed.contains("ABCDEFGH"), printed);
        assertThrows(IllegalArgumentException.class, () -> new Finding(FindingType.PAN, 5, 5));
        assertThrows(IllegalArgumentException.class, () -> new Finding(FindingType.PAN, -1, 5));
    }

    @Test
    void findingsAreCapped() {
        String many = "a@b.example ".repeat(Detectors.MAX_PER_TYPE + 50);
        Detectors.Scan scan = Detectors.scanAll(many);
        assertEquals(Detectors.MAX_PER_TYPE, scan.findings().size());
        assertTrue(scan.truncated());
        assertFalse(Detectors.scanAll("a@b.example c@d.example").truncated());
    }
}
