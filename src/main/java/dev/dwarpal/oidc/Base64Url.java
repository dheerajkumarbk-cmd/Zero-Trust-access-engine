package dev.dwarpal.oidc;

import java.util.Base64;

/** Strict base64url without padding (RFC 7515, section 2): no whitespace, no padding, no spare bits. */
final class Base64Url {

    private Base64Url() {
    }

    /**
     * Decodes {@code s}, or throws {@link OidcException} with {@code failure}. Besides the alphabet,
     * the text must be the canonical encoding of the bytes: the unused bits of the last character
     * must be zero, so one byte string has exactly one accepted spelling.
     */
    static byte[] decode(String s, OidcException.Reason failure) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_';
            if (!ok) {
                throw new OidcException(failure);
            }
        }
        if (s.length() % 4 == 1) {
            throw new OidcException(failure);
        }
        byte[] bytes;
        try {
            bytes = Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new OidcException(failure);
        }
        if (!encode(bytes).equals(s)) {
            throw new OidcException(failure);
        }
        return bytes;
    }

    static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
