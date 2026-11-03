package dev.dwarpal.wire;

/**
 * Hard limits on JSON input. Every limit exists because a parser without it can be made to use
 * unbounded memory or time (CWE-400, CWE-674).
 *
 * @param maxBytes       whole document, in UTF-8 bytes
 * @param maxDepth       nesting of objects and arrays (bounds recursion)
 * @param maxStringChars one string, after unescaping
 * @param maxMembers     members of one object
 * @param maxElements    elements of one array
 * @param maxNumberChars one number literal (stops "1" followed by a million zeros)
 * @param maxValues      all values in the document
 */
public record JsonLimits(int maxBytes, int maxDepth, int maxStringChars, int maxMembers, int maxElements,
                         int maxNumberChars, int maxValues) {

    public JsonLimits {
        if (maxBytes < 2 || maxDepth < 1 || maxStringChars < 1 || maxMembers < 1 || maxElements < 1
                || maxNumberChars < 1 || maxValues < 1) {
            throw new IllegalArgumentException("JSON limits must be positive");
        }
    }

    /** 64 KiB, depth 16, strings of 4,096 characters, 256 members, 1,024 elements, 32-character numbers, 10,000 values. */
    public static JsonLimits defaults() {
        return new JsonLimits(64 * 1024, 16, 4096, 256, 1024, 32, 10_000);
    }
}
