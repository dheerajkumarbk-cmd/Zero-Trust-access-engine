package dev.dwarpal.wire;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;

/**
 * Strict JSON reader (RFC 8259), written for input from the network.
 *
 * <p>Stricter than the RFC requires, on purpose: duplicate keys are an error (two parsers that keep
 * different duplicates is a classic smuggling bug), invalid UTF-8, a byte-order mark, lone surrogates,
 * raw control characters and NUL are errors, numbers must follow the exact grammar, and nothing may
 * follow the top-level value. Every size is bounded by {@link JsonLimits}; recursion depth is bounded
 * too, so a deeply nested document cannot overflow the stack.
 *
 * <p>Characters are compared by code, never by escape literals, so this source contains no escape
 * sequences an editor could alter.
 */
public final class JsonReader {

    private static final char QUOTE = 0x22;
    private static final char BACKSLASH = 0x5C;
    private static final char SLASH = 0x2F;
    private static final char SPACE = 0x20;
    private static final char TAB = 0x09;
    private static final char LF = 0x0A;
    private static final char CR = 0x0D;
    private static final char BACKSPACE = 0x08;
    private static final char FORM_FEED = 0x0C;
    private static final char BOM = 0xFEFF;

    private final JsonLimits limits;

    public JsonReader(JsonLimits limits) {
        this.limits = Objects.requireNonNull(limits, "limits");
    }

    public JsonReader() {
        this(JsonLimits.defaults());
    }

    /** Reads a document from strict UTF-8 bytes. */
    public JsonValue read(byte[] utf8) {
        Objects.requireNonNull(utf8, "utf8");
        if (utf8.length > limits.maxBytes()) {
            throw new JsonException("document larger than " + limits.maxBytes() + " bytes");
        }
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        String text;
        try {
            text = decoder.decode(ByteBuffer.wrap(utf8)).toString();
        } catch (CharacterCodingException e) {
            throw new JsonException("document is not valid UTF-8");
        }
        return parse(text);
    }

    /** Reads a document from text (its UTF-8 size is still checked). */
    public JsonValue read(String text) {
        Objects.requireNonNull(text, "text");
        if (text.length() > limits.maxBytes() || text.getBytes(StandardCharsets.UTF_8).length > limits.maxBytes()) {
            throw new JsonException("document larger than " + limits.maxBytes() + " bytes");
        }
        return parse(text);
    }

    private JsonValue parse(String text) {
        if (!text.isEmpty() && text.charAt(0) == BOM) {
            throw new JsonException("byte-order mark not allowed");
        }
        Cursor c = new Cursor(text);
        skipWhitespace(c);
        JsonValue v = value(c, 0);
        skipWhitespace(c);
        if (c.pos != text.length()) {
            throw new JsonException("unexpected content after the document at position " + c.pos);
        }
        return v;
    }

    private static final class Cursor {
        final String s;
        int pos;
        int values;

        Cursor(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return pos >= s.length();
        }

        char peek() {
            if (atEnd()) {
                throw new JsonException("unexpected end of document");
            }
            return s.charAt(pos);
        }

        char next() {
            char ch = peek();
            pos++;
            return ch;
        }
    }

    private JsonValue value(Cursor c, int depth) {
        if (++c.values > limits.maxValues()) {
            throw new JsonException("more than " + limits.maxValues() + " values");
        }
        char ch = c.peek();
        return switch (ch) {
            case '{' -> object(c, depth + 1);
            case '[' -> array(c, depth + 1);
            case QUOTE -> new JsonValue.JString(string(c));
            case 't' -> literal(c, "true", new JsonValue.JBool(true));
            case 'f' -> literal(c, "false", new JsonValue.JBool(false));
            case 'n' -> literal(c, "null", new JsonValue.JNull());
            default -> {
                if (ch == '-' || (ch >= '0' && ch <= '9')) {
                    yield number(c);
                }
                throw new JsonException("unexpected character at position " + c.pos);
            }
        };
    }

    private JsonValue object(Cursor c, int depth) {
        if (depth > limits.maxDepth()) {
            throw new JsonException("nesting deeper than " + limits.maxDepth());
        }
        c.next();
        LinkedHashMap<String, JsonValue> members = new LinkedHashMap<>();
        skipWhitespace(c);
        if (c.peek() == '}') {
            c.next();
            return JsonValue.JObject.of(members);
        }
        while (true) {
            skipWhitespace(c);
            if (c.peek() != QUOTE) {
                throw new JsonException("object key expected at position " + c.pos);
            }
            String key = string(c);
            skipWhitespace(c);
            if (c.next() != ':') {
                throw new JsonException("':' expected at position " + (c.pos - 1));
            }
            skipWhitespace(c);
            JsonValue v = value(c, depth);
            if (members.putIfAbsent(key, v) != null) {
                throw new JsonException("duplicate key at position " + c.pos);
            }
            if (members.size() > limits.maxMembers()) {
                throw new JsonException("object with more than " + limits.maxMembers() + " members");
            }
            skipWhitespace(c);
            char ch = c.next();
            if (ch == '}') {
                return JsonValue.JObject.of(members);
            }
            if (ch != ',') {
                throw new JsonException("',' or '}' expected at position " + (c.pos - 1));
            }
        }
    }

    private JsonValue array(Cursor c, int depth) {
        if (depth > limits.maxDepth()) {
            throw new JsonException("nesting deeper than " + limits.maxDepth());
        }
        c.next();
        List<JsonValue> elements = new ArrayList<>();
        skipWhitespace(c);
        if (c.peek() == ']') {
            c.next();
            return new JsonValue.JArray(elements);
        }
        while (true) {
            skipWhitespace(c);
            elements.add(value(c, depth));
            if (elements.size() > limits.maxElements()) {
                throw new JsonException("array with more than " + limits.maxElements() + " elements");
            }
            skipWhitespace(c);
            char ch = c.next();
            if (ch == ']') {
                return new JsonValue.JArray(elements);
            }
            if (ch != ',') {
                throw new JsonException("',' or ']' expected at position " + (c.pos - 1));
            }
        }
    }

    private String string(Cursor c) {
        int start = c.pos;
        c.next(); // opening quote
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (c.atEnd()) {
                throw new JsonException("unterminated string starting at position " + start);
            }
            char ch = c.next();
            if (ch == QUOTE) {
                return sb.toString();
            }
            if (ch == BACKSLASH) {
                ch = escape(c);
            } else if (ch < SPACE) {
                throw new JsonException("control character in string at position " + (c.pos - 1));
            }
            if (ch == 0) {
                throw new JsonException("NUL character in string at position " + (c.pos - 1));
            }
            if (Character.isHighSurrogate(ch)) {
                sb.append(ch);
                char low = lowSurrogateAfter(c);
                sb.append(low);
            } else if (Character.isLowSurrogate(ch)) {
                throw new JsonException("unpaired surrogate in string at position " + (c.pos - 1));
            } else {
                sb.append(ch);
            }
            if (sb.length() > limits.maxStringChars()) {
                throw new JsonException("string longer than " + limits.maxStringChars() + " characters");
            }
        }
    }

    /** A high surrogate must be followed by a low one, written raw or escaped. */
    private char lowSurrogateAfter(Cursor c) {
        if (c.atEnd()) {
            throw new JsonException("unpaired surrogate at end of document");
        }
        char ch = c.next();
        if (ch == BACKSLASH) {
            ch = escape(c);
        }
        if (!Character.isLowSurrogate(ch)) {
            throw new JsonException("unpaired surrogate in string at position " + (c.pos - 1));
        }
        return ch;
    }

    private static char escape(Cursor c) {
        char e = c.next();
        return switch (e) {
            case QUOTE -> QUOTE;
            case BACKSLASH -> BACKSLASH;
            case SLASH -> SLASH;
            case 'b' -> BACKSPACE;
            case 'f' -> FORM_FEED;
            case 'n' -> LF;
            case 'r' -> CR;
            case 't' -> TAB;
            case 'u' -> hex4(c);
            default -> throw new JsonException("invalid escape at position " + (c.pos - 1));
        };
    }

    private static char hex4(Cursor c) {
        int v = 0;
        for (int i = 0; i < 4; i++) {
            int d = Character.digit(c.next(), 16);
            if (d < 0) {
                throw new JsonException("invalid hex escape at position " + (c.pos - 1));
            }
            v = v * 16 + d;
        }
        return (char) v;
    }

    private JsonValue number(Cursor c) {
        int start = c.pos;
        if (c.peek() == '-') {
            c.next();
        }
        if (c.atEnd()) {
            throw new JsonException("digit expected at position " + c.pos);
        }
        char first = c.next();
        if (first == '0') {
            if (!c.atEnd() && isDigit(c.s.charAt(c.pos))) {
                throw new JsonException("leading zero in number at position " + start);
            }
        } else if (first >= '1' && first <= '9') {
            digits(c, start);
        } else {
            throw new JsonException("digit expected at position " + (c.pos - 1));
        }
        if (!c.atEnd() && c.s.charAt(c.pos) == '.') {
            c.next();
            requireDigit(c);
            digits(c, start);
        }
        if (!c.atEnd() && (c.s.charAt(c.pos) == 'e' || c.s.charAt(c.pos) == 'E')) {
            c.next();
            if (!c.atEnd() && (c.s.charAt(c.pos) == '+' || c.s.charAt(c.pos) == '-')) {
                c.next();
            }
            requireDigit(c);
            digits(c, start);
        }
        String text = c.s.substring(start, c.pos);
        if (text.length() > limits.maxNumberChars()) {
            throw new JsonException("number longer than " + limits.maxNumberChars() + " characters");
        }
        return new JsonValue.JNumber(text);
    }

    private void digits(Cursor c, int start) {
        while (!c.atEnd() && isDigit(c.s.charAt(c.pos))) {
            c.next();
            if (c.pos - start > limits.maxNumberChars()) {
                throw new JsonException("number longer than " + limits.maxNumberChars() + " characters");
            }
        }
    }

    private static void requireDigit(Cursor c) {
        if (c.atEnd() || !isDigit(c.s.charAt(c.pos))) {
            throw new JsonException("digit expected at position " + c.pos);
        }
    }

    private static boolean isDigit(char ch) {
        return ch >= '0' && ch <= '9';
    }

    private static JsonValue literal(Cursor c, String word, JsonValue v) {
        if (!c.s.startsWith(word, c.pos)) {
            throw new JsonException("invalid literal at position " + c.pos);
        }
        c.pos += word.length();
        return v;
    }

    private static void skipWhitespace(Cursor c) {
        while (!c.atEnd()) {
            char ch = c.s.charAt(c.pos);
            if (ch != SPACE && ch != TAB && ch != LF && ch != CR) {
                return;
            }
            c.pos++;
        }
    }
}
