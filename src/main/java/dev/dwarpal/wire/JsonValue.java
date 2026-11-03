package dev.dwarpal.wire;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * An immutable JSON value, as read by {@link JsonReader} or built for {@link JsonWriter}. Numbers keep
 * their exact text, so nothing is rounded or reinterpreted before the caller asks for a type.
 */
public sealed interface JsonValue {

    static JString str(String s) {
        return new JString(s);
    }

    static JNumber num(long n) {
        return new JNumber(Long.toString(n));
    }

    static JBool bool(boolean b) {
        return new JBool(b);
    }

    static JNull nul() {
        return new JNull();
    }

    static JObject.Builder object() {
        return new JObject.Builder();
    }

    /** An object; members keep their order. Duplicate keys are impossible by construction. */
    final class JObject implements JsonValue {
        private final LinkedHashMap<String, JsonValue> members;

        private JObject(LinkedHashMap<String, JsonValue> members) {
            this.members = members;
        }

        public Optional<JsonValue> get(String key) {
            return Optional.ofNullable(members.get(key));
        }

        public List<String> keys() {
            return List.copyOf(new ArrayList<>(members.keySet()));
        }

        public int size() {
            return members.size();
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof JObject other && members.equals(other.members);
        }

        @Override
        public int hashCode() {
            return members.hashCode();
        }

        void forEach(java.util.function.BiConsumer<String, JsonValue> action) {
            members.forEach(action);
        }

        public static final class Builder {
            private final LinkedHashMap<String, JsonValue> members = new LinkedHashMap<>();

            Builder() {
            }

            public Builder put(String key, JsonValue value) {
                Objects.requireNonNull(key, "key");
                Objects.requireNonNull(value, "value");
                if (members.putIfAbsent(key, value) != null) {
                    throw new JsonException("duplicate key in output: " + key);
                }
                return this;
            }

            public Builder put(String key, String value) {
                return put(key, new JString(value));
            }

            public Builder putIfPresent(String key, Optional<? extends JsonValue> value) {
                value.ifPresent(v -> put(key, v));
                return this;
            }

            public JObject build() {
                return new JObject(new LinkedHashMap<>(members));
            }
        }

        static JObject of(Map<String, JsonValue> ordered) {
            return new JObject(new LinkedHashMap<>(ordered));
        }
    }

    final class JArray implements JsonValue {
        private final List<JsonValue> elements;

        public JArray(List<JsonValue> elements) {
            this.elements = new ArrayList<>(Objects.requireNonNull(elements, "elements"));
        }

        public JsonValue get(int i) {
            return elements.get(i);
        }

        public int size() {
            return elements.size();
        }

        public List<JsonValue> elements() {
            return List.copyOf(elements);
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof JArray other && elements.equals(other.elements);
        }

        @Override
        public int hashCode() {
            return elements.hashCode();
        }
    }

    record JString(String value) implements JsonValue {
        public JString {
            Objects.requireNonNull(value, "value");
        }
    }

    /** A number in strict JSON grammar; {@code text} is exactly as written. */
    record JNumber(String text) implements JsonValue {
        public JNumber {
            Objects.requireNonNull(text, "text");
        }

        /** The value as a finite double. */
        public double asDouble() {
            double d = Double.parseDouble(text);
            if (!Double.isFinite(d)) {
                throw new JsonException("number out of range");
            }
            return d;
        }

        /** The value as a long; only plain integers are accepted (no fraction, no exponent). */
        public long asLong() {
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (!(c == '-' && i == 0) && (c < '0' || c > '9')) {
                    throw new JsonException("an integer was expected");
                }
            }
            try {
                return Long.parseLong(text);
            } catch (NumberFormatException e) {
                throw new JsonException("integer out of range");
            }
        }
    }

    record JBool(boolean value) implements JsonValue {
    }

    record JNull() implements JsonValue {
    }
}
