package dev.dwarpal.console;

import com.sun.net.httpserver.HttpExchange;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** What a built-in route sees: the exchange, who is calling (from the session, never from the request), and the body. */
final class Ctx {

    private static final JsonReader READER = new JsonReader(new JsonLimits(ConsoleSettings.MAX_BODY_BYTES, 6, 8_192, 32, 64,
            24, 2_000));

    final HttpExchange exchange;
    final ConsoleSessions.Session session;
    final String source;
    final String agent;
    final Map<String, String> query;
    final byte[] body;
    final List<String> params;

    Ctx(HttpExchange exchange, ConsoleSessions.Session session, String source, String agent, Map<String, String> query,
        byte[] body, List<String> params) {
        this.exchange = exchange;
        this.session = session;
        this.source = source;
        this.agent = agent;
        this.query = query;
        this.body = body;
        this.params = params;
    }

    /** The calling person; only valid on routes that need a session. */
    ConsoleAuth.Person person() {
        return session.person;
    }

    /**
     * The body as an object with exactly these members (all required, no others: unknown fields are an error, not
     * ignored). {@link JsonException} becomes a 400.
     */
    Fields fields(Set<String> exactly) {
        JsonValue v = READER.read(body);
        if (!(v instanceof JsonValue.JObject o) || o.size() != exactly.size() || !Set.copyOf(o.keys()).equals(exactly)) {
            throw new JsonException("members must be exactly " + new java.util.TreeSet<>(exactly));
        }
        return new Fields(o);
    }

    /** Typed access to the members of a checked body. */
    static final class Fields {
        private final JsonValue.JObject o;

        Fields(JsonValue.JObject o) {
            this.o = o;
        }

        String text(String key, int max) {
            if (!(o.get(key).orElseThrow() instanceof JsonValue.JString s) || s.value().isEmpty() || s.value().length() > max) {
                throw new JsonException(key + " must be text of 1 to " + max + " characters");
            }
            return s.value();
        }

        long number(String key, long min, long max) {
            if (!(o.get(key).orElseThrow() instanceof JsonValue.JNumber n)) {
                throw new JsonException(key + " must be a number");
            }
            long v = n.asLong();
            if (v < min || v > max) {
                throw new JsonException(key + " out of range");
            }
            return v;
        }

        Instant time(String key) {
            try {
                return Instant.parse(text(key, 40));
            } catch (DateTimeException e) {
                throw new JsonException(key + " must be an ISO-8601 instant");
            }
        }
    }

    static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }
}
