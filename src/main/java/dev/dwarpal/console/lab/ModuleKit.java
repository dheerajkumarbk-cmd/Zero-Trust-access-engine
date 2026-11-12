package dev.dwarpal.console.lab;

import dev.dwarpal.console.ConsoleModule.Handler;
import dev.dwarpal.console.ConsoleModule.Principal;
import dev.dwarpal.console.ConsoleModule.Request;
import dev.dwarpal.console.ConsoleModule.Response;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * What the lab, guide and admin modules share: strict request bodies (unknown fields refused), JSON output built
 * from records, a role check inside every handler (the host checks the minimum role first; this is the second
 * line, because hiding a page or trusting one check is never the control) and one rule for errors: a short public
 * message, never a stack trace, a path or the submitted text.
 */
public final class ModuleKit {

    /** A request the module refuses, with the status and the message the browser may see. */
    public static final class Refusal extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int status;

        public Refusal(int status, String publicMessage) {
            super(publicMessage);
            this.status = status;
        }

        public int status() {
            return status;
        }
    }

    private static final JsonReader BODY = new JsonReader(new JsonLimits(64 * 1024, 6, 40_000, 16, 64, 20, 2_000));

    private ModuleKit() {
    }

    /** ANALYST below LEAD below ADMIN; USER stands apart (an ordinary person is no analyst). */
    public static boolean atLeast(Principal who, Role minimum) {
        return switch (minimum) {
            case USER -> who.has(Role.USER) || who.has(Role.ANALYST) || who.has(Role.LEAD) || who.has(Role.ADMIN) || who.has(Role.HR);
            case HR -> who.has(Role.HR);
            case ANALYST -> who.has(Role.ANALYST) || who.has(Role.LEAD) || who.has(Role.ADMIN);
            case LEAD -> who.has(Role.LEAD) || who.has(Role.ADMIN);
            case ADMIN -> who.has(Role.ADMIN);
        };
    }

    /** Wraps a handler: role check, and the one error policy. */
    public static Handler guard(Role minimum, Handler inner) {
        return (request, params) -> {
            if (!atLeast(request.who(), minimum)) {
                return Response.error(403, "not allowed for your role");
            }
            try {
                return inner.handle(request, params);
            } catch (Refusal r) {
                return Response.error(r.status(), r.getMessage());
            } catch (JsonException e) {
                return Response.error(400, "the request body is not valid");
            } catch (RuntimeException e) {
                return Response.error(500, "the lab could not do that");
            }
        };
    }

    /** The JSON object of a request body (empty body is {@code {}}); only {@code allowed} keys may appear. */
    public static JsonValue.JObject body(Request request, Set<String> allowed) {
        String text = request.body();
        if (text == null || text.isBlank()) {
            return JsonValue.object().build();
        }
        JsonValue v = BODY.read(text);
        if (!(v instanceof JsonValue.JObject o)) {
            throw new Refusal(400, "the request body must be a JSON object");
        }
        for (String k : o.keys()) {
            if (!allowed.contains(k)) {
                throw new Refusal(400, "unknown field in the request body");
            }
        }
        return o;
    }

    public static Optional<String> string(JsonValue.JObject o, String key) {
        return o.get(key).map(v -> {
            if (v instanceof JsonValue.JString s) {
                return s.value();
            }
            throw new Refusal(400, key + " must be text");
        });
    }

    public static Optional<Long> integer(JsonValue.JObject o, String key) {
        return o.get(key).map(v -> {
            if (v instanceof JsonValue.JNumber n) {
                try {
                    return n.asLong();
                } catch (JsonException e) {
                    throw new Refusal(400, key + " must be a whole number");
                }
            }
            throw new Refusal(400, key + " must be a number");
        });
    }

    public static Optional<Double> number(JsonValue.JObject o, String key) {
        return o.get(key).map(v -> {
            if (v instanceof JsonValue.JNumber n) {
                try {
                    return n.asDouble();
                } catch (JsonException | NumberFormatException e) {
                    throw new Refusal(400, key + " must be a number");
                }
            }
            throw new Refusal(400, key + " must be a number");
        });
    }

    public static Optional<Boolean> bool(JsonValue.JObject o, String key) {
        return o.get(key).map(v -> {
            if (v instanceof JsonValue.JBool b) {
                return b.value();
            }
            throw new Refusal(400, key + " must be true or false");
        });
    }

    /** Path parameters are identifiers: letters, digits and a few separators, short. */
    public static String id(String param) {
        if (param == null || param.isEmpty() || param.length() > 64
                || !param.chars().allMatch(c -> Character.isLetterOrDigit(c) && c < 128 || c == '-' || c == '_')) {
            throw new Refusal(400, "not a valid name");
        }
        return param;
    }

    public static Response json(Object value) {
        return Response.ok(JsonWriter.write(toJson(value)));
    }

    /** Records, maps, lists, optionals, enums, instants, text and numbers; nothing else leaves a module. */
    public static JsonValue toJson(Object o) {
        switch (o) {
            case null -> {
                return JsonValue.nul();
            }
            case JsonValue j -> {
                return j;
            }
            case String s -> {
                return JsonValue.str(s);
            }
            case Boolean b -> {
                return JsonValue.bool(b);
            }
            case Integer i -> {
                return JsonValue.num(i);
            }
            case Long l -> {
                return JsonValue.num(l);
            }
            case Double d -> {
                if (!Double.isFinite(d)) {
                    throw new IllegalArgumentException("number is not finite");
                }
                return new JsonValue.JNumber(Double.toString(d));
            }
            case Enum<?> e -> {
                return JsonValue.str(e.name());
            }
            case java.time.Duration d -> {
                return JsonValue.str(d.toString());
            }
            case java.time.temporal.TemporalAccessor t -> {
                return JsonValue.str(t.toString());
            }
            case Optional<?> opt -> {
                return opt.map(ModuleKit::toJson).orElse(JsonValue.nul());
            }
            case Map<?, ?> m -> {
                JsonValue.JObject.Builder b = JsonValue.object();
                m.forEach((k, v) -> b.put(String.valueOf(k), toJson(v)));
                return b.build();
            }
            case Collection<?> c -> {
                List<JsonValue> items = new ArrayList<>(c.size());
                c.forEach(x -> items.add(toJson(x)));
                return new JsonValue.JArray(items);
            }
            default -> {
                if (!o.getClass().isRecord()) {
                    throw new IllegalArgumentException("cannot write " + o.getClass().getSimpleName() + " as JSON");
                }
                JsonValue.JObject.Builder b = JsonValue.object();
                for (RecordComponent rc : o.getClass().getRecordComponents()) {
                    try {
                        java.lang.reflect.Method accessor = rc.getAccessor();
                        accessor.setAccessible(true);
                        Object v = accessor.invoke(o);
                        if (v instanceof Optional<?> opt && opt.isEmpty()) {
                            continue;
                        }
                        b.put(rc.getName(), toJson(v));
                    } catch (IllegalAccessException | InvocationTargetException | RuntimeException e) {
                        throw new IllegalStateException("cannot read a record component", e);
                    }
                }
                return b.build();
            }
        }
    }
}
