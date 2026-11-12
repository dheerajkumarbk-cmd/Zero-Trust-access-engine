package dev.dwarpal.console;

import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One answer before the server adds the security headers. {@code audit} is a short note for the audit record of a
 * sensitive read or a write (never shown to the browser); {@code handled} means the handler already took over the
 * connection (the event stream) and the server must send nothing more.
 */
record Reply(int status, byte[] body, String contentType, String audit, List<String> cookies, Map<String, String> headers,
             boolean handled) {

    static final String JSON = "application/json; charset=utf-8";

    static Reply json(int status, JsonValue v) {
        return new Reply(status, JsonWriter.bytes(v), JSON, "", List.of(), Map.of(), false);
    }

    static Reply ok(JsonValue v) {
        return json(200, v);
    }

    /** A raw JSON text that something else already checked (the SOC API's answer, a module's answer). */
    static Reply rawJson(int status, String jsonText) {
        return new Reply(status, jsonText.getBytes(StandardCharsets.UTF_8), JSON, "", List.of(), Map.of(), false);
    }

    /** The one error shape: a short fixed phrase, never a reason, a stack trace or a path. */
    static Reply error(int status, String publicText) {
        return json(status, JsonValue.object().put("error", publicText).build());
    }

    static Reply handledElsewhere() {
        return new Reply(0, new byte[0], JSON, "", List.of(), Map.of(), true);
    }

    Reply audited(String note) {
        return new Reply(status, body, contentType, note, cookies, headers, handled);
    }

    Reply withCookie(String setCookie) {
        List<String> c = new ArrayList<>(cookies);
        c.add(setCookie);
        return new Reply(status, body, contentType, audit, List.copyOf(c), headers, handled);
    }

    Reply withHeader(String name, String value) {
        Map<String, String> h = new LinkedHashMap<>(headers);
        h.put(name, value);
        return new Reply(status, body, contentType, audit, cookies, Map.copyOf(h), handled);
    }
}
