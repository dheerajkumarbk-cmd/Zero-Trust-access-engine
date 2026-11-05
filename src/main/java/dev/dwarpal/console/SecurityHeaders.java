package dev.dwarpal.console;

import com.sun.net.httpserver.Headers;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The response headers of docs/layer-6/standards.md section 3, exactly. {@link #apply} runs for every response the
 * server sends (pages, static files, API answers, errors, the event stream); no code path writes a response without
 * it. No {@code unsafe-inline}, no {@code unsafe-eval}, no CDN.
 */
public final class SecurityHeaders {

    public static final String CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            + "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "
            + "require-trusted-types-for 'script'; upgrade-insecure-requests";

    /** Header name to value, in the order they are written. */
    public static final Map<String, String> ALL;

    static {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
        m.put("Content-Security-Policy", CSP);
        m.put("X-Content-Type-Options", "nosniff");
        m.put("Referrer-Policy", "no-referrer");
        m.put("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()");
        m.put("Cross-Origin-Opener-Policy", "same-origin");
        m.put("Cross-Origin-Resource-Policy", "same-origin");
        m.put("Cross-Origin-Embedder-Policy", "require-corp");
        m.put("X-Frame-Options", "DENY");
        ALL = Map.copyOf(m);
    }

    private SecurityHeaders() {
    }

    /** Sets every baseline header (replacing anything a handler put there) and leaves Cache-Control to the caller. */
    public static void apply(Headers h) {
        ALL.forEach(h::set);
    }
}
