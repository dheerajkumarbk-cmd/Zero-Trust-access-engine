package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Audit events and alerts in the three formats SIEMs read: JSON lines (Elastic, Wazuh, Splunk HEC),
 * ArcSight CEF and RFC 5424 syslog. Each line is one event and can never become two, nor carry a field
 * it does not have: every format's own escaping is applied to every value <em>and</em> every field
 * name (a record read without the audit key is not proven to be Dwarpal's, so its names are input too).
 *
 * <ul>
 *   <li><b>JSON lines</b>: lossless; strings escaped by {@link JsonWriter} (quotes, backslash, every
 *       control character, line separators, bidi controls).</li>
 *   <li><b>CEF</b>: header fields escape {@code \} and {@code |}; extension values escape {@code \},
 *       {@code =}, CR and LF. Extension keys cannot be escaped in CEF, so a payload name becomes
 *       {@code dwf<name>} when it is 1 to 28 letters and digits, otherwise {@code dwh<sha-256 prefix>}:
 *       never a standard key, never two names on one key.</li>
 *   <li><b>Syslog</b>: HEADER fields are printable US-ASCII without spaces; structured-data values
 *       escape {@code "}, {@code \} and {@code ]}; names are encoded as for CEF ({@code f...} /
 *       {@code h...}, at most 32 characters, RFC 5424 section 6.3.3).</li>
 *   <li>In CEF and syslog other control, line-separator and bidi characters become the visible text
 *       {@code \\uXXXX} (with the backslash itself escaped), values are cut at {@link #MAX_VALUE_CHARS}
 *       and a line at about {@link #MAX_LINE_CHARS}; short fields come first, so a huge value can push
 *       out only other huge values, never the subject, address or outcome. The JSON line keeps all.</li>
 * </ul>
 *
 * Fields are written in a fixed order (by length, then name), so the same event always gives the
 * same line.
 */
public final class Exporters {

    public static final int MAX_VALUE_CHARS = 2048;
    public static final int MAX_LINE_CHARS = 32 * 1024;
    /** Example private enterprise number for documentation (RFC 5612), until Dwarpal has its own. */
    static final String PEN = "32473";
    static final String PRODUCT_VERSION = "0.1";
    /** RFC 5424 facility 13, "log audit". */
    static final int FACILITY = 13;

    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9]{1,28}");
    private static final Pattern HOSTNAME = Pattern.compile("[\\x21-\\x7e]{1,255}");
    private static final Pattern APP_NAME = Pattern.compile("[\\x21-\\x7e]{1,48}");
    private static final DateTimeFormatter RFC3339 = DateTimeFormatter.ISO_INSTANT;
    private static final String TRUNCATED = "...[truncated]";

    private Exporters() {
    }

    // ---- JSON lines ----------------------------------------------------------------------------------

    /** {@code {"seq":..,"at":..,"type":..,"actor":..,"fields":{..}}}, one line. */
    public static String jsonLine(AuditEvent e) {
        Objects.requireNonNull(e, "event");
        JsonValue.JObject.Builder f = JsonValue.object();
        for (Map.Entry<String, String> x : ordered(e.fields())) {
            f.put(x.getKey(), x.getValue());
        }
        return JsonWriter.write(JsonValue.object().put("seq", JsonValue.num(e.sequence()))
                .put("at", e.at().toString()).put("type", e.type()).put("actor", e.actor())
                .put("fields", f.build()).build());
    }

    /** An alert as one JSON line. */
    public static String jsonLine(Alert a) {
        Objects.requireNonNull(a, "alert");
        List<JsonValue> entities = new ArrayList<>();
        for (Entity x : a.entities()) {
            entities.add(JsonValue.object().put("kind", x.kind().name()).put("id", x.id()).build());
        }
        List<JsonValue> evidence = new ArrayList<>();
        for (long s : a.evidence()) {
            evidence.add(JsonValue.num(s));
        }
        return JsonWriter.write(JsonValue.object().put("id", a.id()).put("rule", a.rule())
                .put("severity", a.severity().name()).put("raisedAt", a.raisedAt().toString())
                .put("count", JsonValue.num(a.count())).put("entities", new JsonValue.JArray(entities))
                .put("evidence", new JsonValue.JArray(evidence)).put("summary", a.summary()).build());
    }

    // ---- CEF -----------------------------------------------------------------------------------------

    /** {@code CEF:0|Dwarpal|Dwarpal|0.1|<type>|<type>|<severity>|rt=.. externalId=<seq> ..}. */
    public static String cef(AuditEvent e) {
        Objects.requireNonNull(e, "event");
        StringBuilder sb = cefHeader(e.type(), e.type(), eventCefSeverity(e));
        sb.append("rt=").append(e.at().toEpochMilli()).append(" externalId=").append(e.sequence())
                .append(" cat=").append(cefValue(e.type())).append(" suser=").append(cefValue(e.actor()));
        cefFields(sb, ordered(e.fields()));
        return sb.toString();
    }

    /** An alert in CEF; the signature id is the rule. */
    public static String cef(Alert a) {
        Objects.requireNonNull(a, "alert");
        StringBuilder sb = cefHeader(a.rule(), a.summary(), cefSeverity(a.severity()));
        sb.append("rt=").append(a.raisedAt().toEpochMilli()).append(" externalId=").append(cefValue(a.id()))
                .append(" cat=").append(cefValue(a.rule())).append(" cnt=").append(a.count())
                .append(" msg=").append(cefValue(a.summary()));
        cefFields(sb, alertFields(a));
        return sb.toString();
    }

    private static StringBuilder cefHeader(String signature, String name, int severity) {
        return new StringBuilder(256).append("CEF:0|Dwarpal|Dwarpal|").append(PRODUCT_VERSION).append('|')
                .append(cefHeaderValue(signature)).append('|').append(cefHeaderValue(name)).append('|')
                .append(severity).append('|');
    }

    private static void cefFields(StringBuilder sb, List<Map.Entry<String, String>> fields) {
        int written = 0;
        for (Map.Entry<String, String> f : fields) {
            String part = " " + cefKey(f.getKey()) + "=" + cefValue(cut(f.getValue()));
            if (sb.length() + part.length() > MAX_LINE_CHARS) {
                break;
            }
            sb.append(part);
            written++;
        }
        if (written < fields.size()) {
            sb.append(" dwftruncated=").append(fields.size() - written);
        }
    }

    static String cefKey(String name) {
        return SAFE_NAME.matcher(name).matches() ? "dwf" + name : "dwh" + Digests.sha256Hex(name).substring(0, 24);
    }

    static String cefHeaderValue(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '|' -> sb.append("\\|");
                default -> visible(sb, c);
            }
        }
        return sb.toString();
    }

    static String cefValue(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '=' -> sb.append("\\=");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                default -> visible(sb, c);
            }
        }
        return sb.toString();
    }

    static int cefSeverity(Severity s) {
        return switch (s) {
            case LOW -> 3;
            case MEDIUM -> 5;
            case HIGH -> 8;
            case CRITICAL -> 10;
        };
    }

    private static int eventCefSeverity(AuditEvent e) {
        return cefSeverity(eventSeverity(e));
    }

    /** A coarse severity for raw audit events, from their type (never from a payload value). */
    static Severity eventSeverity(AuditEvent e) {
        String t = e.type();
        if (t.equals("BREAK_GLASS_USED")) {
            return Severity.CRITICAL;
        }
        if (t.contains("REFUSED") || t.contains("REVOKED") || t.contains("FAILED") || t.contains("REPLAY")
                || t.startsWith("SIGNAL_")) {
            return Severity.MEDIUM;
        }
        return Severity.LOW;
    }

    // ---- syslog (RFC 5424) ---------------------------------------------------------------------------

    /**
     * {@code <PRI>1 TIMESTAMP HOSTNAME APP-NAME - MSGID [audit@32473 ..][fields@32473 ..]}.
     *
     * @param hostname printable US-ASCII, 1 to 255 characters
     * @param appName  printable US-ASCII, 1 to 48 characters
     */
    public static String syslog(AuditEvent e, String hostname, String appName) {
        Objects.requireNonNull(e, "event");
        StringBuilder sb = syslogHeader(eventSeverity(e), e.at(), hostname, appName, e.type());
        sb.append("[audit@").append(PEN).append(" seq=\"").append(e.sequence()).append("\" type=\"")
                .append(sdValue(e.type())).append("\" actor=\"").append(sdValue(e.actor())).append("\"]");
        sdFields(sb, ordered(e.fields()));
        return sb.toString();
    }

    /** An alert as a syslog line; its summary is the message. */
    public static String syslog(Alert a, String hostname, String appName) {
        Objects.requireNonNull(a, "alert");
        StringBuilder sb = syslogHeader(a.severity(), a.raisedAt(), hostname, appName, a.rule());
        sb.append("[alert@").append(PEN).append(" id=\"").append(sdValue(a.id())).append("\" severity=\"")
                .append(a.severity().name()).append("\" count=\"").append(a.count()).append("\"]");
        sdFields(sb, alertFields(a));
        sb.append(' ').append(msg(a.summary()));
        return sb.toString();
    }

    private static StringBuilder syslogHeader(Severity s, Instant at, String hostname, String appName, String msgId) {
        if (hostname == null || !HOSTNAME.matcher(hostname).matches()) {
            throw new IllegalArgumentException("hostname must be 1 to 255 printable US-ASCII characters");
        }
        if (appName == null || !APP_NAME.matcher(appName).matches()) {
            throw new IllegalArgumentException("app name must be 1 to 48 printable US-ASCII characters");
        }
        int pri = FACILITY * 8 + syslogSeverity(s);
        return new StringBuilder(256).append('<').append(pri).append(">1 ")
                .append(RFC3339.format(at.truncatedTo(ChronoUnit.MICROS))).append(' ').append(hostname).append(' ')
                .append(appName).append(" - ").append(msgId(msgId)).append(' ');
    }

    static int syslogSeverity(Severity s) {
        return switch (s) {
            case LOW -> 6;
            case MEDIUM -> 4;
            case HIGH -> 3;
            case CRITICAL -> 2;
        };
    }

    private static String msgId(String s) {
        StringBuilder sb = new StringBuilder(32);
        for (int i = 0; i < s.length() && sb.length() < 32; i++) {
            char c = s.charAt(i);
            sb.append(c > 0x20 && c < 0x7f ? c : '_');
        }
        return sb.isEmpty() ? "-" : sb.toString();
    }

    private static void sdFields(StringBuilder sb, List<Map.Entry<String, String>> fields) {
        if (fields.isEmpty()) {
            return;
        }
        sb.append("[fields@").append(PEN);
        int written = 0;
        for (Map.Entry<String, String> f : fields) {
            String part = " " + sdName(f.getKey()) + "=\"" + sdValue(cut(f.getValue())) + "\"";
            if (sb.length() + part.length() > MAX_LINE_CHARS) {
                break;
            }
            sb.append(part);
            written++;
        }
        if (written < fields.size()) {
            sb.append(" ftruncated=\"").append(fields.size() - written).append('"');
        }
        sb.append(']');
    }

    static String sdName(String name) {
        return SAFE_NAME.matcher(name).matches() ? "f" + name : "h" + Digests.sha256Hex(name).substring(0, 24);
    }

    static String sdValue(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case ']' -> sb.append("\\]");
                default -> visible(sb, c);
            }
        }
        return sb.toString();
    }

    private static String msg(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            visible(sb, s.charAt(i));
        }
        return sb.toString();
    }

    // ---- shared --------------------------------------------------------------------------------------

    /** Appends {@code c}, or the visible text {@code \\uXXXX} for characters that could forge a line. */
    private static void visible(StringBuilder sb, char c) {
        if (Character.isISOControl(c) || c == 0x2028 || c == 0x2029 || (c >= 0x202A && c <= 0x202E)
                || (c >= 0x2066 && c <= 0x2069) || c == 0x200E || c == 0x200F || c == 0xFEFF) {
            sb.append("\\\\u").append(String.format("%04x", (int) c));
        } else {
            sb.append(c);
        }
    }

    private static String cut(String v) {
        if (v.length() <= MAX_VALUE_CHARS) {
            return v;
        }
        // Never cut a surrogate pair in half.
        int end = Character.isHighSurrogate(v.charAt(MAX_VALUE_CHARS - 1)) ? MAX_VALUE_CHARS - 1 : MAX_VALUE_CHARS;
        return v.substring(0, end) + TRUNCATED;
    }

    /** Short values first, then by name: deterministic, and long values cannot push out short ones. */
    static List<Map.Entry<String, String>> ordered(Map<String, String> fields) {
        List<Map.Entry<String, String>> l = new ArrayList<>(fields.entrySet());
        l.sort(Comparator.<Map.Entry<String, String>>comparingInt(x -> Math.min(x.getValue().length(), MAX_VALUE_CHARS))
                .thenComparing(Map.Entry::getKey));
        return l;
    }

    private static List<Map.Entry<String, String>> alertFields(Alert a) {
        StringBuilder entities = new StringBuilder();
        for (Entity x : a.entities()) {
            if (!entities.isEmpty()) {
                entities.append(',');
            }
            entities.append(x.kind().name()).append(':').append(x.id());
        }
        StringBuilder evidence = new StringBuilder();
        for (long s : a.evidence()) {
            if (!evidence.isEmpty()) {
                evidence.append(',');
            }
            evidence.append(s);
        }
        return List.of(Map.entry("entities", entities.toString()), Map.entry("evidence", evidence.toString()));
    }
}
