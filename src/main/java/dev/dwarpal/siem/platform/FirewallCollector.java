package dev.dwarpal.siem.platform;

import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;

import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Collects firewall flow logs sent as syslog, in RFC 5424 form
 * ({@code <134>1 2026-11-04T10:00:02Z fw01 dwfw 42 - - action=allow src=... dst=...}) or the older BSD form
 * ({@code <134>Nov  4 10:00:02 fw01 dwfw: action=allow src=...}). Each line becomes one {@code network.flow}
 * event with {@link SecurityEvent.Provenance#COLLECTED} provenance: syslog over the network proves nothing about
 * who sent it.
 *
 * <p>Strict parsing, by hand: the priority is 0 to 191, the version 1, the time required, the message a list of
 * {@code key=value} pairs with each key at most once (a second {@code src=} is refused, not guessed between);
 * {@code action}, {@code src} and {@code dst} are required, ports are 0 to 65535 and byte counts whole numbers.
 * The source and destination become {@code IP} entities; the device behind an internal address comes from the
 * DHCP leases given to the collector. Lines over {@link #MAX_LINE} characters or not matching are kept as
 * {@code parse.failure} events.
 *
 * <p>BSD lines carry no year and no zone: they are read as UTC in the year of arrival, moved back a year when
 * that would put them more than a day in the future (December lines arriving in January).
 */
public final class FirewallCollector extends CollectorBase {

    public static final String DATASET = "firewall";
    public static final int MAX_LINE = 8_192;
    public static final int MAX_LEASES = 100_000;
    private static final String[] MONTHS = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
            "Nov", "Dec"};

    private final Map<String, String> leases;

    /**
     * @param runId  distinguishes this run's event ids from earlier runs (for example the start time in base 36)
     * @param leases internal address to device id (DHCP leases); at most {@link #MAX_LEASES}
     */
    public FirewallCollector(String runId, Map<String, String> leases) {
        super(DATASET, "fw", runId(runId));
        Objects.requireNonNull(leases, "leases");
        if (leases.size() > MAX_LEASES) {
            throw new IllegalArgumentException("at most " + MAX_LEASES + " leases");
        }
        Map<String, String> copy = new HashMap<>();
        leases.forEach((ip, device) -> copy.put(Objects.requireNonNull(ip, "lease ip"),
                new Entity(Entity.Kind.DEVICE, device).id()));
        this.leases = Map.copyOf(copy);
    }

    /**
     * Takes one line as it arrived.
     *
     * @return whether it was understood (a refused line is counted and kept as a {@code parse.failure} event)
     */
    public boolean offer(String line, Instant receivedAt) {
        Objects.requireNonNull(line, "line");
        seen(receivedAt);
        if (line.length() > MAX_LINE) {
            parseFailure(receivedAt, "line longer than " + MAX_LINE, line);
            return false;
        }
        try {
            SecurityEvent e = parse(line, receivedAt);
            enqueue(e);
            return true;
        } catch (IllegalArgumentException | DateTimeException bad) {
            parseFailure(receivedAt, reason(bad), line);
            return false;
        }
    }

    private static String reason(RuntimeException e) {
        return e instanceof Malformed m ? m.getMessage() : "malformed " + e.getClass().getSimpleName();
    }

    /** A parse error whose message is ours (never input text). */
    static final class Malformed extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        Malformed(String m) {
            super(m);
        }
    }

    private SecurityEvent parse(String line, Instant receivedAt) {
        Cursor c = new Cursor(line);
        int pri = c.priority();
        Instant at;
        String host;
        String app;
        if (c.peek() == '1' && c.peekAt(1) == ' ') {
            c.skip(2);
            at = parseIso(c.word("time"));
            host = c.word("host");
            app = c.word("app");
            c.word("procid");
            c.word("msgid");
            c.structuredData();
        } else {
            at = bsdTime(c, receivedAt);
            host = c.word("host");
            String tag = c.word("tag");
            app = tag.endsWith(":") ? tag.substring(0, tag.length() - 1) : tag;
            int bracket = app.indexOf('[');
            if (bracket > 0) {
                app = app.substring(0, bracket);
            }
        }
        Map<String, String> kv = c.pairs();
        String action = required(kv, "action");
        String src = required(kv, "src");
        String dst = required(kv, "dst");
        if (!address(src) || !address(dst)) {
            throw new Malformed("src or dst is not an address");
        }
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("host", host);
        fields.put("app", app);
        fields.put("severity", Integer.toString(pri & 7));
        fields.put("verdict", action);
        int extra = 0;
        for (Map.Entry<String, String> x : kv.entrySet()) {
            String k = x.getKey();
            if (k.equals("action")) {
                continue;
            }
            if (reserved(k)) {
                throw new Malformed("reserved key in message");
            }
            if (k.equals("sport") || k.equals("dport")) {
                long port = count(x.getValue());
                if (port < 0 || port > 65_535) {
                    throw new Malformed(k + " is not a port");
                }
            } else if (k.equals("bytes") || k.equals("packets")) {
                if (count(x.getValue()) < 0) {
                    throw new Malformed(k + " is not a count");
                }
            }
            if (fields.size() < MAX_COPIED_FIELDS) {
                fields.put(k, x.getValue());
            } else {
                extra++;
            }
        }
        if (extra > 0) {
            fields.put("extraFields", Integer.toString(extra));
        }
        List<Entity> entities = new ArrayList<>(4);
        addEntity(entities, Entity.Kind.IP, src);
        addEntity(entities, Entity.Kind.IP, dst);
        String device = leases.get(src);
        if (device == null) {
            device = leases.get(dst);
        }
        if (device != null) {
            addEntity(entities, Entity.Kind.DEVICE, device);
        }
        SecurityEvent.EventOutcome outcome = switch (action) {
            case "allow", "accept", "pass" -> SecurityEvent.EventOutcome.SUCCESS;
            case "deny", "drop", "reject", "block" -> SecurityEvent.EventOutcome.FAILURE;
            default -> SecurityEvent.EventOutcome.UNKNOWN;
        };
        return event(at, SecurityEvent.Category.NETWORK, "network.flow", outcome,
                SecurityEvent.Provenance.COLLECTED, entities, fields);
    }

    private static String required(Map<String, String> kv, String k) {
        String v = kv.get(k);
        if (v == null || v.isEmpty()) {
            throw new Malformed("missing " + k);
        }
        return v;
    }

    private static Instant bsdTime(Cursor c, Instant receivedAt) {
        String mon = c.word("month");
        int month = -1;
        for (int i = 0; i < MONTHS.length; i++) {
            if (MONTHS[i].equals(mon)) {
                month = i + 1;
            }
        }
        if (month < 0) {
            throw new Malformed("not RFC 5424 and no BSD month");
        }
        long day = count(c.word("day"));
        String time = c.word("time");
        if (day < 1 || day > 31 || time.length() != 8 || time.charAt(2) != ':' || time.charAt(5) != ':') {
            throw new Malformed("bad BSD time");
        }
        long h = count(time.substring(0, 2));
        long m = count(time.substring(3, 5));
        long s = count(time.substring(6, 8));
        if (h < 0 || h > 23 || m < 0 || m > 59 || s < 0 || s > 59) {
            throw new Malformed("bad BSD time");
        }
        int year = receivedAt.atOffset(ZoneOffset.UTC).getYear();
        Instant t = LocalDateTime.of(year, month, (int) day, (int) h, (int) m, (int) s).toInstant(ZoneOffset.UTC);
        if (t.isAfter(receivedAt.plus(Duration.ofDays(1)))) {
            t = LocalDateTime.of(year - 1, month, (int) day, (int) h, (int) m, (int) s).toInstant(ZoneOffset.UTC);
        }
        return t;
    }

    /** Reads a syslog line left to right; every method fails with {@link Malformed}. */
    private static final class Cursor {
        private final String s;
        private int i;

        Cursor(String s) {
            this.s = s;
        }

        char peek() {
            return peekAt(0);
        }

        char peekAt(int k) {
            return i + k < s.length() ? s.charAt(i + k) : '\0';
        }

        void skip(int n) {
            i += n;
        }

        int priority() {
            if (peek() != '<') {
                throw new Malformed("no priority");
            }
            int end = s.indexOf('>', i);
            if (end < 2 || end > 4) {
                throw new Malformed("bad priority");
            }
            long p = count(s.substring(1, end));
            if (p < 0 || p > 191) {
                throw new Malformed("bad priority");
            }
            i = end + 1;
            return (int) p;
        }

        /** The next space-separated word (BSD days may be padded with two spaces). */
        String word(String what) {
            while (peek() == ' ') {
                i++;
            }
            int start = i;
            while (i < s.length() && s.charAt(i) != ' ') {
                i++;
            }
            if (start == i) {
                throw new Malformed("missing " + what);
            }
            return s.substring(start, i);
        }

        /** RFC 5424 structured data: '-' or one or more [...] elements, skipped with quotes and escapes. */
        void structuredData() {
            while (peek() == ' ') {
                i++;
            }
            if (peek() == '-') {
                i++;
                return;
            }
            if (peek() != '[') {
                throw new Malformed("bad structured data");
            }
            while (peek() == '[') {
                boolean quoted = false;
                i++;
                while (true) {
                    if (i >= s.length()) {
                        throw new Malformed("unterminated structured data");
                    }
                    char c = s.charAt(i++);
                    if (quoted && c == '\\') {
                        i++;
                    } else if (c == '"') {
                        quoted = !quoted;
                    } else if (c == ']' && !quoted) {
                        break;
                    }
                }
            }
        }

        /** {@code key=value} pairs to the end; values may be quoted. Each key at most once. */
        Map<String, String> pairs() {
            Map<String, String> out = new LinkedHashMap<>();
            while (true) {
                while (peek() == ' ') {
                    i++;
                }
                if (i >= s.length()) {
                    return out;
                }
                int eq = s.indexOf('=', i);
                int sp = s.indexOf(' ', i);
                if (eq < 0 || (sp >= 0 && sp < eq)) {
                    throw new Malformed("expected key=value");
                }
                String key = s.substring(i, eq);
                if (!fieldName(key)) {
                    throw new Malformed("bad key");
                }
                i = eq + 1;
                String value;
                if (peek() == '"') {
                    StringBuilder b = new StringBuilder();
                    i++;
                    while (true) {
                        if (i >= s.length()) {
                            throw new Malformed("unterminated quoted value");
                        }
                        char c = s.charAt(i++);
                        if (c == '\\' && i < s.length()) {
                            b.append(s.charAt(i++));
                        } else if (c == '"') {
                            break;
                        } else {
                            b.append(c);
                        }
                    }
                    value = b.toString();
                } else {
                    int end = s.indexOf(' ', i);
                    end = end < 0 ? s.length() : end;
                    value = s.substring(i, end);
                    i = end;
                }
                if (out.putIfAbsent(key, value) != null) {
                    throw new Malformed("key given twice");
                }
                if (out.size() > 64) {
                    throw new Malformed("too many keys");
                }
            }
        }
    }

    static Instant parseIso(String s) {
        try {
            return OffsetDateTime.parse(s).toInstant();
        } catch (DateTimeParseException e) {
            throw new Malformed("bad time");
        }
    }
}
