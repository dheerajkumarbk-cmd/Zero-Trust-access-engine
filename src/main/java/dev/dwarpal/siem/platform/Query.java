package dev.dwarpal.siem.platform;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The search language, shared by {@link EventStore} (analyst searches) and {@link RuleBook} (the
 * {@code where} of every correlation rule), so a search an analyst tries out is exactly what a rule matches.
 *
 * <pre>
 *   query      := expr [ '|' 'count' 'by' field { ',' field } ]
 *   expr       := and { 'or' and }
 *   and        := unary { 'and' unary }
 *   unary      := 'not' unary | '(' expr ')' | comparison | '*'
 *   comparison := field op value | field 'in' '(' value { ',' value } ')'
 *   op         := '=' | '!=' | '&gt;' | '&gt;=' | '&lt;' | '&lt;=' | '~'   ('~' is "contains", ignoring case)
 *   value      := bare word (letters, digits and . _ : @ / - + *) | "quoted string" (\" and \\ escapes)
 * </pre>
 *
 * <p>Fields: {@code id}, {@code dataset}, {@code category}, {@code action}, {@code outcome}, {@code provenance},
 * {@code at} (event time, ISO-8601), the entity kinds {@code subject}, {@code device}, {@code ip},
 * {@code session}, {@code resource} (true if any entity of that kind matches), {@code f.<name>} for an event
 * field whose name is one of these, and any other name for the event field of that name. Category, outcome and
 * provenance values are checked against their enums when the query is parsed, so a typo is an error, never a
 * query that silently matches nothing. A comparison on a field the event does not have is false (also for
 * {@code !=}); {@code not} makes it true. {@code &gt;}, {@code &lt;} compare numbers (or times for {@code at})
 * and are false for values that are not numbers.
 *
 * <p>Parsed by hand, character by character: no regular expression ever runs on user input. Limits:
 * {@link #MAX_TOKENS} tokens, {@link #MAX_DEPTH} nesting, {@link #MAX_NODES} nodes, {@link #MAX_IN} values in an
 * {@code in} list, {@link #MAX_GROUP} fields after {@code count by}.
 */
public final class Query {

    public static final int MAX_TOKENS = 256;
    public static final int MAX_DEPTH = 16;
    public static final int MAX_NODES = 128;
    public static final int MAX_IN = 32;
    public static final int MAX_GROUP = 4;
    public static final int MAX_VALUE = 256;

    /** Field names with a meaning of their own (an event field with such a name is reached as {@code f.<name>}). */
    public static final Set<String> BUILT_IN = Set.of("id", "dataset", "category", "action", "outcome", "provenance",
            "at", "subject", "device", "ip", "session", "resource");

    public enum Op { EQ, NE, GT, GE, LT, LE, CONTAINS, IN }

    /** A node of a parsed query. */
    public sealed interface Node permits All, And, Or, Not, Cmp {
    }

    /** {@code *}: every event. */
    public record All() implements Node {
    }

    public record And(List<Node> parts) implements Node {
        public And {
            parts = List.copyOf(parts);
        }
    }

    public record Or(List<Node> parts) implements Node {
        public Or {
            parts = List.copyOf(parts);
        }
    }

    public record Not(Node inner) implements Node {
    }

    /** One comparison; {@code values} has one value except for {@code in}. */
    public record Cmp(String field, Op op, List<String> values) implements Node {
        public Cmp {
            values = List.copyOf(values);
        }
    }

    private final Node root;
    private final List<String> countBy;
    private final int nodes;

    private Query(Node root, List<String> countBy, int nodes) {
        this.root = root;
        this.countBy = List.copyOf(countBy);
        this.nodes = nodes;
    }

    /** The query that matches every event. */
    public static Query all() {
        return new Query(new All(), List.of(), 1);
    }

    /**
     * Parses a query.
     *
     * @throws QueryException with the position and the problem, if it is malformed or over a limit
     */
    public static Query parse(String text) {
        Objects.requireNonNull(text, "query");
        if (text.length() > dev.dwarpal.soc.EventSearch.MAX_QUERY) {
            throw new QueryException("query longer than " + dev.dwarpal.soc.EventSearch.MAX_QUERY + " characters");
        }
        List<Token> tokens = tokenize(text);
        if (tokens.isEmpty()) {
            return all();
        }
        Parser p = new Parser(tokens);
        Node root = p.expr(0);
        List<String> by = new ArrayList<>();
        if (p.peekIs(Kind.PIPE)) {
            p.next();
            p.keyword("count");
            p.keyword("by");
            do {
                if (by.size() == MAX_GROUP) {
                    throw new QueryException("at most " + MAX_GROUP + " fields after 'count by'");
                }
                String f = p.field();
                if (by.contains(f)) {
                    throw new QueryException("'" + f + "' named twice after 'count by'");
                }
                by.add(f);
            } while (p.accept(Kind.COMMA));
        }
        if (!p.done()) {
            throw p.error("unexpected '" + p.peek().text + "'");
        }
        return new Query(root, by, p.nodes);
    }

    public Node root() {
        return root;
    }

    /** The fields after {@code count by}; empty for a plain search. */
    public List<String> countBy() {
        return countBy;
    }

    public int nodes() {
        return nodes;
    }

    /** Whether the event matches. Cost is bounded by the number of nodes and the event's entities. */
    public boolean matches(SecurityEvent e) {
        return eval(root, e);
    }

    /** The comparisons that every match must satisfy (the top-level {@code and}), for index planning and lint. */
    public List<Cmp> required() {
        if (root instanceof Cmp c) {
            return List.of(c);
        }
        if (root instanceof And a) {
            List<Cmp> out = new ArrayList<>();
            for (Node n : a.parts()) {
                if (n instanceof Cmp c) {
                    out.add(c);
                }
            }
            return out;
        }
        return List.of();
    }

    /** Every comparison anywhere in the query (for lint). */
    public List<Cmp> comparisons() {
        List<Cmp> out = new ArrayList<>();
        collect(root, out);
        return out;
    }

    private static void collect(Node n, List<Cmp> out) {
        switch (n) {
            case Cmp c -> out.add(c);
            case And a -> a.parts().forEach(x -> collect(x, out));
            case Or o -> o.parts().forEach(x -> collect(x, out));
            case Not x -> collect(x.inner(), out);
            case All x -> {
                // nothing to collect
            }
        }
    }

    // ---- evaluation -----------------------------------------------------------------------------------------

    private static boolean eval(Node n, SecurityEvent e) {
        return switch (n) {
            case All a -> true;
            case And a -> {
                for (Node x : a.parts()) {
                    if (!eval(x, e)) {
                        yield false;
                    }
                }
                yield true;
            }
            case Or o -> {
                for (Node x : o.parts()) {
                    if (eval(x, e)) {
                        yield true;
                    }
                }
                yield false;
            }
            case Not x -> !eval(x.inner(), e);
            case Cmp c -> compare(c, e);
        };
    }

    private static boolean compare(Cmp c, SecurityEvent e) {
        if (c.field().equals("at")) {
            return compareTime(c, e.at());
        }
        List<String> vs = values(e, c.field());
        for (String v : vs) {
            if (test(c, v)) {
                return true;
            }
        }
        return false;
    }

    private static boolean test(Cmp c, String v) {
        String want = c.values().getFirst();
        return switch (c.op()) {
            case EQ -> v.equals(want);
            case NE -> !v.equals(want);
            case IN -> c.values().contains(v);
            case CONTAINS -> v.toLowerCase(Locale.ROOT).contains(want);
            case GT, GE, LT, LE -> numeric(c.op(), v, want);
        };
    }

    private static boolean numeric(Op op, String v, String want) {
        Optional<Double> a = number(v);
        Optional<Double> b = number(want);
        if (a.isEmpty() || b.isEmpty()) {
            return false;
        }
        int cmp = Double.compare(a.get(), b.get());
        return switch (op) {
            case GT -> cmp > 0;
            case GE -> cmp >= 0;
            case LT -> cmp < 0;
            default -> cmp <= 0;
        };
    }

    private static boolean compareTime(Cmp c, Instant at) {
        for (String v : c.values()) {
            Instant t = Instant.parse(v);    // checked when parsed
            int cmp = at.compareTo(t);
            boolean ok = switch (c.op()) {
                case EQ, IN -> cmp == 0;
                case NE -> cmp != 0;
                case GT -> cmp > 0;
                case GE -> cmp >= 0;
                case LT -> cmp < 0;
                case LE -> cmp <= 0;
                case CONTAINS -> false;
            };
            if (ok) {
                return true;
            }
        }
        return false;
    }

    /** A number of at most 32 characters (digits, one '.', a leading '-'), parsed without a regex. */
    static Optional<Double> number(String s) {
        if (s.isEmpty() || s.length() > 32) {
            return Optional.empty();
        }
        boolean dot = false;
        boolean digit = false;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch >= '0' && ch <= '9') {
                digit = true;
            } else if (ch == '.' && !dot) {
                dot = true;
            } else if (!(ch == '-' && i == 0)) {
                return Optional.empty();
            }
        }
        return digit ? Optional.of(Double.parseDouble(s)) : Optional.empty();
    }

    /** The values a field has in an event: none if it is missing, several for an entity kind. */
    public static List<String> values(SecurityEvent e, String field) {
        return switch (field) {
            case "id" -> List.of(e.id());
            case "dataset" -> List.of(e.dataset());
            case "category" -> List.of(e.category().name());
            case "action" -> List.of(e.action());
            case "outcome" -> List.of(e.outcome().name());
            case "provenance" -> List.of(e.provenance().name());
            case "at" -> List.of(e.at().toString());
            case "subject" -> entities(e, Entity.Kind.SUBJECT);
            case "device" -> entities(e, Entity.Kind.DEVICE);
            case "ip" -> entities(e, Entity.Kind.IP);
            case "session" -> entities(e, Entity.Kind.SESSION);
            case "resource" -> entities(e, Entity.Kind.RESOURCE);
            default -> {
                String name = field.startsWith("f.") ? field.substring(2) : field;
                String v = e.fields().get(name);
                yield v == null ? List.of() : List.of(v);
            }
        };
    }

    /** The entity kind a field name stands for, if it is one. */
    public static Optional<Entity.Kind> entityKind(String field) {
        return switch (field) {
            case "subject" -> Optional.of(Entity.Kind.SUBJECT);
            case "device" -> Optional.of(Entity.Kind.DEVICE);
            case "ip" -> Optional.of(Entity.Kind.IP);
            case "session" -> Optional.of(Entity.Kind.SESSION);
            case "resource" -> Optional.of(Entity.Kind.RESOURCE);
            default -> Optional.empty();
        };
    }

    private static List<String> entities(SecurityEvent e, Entity.Kind kind) {
        List<String> out = new ArrayList<>(2);
        for (Entity x : e.entities()) {
            if (x.kind() == kind) {
                out.add(x.id());
            }
        }
        return out;
    }

    // ---- tokens ---------------------------------------------------------------------------------------------

    private enum Kind { WORD, STRING, OP, LPAREN, RPAREN, COMMA, PIPE }

    private record Token(Kind kind, String text, int pos) {
    }

    private static List<Token> tokenize(String s) {
        List<Token> out = new ArrayList<>();
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                i++;
                continue;
            }
            if (out.size() == MAX_TOKENS) {
                throw new QueryException("more than " + MAX_TOKENS + " tokens");
            }
            int start = i;
            switch (c) {
                case '(' -> {
                    out.add(new Token(Kind.LPAREN, "(", start));
                    i++;
                }
                case ')' -> {
                    out.add(new Token(Kind.RPAREN, ")", start));
                    i++;
                }
                case ',' -> {
                    out.add(new Token(Kind.COMMA, ",", start));
                    i++;
                }
                case '|' -> {
                    out.add(new Token(Kind.PIPE, "|", start));
                    i++;
                }
                case '=', '~' -> {
                    out.add(new Token(Kind.OP, String.valueOf(c), start));
                    i++;
                }
                case '!', '<', '>' -> {
                    boolean eq = i + 1 < s.length() && s.charAt(i + 1) == '=';
                    if (c == '!' && !eq) {
                        throw new QueryException("at " + (start + 1) + ": '!' must be followed by '='");
                    }
                    out.add(new Token(Kind.OP, eq ? c + "=" : String.valueOf(c), start));
                    i += eq ? 2 : 1;
                }
                case '"' -> {
                    StringBuilder b = new StringBuilder();
                    i++;
                    boolean closed = false;
                    while (i < s.length()) {
                        char d = s.charAt(i);
                        if (d == '\\' && i + 1 < s.length() && (s.charAt(i + 1) == '"' || s.charAt(i + 1) == '\\')) {
                            b.append(s.charAt(i + 1));
                            i += 2;
                        } else if (d == '"') {
                            closed = true;
                            i++;
                            break;
                        } else {
                            b.append(d);
                            i++;
                        }
                        if (b.length() > MAX_VALUE) {
                            throw new QueryException("at " + (start + 1) + ": value longer than " + MAX_VALUE);
                        }
                    }
                    if (!closed) {
                        throw new QueryException("at " + (start + 1) + ": unterminated string");
                    }
                    out.add(new Token(Kind.STRING, b.toString(), start));
                }
                default -> {
                    if (!wordChar(c)) {
                        throw new QueryException("at " + (start + 1) + ": unexpected character "
                                + Sanitize.text(String.valueOf(c), 8));
                    }
                    while (i < s.length() && wordChar(s.charAt(i))) {
                        i++;
                    }
                    if (i - start > MAX_VALUE) {
                        throw new QueryException("at " + (start + 1) + ": word longer than " + MAX_VALUE);
                    }
                    out.add(new Token(Kind.WORD, s.substring(start, i), start));
                }
            }
        }
        return out;
    }

    private static boolean wordChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '.' || c == '_' || c == ':' || c == '@' || c == '/' || c == '-' || c == '+' || c == '*';
    }

    // ---- parser ---------------------------------------------------------------------------------------------

    private static final class Parser {
        private final List<Token> tokens;
        private int at;
        private int nodes;

        Parser(List<Token> tokens) {
            this.tokens = tokens;
        }

        boolean done() {
            return at >= tokens.size();
        }

        Token peek() {
            return tokens.get(at);
        }

        boolean peekIs(Kind k) {
            return !done() && peek().kind == k;
        }

        boolean peekWord(String w) {
            return peekIs(Kind.WORD) && peek().text.equalsIgnoreCase(w);
        }

        Token next() {
            if (done()) {
                throw new QueryException("the query ends too early");
            }
            return tokens.get(at++);
        }

        boolean accept(Kind k) {
            if (peekIs(k)) {
                at++;
                return true;
            }
            return false;
        }

        void keyword(String w) {
            if (!peekWord(w)) {
                throw done() ? new QueryException("expected '" + w + "' at the end") : error("expected '" + w + "'");
            }
            at++;
        }

        QueryException error(String what) {
            Token t = done() ? tokens.getLast() : peek();
            return new QueryException("at " + (t.pos + 1) + ": " + Sanitize.text(what, 80));
        }

        private void count() {
            if (++nodes > MAX_NODES) {
                throw new QueryException("more than " + MAX_NODES + " terms");
            }
        }

        Node expr(int depth) {
            if (depth > MAX_DEPTH) {
                throw new QueryException("nested deeper than " + MAX_DEPTH);
            }
            List<Node> parts = new ArrayList<>();
            parts.add(and(depth));
            while (peekWord("or")) {
                at++;
                parts.add(and(depth));
            }
            if (parts.size() == 1) {
                return parts.getFirst();
            }
            count();
            return new Or(parts);
        }

        Node and(int depth) {
            List<Node> parts = new ArrayList<>();
            parts.add(unary(depth));
            while (peekWord("and")) {
                at++;
                parts.add(unary(depth));
            }
            if (parts.size() == 1) {
                return parts.getFirst();
            }
            count();
            return new And(parts);
        }

        Node unary(int depth) {
            if (depth > MAX_DEPTH) {
                throw new QueryException("nested deeper than " + MAX_DEPTH);
            }
            if (peekWord("not")) {
                at++;
                count();
                return new Not(unary(depth + 1));
            }
            if (accept(Kind.LPAREN)) {
                Node inner = expr(depth + 1);
                if (!accept(Kind.RPAREN)) {
                    throw error("expected ')'");
                }
                return inner;
            }
            if (peekIs(Kind.WORD) && peek().text.equals("*")) {
                at++;
                count();
                return new All();
            }
            return comparison();
        }

        String field() {
            Token t = next();
            if (t.kind != Kind.WORD || !fieldName(t.text)) {
                at--;
                throw error("expected a field name");
            }
            return t.text;
        }

        Node comparison() {
            String f = field();
            count();
            if (peekWord("in")) {
                at++;
                if (!accept(Kind.LPAREN)) {
                    throw error("expected '(' after 'in'");
                }
                Set<String> vs = new LinkedHashSet<>();
                do {
                    if (vs.size() == MAX_IN) {
                        throw error("at most " + MAX_IN + " values in a list");
                    }
                    vs.add(value(f, Op.IN));
                } while (accept(Kind.COMMA));
                if (!accept(Kind.RPAREN)) {
                    throw error("expected ')' to close the list");
                }
                return new Cmp(f, Op.IN, new ArrayList<>(vs));
            }
            Token t = next();
            if (t.kind != Kind.OP) {
                at--;
                throw error("expected an operator after '" + f + "'");
            }
            Op op = switch (t.text) {
                case "=" -> Op.EQ;
                case "!=" -> Op.NE;
                case ">" -> Op.GT;
                case ">=" -> Op.GE;
                case "<" -> Op.LT;
                case "<=" -> Op.LE;
                default -> Op.CONTAINS;
            };
            return new Cmp(f, op, Collections.singletonList(value(f, op)));
        }

        String value(String field, Op op) {
            Token t = next();
            if (t.kind != Kind.WORD && t.kind != Kind.STRING) {
                at--;
                throw error("expected a value");
            }
            String v = t.text;
            switch (field) {
                case "category" -> v = enumValue(SecurityEvent.Category.class, v, t);
                case "outcome" -> v = enumValue(SecurityEvent.EventOutcome.class, v, t);
                case "provenance" -> v = enumValue(SecurityEvent.Provenance.class, v, t);
                case "at" -> {
                    try {
                        Instant.parse(v);
                    } catch (DateTimeParseException e) {
                        throw new QueryException("at " + (t.pos + 1) + ": 'at' needs an ISO-8601 time");
                    }
                    if (op == Op.CONTAINS) {
                        throw new QueryException("at " + (t.pos + 1) + ": '~' does not apply to 'at'");
                    }
                }
                default -> {
                    // free text
                }
            }
            if (op == Op.CONTAINS) {
                if (v.isEmpty()) {
                    throw new QueryException("at " + (t.pos + 1) + ": '~' needs a non-empty value");
                }
                v = v.toLowerCase(Locale.ROOT);
            }
            if ((op == Op.GT || op == Op.GE || op == Op.LT || op == Op.LE) && !field.equals("at")
                    && number(v).isEmpty()) {
                throw new QueryException("at " + (t.pos + 1) + ": '" + opText(op) + "' needs a number");
            }
            return v;
        }

        private <E extends Enum<E>> String enumValue(Class<E> type, String v, Token t) {
            String up = v.toUpperCase(Locale.ROOT);
            for (E c : type.getEnumConstants()) {
                if (c.name().equals(up)) {
                    return up;
                }
            }
            throw new QueryException("at " + (t.pos + 1) + ": unknown " + type.getSimpleName() + " '"
                    + Sanitize.text(v, 40) + "'");
        }
    }

    private static String opText(Op op) {
        return switch (op) {
            case GT -> ">";
            case GE -> ">=";
            case LT -> "<";
            default -> "<=";
        };
    }

    /** A field name: built-in, {@code f.<name>}, or a valid event field name. */
    static boolean fieldName(String s) {
        if (BUILT_IN.contains(s)) {
            return true;
        }
        String n = s.startsWith("f.") ? s.substring(2) : s;
        try {
            SecurityEvent.name(n);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public String toString() {
        return "Query[" + nodes + " terms" + (countBy.isEmpty() ? "" : ", count by " + countBy) + "]";
    }
}
