package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

/**
 * The standard detection rules. Each reads only fields written by Dwarpal's own code (types, policy ids,
 * outcomes, ids) and, where it must, fixed reason texts; it never copies a payload value into a summary
 * except ids, which {@link #entity} validates. Thresholds are starting values for a small organisation,
 * stated in docs/layer-5/part-a.md; they are assumptions, not measured rates.
 */
final class Rules {

    static final String BREAK_GLASS = "break-glass-used";
    static final String HONEYTOKEN = "honeytoken-touched";
    static final String STOLEN_TOKEN = "stolen-token-revoked";
    static final String DENY_STORM_SUBJECT = "deny-storm-subject";
    static final String DENY_STORM_IP = "deny-storm-ip";
    static final String MFA_FATIGUE = "mfa-fatigue";
    static final String TRAVEL_THEN_ALLOW = "impossible-travel-allow";
    static final String DLP_SPIKE = "dlp-block-spike";
    static final String PAM_REFUSED = "pam-refused";
    static final String BREAK_GLASS_REFUSED = "break-glass-refused";

    /** Reason text {@code PolicyAdministrator} writes when a token is presented for another subject or device. */
    static final String TOKEN_THEFT_REASON = "possible token theft";
    static final String HONEYTOKEN_POLICY = "hard-gate:honeytoken";
    private static final int MAX_ENTITIES = 12;
    private static final String TRAVEL = "RiskFactor[name=impossible-travel, logLikelihoodRatio=";
    private static final int MAX_NUMBER = 32;

    private Rules() {
    }

    /** One rule's finding: what the engine deduplicates, throttles and turns into an alert. */
    static final class Hit {
        final String rule;
        final Severity severity;
        final String key;
        final List<Entity> entities;
        final List<Long> evidence;
        final Instant at;
        final String summary;

        Hit(String rule, Severity severity, String key, List<Entity> entities, List<Long> evidence, Instant at,
            String summary) {
            this.rule = rule;
            this.severity = severity;
            this.key = key;
            this.entities = List.copyOf(entities);
            this.evidence = List.copyOf(evidence);
            this.at = at;
            this.summary = summary;
        }
    }

    /** A detection rule: sees every verified event in order; keeps bounded state of its own. */
    interface Rule {
        void observe(AuditEvent e, Consumer<Hit> hits);

        /** Keys currently tracked. */
        int stateSize();

        /** New keys refused because the state was full. */
        long overflow();
    }

    static List<Rule> standard(int maxKeys) {
        return List.of(new BreakGlassUsed(), new Honeytoken(), new StolenToken(), new DenyStormSubject(maxKeys),
                new DenyStormIp(maxKeys), new MfaFatigue(maxKeys), new TravelThenAllow(maxKeys),
                new DlpSpike(maxKeys), new PamRefused(maxKeys));
    }

    /**
     * An entity from a payload value. A value that is not a valid id (only possible in a record Dwarpal
     * did not write) is not dropped, which would let it hide; it becomes {@code invalid-<hash>}.
     */
    static Optional<Entity> entity(Entity.Kind kind, Optional<String> raw) {
        if (raw.isEmpty() || raw.get().isEmpty()) {
            return Optional.empty();
        }
        String v = raw.get();
        try {
            return Optional.of(new Entity(kind, Validate.id(v, "entity")));
        } catch (IllegalArgumentException e) {
            return Optional.of(new Entity(kind, "invalid-" + Digests.sha256Hex(v).substring(0, 16)));
        }
    }

    private static String id(Optional<Entity> e) {
        return e.map(Entity::id).orElse("-");
    }

    private static List<Entity> entities(Optional<Entity> first, List<WindowCounter.Entry> entries, Entity.Kind kind) {
        Set<Entity> out = new LinkedHashSet<>();
        first.ifPresent(out::add);
        for (WindowCounter.Entry x : entries) {
            if (out.size() >= MAX_ENTITIES) {
                break;
            }
            entity(kind, Optional.of(x.tag())).ifPresent(out::add);
        }
        return new ArrayList<>(out);
    }

    private static List<Long> sequences(List<WindowCounter.Entry> entries) {
        List<Long> out = new ArrayList<>(entries.size());
        for (WindowCounter.Entry x : entries) {
            out.add(x.sequence());
        }
        return out;
    }

    private static boolean decision(AuditEvent e, String outcome) {
        return e.type().equals("ACCESS_DECISION") && e.field("outcome").filter(outcome::equals).isPresent();
    }

    /** Whether the decision's factors include a positive impossible-travel factor. */
    static boolean impossibleTravel(AuditEvent e) {
        Optional<String> f = e.field("factors");
        if (f.isEmpty()) {
            return false;
        }
        // Plain index search, no regular expression (no ReDoS on a long factors string). Only a factor that
        // starts the list or follows ", " counts, so text inside another factor's evidence cannot pose as one.
        String s = f.get();
        int i = s.startsWith("[" + TRAVEL) ? 1 : s.indexOf(", " + TRAVEL);
        if (i < 0) {
            return false;
        }
        int from = s.indexOf(TRAVEL, i) + TRAVEL.length();
        int to = s.indexOf(',', from);
        if (to < 0 || to - from > MAX_NUMBER) {
            return false;
        }
        try {
            double llr = Double.parseDouble(s.substring(from, to));
            return Double.isFinite(llr) && llr > 0;
        } catch (NumberFormatException ex) {
            return false;
        }
    }

    // ---- stateless rules -----------------------------------------------------------------------------

    /** Every break-glass use is a CRITICAL alert: someone is acting with emergency rights right now. */
    static final class BreakGlassUsed implements Rule {
        @Override
        public void observe(AuditEvent e, Consumer<Hit> hits) {
            if (!e.type().equals("BREAK_GLASS_USED")) {
                return;
            }
            Optional<Entity> who = entity(Entity.Kind.SUBJECT, e.field("subjectId").or(() -> Optional.of(e.actor())));
            hits.accept(new Hit(BREAK_GLASS, Severity.CRITICAL, e.field("grantId").orElse("seq-" + e.sequence()),
                    who.stream().toList(), List.of(e.sequence()), e.at(),
                    "break-glass account " + id(who) + " holds emergency rights; review now"));
        }

        @Override
        public int stateSize() {
            return 0;
        }

        @Override
        public long overflow() {
            return 0;
        }
    }

    /** A decision stopped by the honeytoken gate: near proof of compromise (MITRE Engage). */
    static final class Honeytoken implements Rule {
        @Override
        public void observe(AuditEvent e, Consumer<Hit> hits) {
            if (!e.type().equals("ACCESS_DECISION") || !e.field("policy").filter(HONEYTOKEN_POLICY::equals).isPresent()) {
                return;
            }
            Optional<Entity> s = entity(Entity.Kind.SUBJECT, e.field("subject"));
            Optional<Entity> d = entity(Entity.Kind.DEVICE, e.field("device"));
            Optional<Entity> ip = entity(Entity.Kind.IP, e.field("sourceIp"));
            List<Entity> ents = new ArrayList<>();
            s.ifPresent(ents::add);
            d.ifPresent(ents::add);
            ip.ifPresent(ents::add);
            if (ents.isEmpty()) {
                ents.add(new Entity(Entity.Kind.RESOURCE, "honeytoken"));
            }
            hits.accept(new Hit(HONEYTOKEN, Severity.CRITICAL, id(s) + "|" + id(d), ents, List.of(e.sequence()), e.at(),
                    "honeytoken used by subject " + id(s) + " on device " + id(d) + " from " + id(ip)));
        }

        @Override
        public int stateSize() {
            return 0;
        }

        @Override
        public long overflow() {
            return 0;
        }
    }

    /** A session ended because its token was presented for another subject or device. */
    static final class StolenToken implements Rule {
        @Override
        public void observe(AuditEvent e, Consumer<Hit> hits) {
            if (!e.type().equals("SESSION_REVOKED")
                    || !e.field("reason").filter(r -> r.contains(TOKEN_THEFT_REASON)).isPresent()) {
                return;
            }
            Optional<Entity> s = entity(Entity.Kind.SUBJECT, e.field("subjectId"));
            Optional<Entity> d = entity(Entity.Kind.DEVICE, e.field("deviceId"));
            Optional<Entity> sid = entity(Entity.Kind.SESSION, e.field("sessionId"));
            List<Entity> ents = new ArrayList<>();
            s.ifPresent(ents::add);
            d.ifPresent(ents::add);
            sid.ifPresent(ents::add);
            if (ents.isEmpty()) {
                ents.add(new Entity(Entity.Kind.SESSION, "unknown"));
            }
            hits.accept(new Hit(STOLEN_TOKEN, Severity.HIGH, id(sid), ents, List.of(e.sequence()), e.at(),
                    "session token of " + id(s) + " (device " + id(d) + ") was presented elsewhere: possible theft"));
        }

        @Override
        public int stateSize() {
            return 0;
        }

        @Override
        public long overflow() {
            return 0;
        }
    }

    // ---- counting rules ------------------------------------------------------------------------------

    /**
     * Five denies for one person within 15 minutes. The person is the <em>target</em>: anyone can send
     * requests in their name, so this alert names the addresses too and is not evidence against them.
     */
    static final class DenyStormSubject implements Rule {
        private final WindowCounter c;

        DenyStormSubject(int maxKeys) {
            c = new WindowCounter(Duration.ofMinutes(15), 5, maxKeys, false);
        }

        @Override
        public void observe(AuditEvent e, Consumer<Hit> hits) {
            if (!decision(e, "DENY")) {
                return;
            }
            Optional<Entity> s = entity(Entity.Kind.SUBJECT, e.field("subject"));
            if (s.isEmpty()) {
                return;
            }
            List<WindowCounter.Entry> hit = c.add(s.get().id(), e.at(), e.sequence(), e.field("sourceIp").orElse(""));
            if (!hit.isEmpty()) {
                hits.accept(new Hit(DENY_STORM_SUBJECT, Severity.MEDIUM, s.get().id(),
                        entities(s, hit, Entity.Kind.IP), sequences(hit), e.at(),
                        hit.size() + " denied requests in 15 min in the name of " + s.get().id()
                                + " (target of an attack, not evidence against them)"));
            }
        }

        @Override
        public int stateSize() {
            return c.size();
        }

        @Override
        public long overflow() {
            return c.overflow();
        }
    }

    /** One address denied 10 times, or for 5 different people, within an hour (stuffing, spray, Tor). */
    static final class DenyStormIp implements Rule {
        private final WindowCounter all;
        private final WindowCounter people;

        DenyStormIp(int maxKeys) {
            all = new WindowCounter(Duration.ofHours(1), 10, maxKeys, false);
            people = new WindowCounter(Duration.ofHours(1), 5, maxKeys, true);
        }

        @Override
        public void observe(AuditEvent e, Consumer<Hit> hits) {
            if (!decision(e, "DENY")) {
                return;
            }
            Optional<Entity> ip = entity(Entity.Kind.IP, e.field("sourceIp"));
            if (ip.isEmpty()) {
                return;
            }
            String subject = e.field("subject").orElse("");
            List<WindowCounter.Entry> byPeople = people.add(ip.get().id(), e.at(), e.sequence(), subject);
            List<WindowCounter.Entry> byCount = all.add(ip.get().id(), e.at(), e.sequence(), subject);
            List<WindowCounter.Entry> hit = !byPeople.isEmpty() ? byPeople : byCount;
            if (!hit.isEmpty()) {
                if (!byPeople.isEmpty()) {
                    all.reset(ip.get().id());
                } else {
                    people.reset(ip.get().id());
                }
                hits.accept(new Hit(DENY_STORM_IP, Severity.HIGH, ip.get().id(),
                        entities(ip, hit, Entity.Kind.SUBJECT), sequences(hit), e.at(),
                        hit.size() + " denied requests from " + ip.get().id() + " within an hour"
                                + (!byPeople.isEmpty() ? ", for " + hit.size() + " different people" : "")));
            }
        }

        @Override
        public int stateSize() {
            return all.size() + people.size();
        }

        @Override
        public long overflow() {
            return all.overflow() + people.overflow();
        }
    }

    /**
     * Five step-ups for one person within 30 minutes with no ALLOW in between: push-MFA
     * fatigue (M9: every prompt is another chance that a tired user approves).
     */
    static final class MfaFatigue implements Rule {
        private final WindowCounter c;

        MfaFatigue(int maxKeys) {
            c = new WindowCounter(Duration.ofMinutes(30), 5, maxKeys, false);
        }

        @Override
        public void observe(AuditEvent e, Consumer<Hit> hits) {
            if (!e.type().equals("ACCESS_DECISION")) {
                return;
            }
            Optional<Entity> s = entity(Entity.Kind.SUBJECT, e.field("subject"));
            if (s.isEmpty()) {
                return;
            }
            if (decision(e, "ALLOW")) {
                // Only a successful decision ends a run. A DENY must not: an attacker could send one bad
                // request between pushes to reset the count (red-team R-A2).
                c.reset(s.get().id());
                return;
            }
            if (!decision(e, "STEP_UP")) {
                return;
            }
            List<WindowCounter.Entry> hit = c.add(s.get().id(), e.at(), e.sequence(), e.field("sourceIp").orElse(""));
            if (!hit.isEmpty()) {
                hits.accept(new Hit(MFA_FATIGUE, Severity.HIGH, s.get().id(), entities(s, hit, Entity.Kind.IP),
                        sequences(hit), e.at(), hit.size() + " MFA challenges in a row for " + s.get().id()
                        + " within 30 min: possible MFA fatigue attack"));
            }
        }

        @Override
        public int stateSize() {
            return c.size();
        }

        @Override
        public long overflow() {
            return c.overflow();
        }
    }

    /** A decision flagged impossible travel, then an ALLOW for the same person within two hours. */
    static final class TravelThenAllow implements Rule {
        private static final long WINDOW_MILLIS = Duration.ofHours(2).toMillis();
        private final int maxKeys;
        private final LinkedHashMap<String, long[]> flagged = new LinkedHashMap<>(16, 0.75f, true);
        private long overflow;

        TravelThenAllow(int maxKeys) {
            this.maxKeys = maxKeys;
        }

        @Override
        public void observe(AuditEvent e, Consumer<Hit> hits) {
            if (!e.type().equals("ACCESS_DECISION")) {
                return;
            }
            Optional<Entity> s = entity(Entity.Kind.SUBJECT, e.field("subject"));
            if (s.isEmpty()) {
                return;
            }
            long now = e.at().toEpochMilli();
            String key = s.get().id();
            if (impossibleTravel(e)) {
                if (!flagged.containsKey(key) && flagged.size() >= maxKeys && !evict(now)) {
                    overflow++;
                } else {
                    flagged.put(key, new long[]{now, e.sequence()});
                }
            }
            if (!decision(e, "ALLOW")) {
                return;
            }
            long[] f = flagged.get(key);
            if (f == null || f[0] <= now - WINDOW_MILLIS) {
                return;
            }
            flagged.remove(key);
            List<Long> ev = f[1] == e.sequence() ? List.of(e.sequence()) : List.of(f[1], e.sequence());
            List<Entity> ents = new ArrayList<>();
            ents.add(s.get());
            entity(Entity.Kind.IP, e.field("sourceIp")).ifPresent(ents::add);
            hits.accept(new Hit(TRAVEL_THEN_ALLOW, Severity.HIGH, key + "|" + f[1], ents, ev, e.at(),
                    "access allowed for " + key + " within 2 h of an impossible-travel signal"));
        }

        private boolean evict(long now) {
            boolean freed = false;
            Iterator<Map.Entry<String, long[]>> it = flagged.entrySet().iterator();
            while (it.hasNext()) {
                if (it.next().getValue()[0] > now - WINDOW_MILLIS) {
                    break;
                }
                it.remove();
                freed = true;
            }
            return freed;
        }

        @Override
        public int stateSize() {
            return flagged.size();
        }

        @Override
        public long overflow() {
            return overflow;
        }
    }

    /** Five DLP blocks for one person within an hour: someone keeps trying to move protected data. */
    static final class DlpSpike implements Rule {
        private final WindowCounter c;

        DlpSpike(int maxKeys) {
            c = new WindowCounter(Duration.ofHours(1), 5, maxKeys, false);
        }

        @Override
        public void observe(AuditEvent e, Consumer<Hit> hits) {
            if (!e.type().equals("casb.dlp") || !e.field("action").filter("BLOCK"::equals).isPresent()) {
                return;
            }
            Optional<Entity> s = entity(Entity.Kind.SUBJECT, Optional.of(e.actor()));
            List<WindowCounter.Entry> hit = c.add(s.orElseThrow().id(), e.at(), e.sequence(),
                    e.field("resource").orElse(""));
            if (!hit.isEmpty()) {
                hits.accept(new Hit(DLP_SPIKE, Severity.MEDIUM, s.get().id(), entities(s, hit, Entity.Kind.RESOURCE),
                        sequences(hit), e.at(), hit.size() + " data-loss blocks for " + s.get().id() + " within an hour"));
            }
        }

        @Override
        public int stateSize() {
            return c.size();
        }

        @Override
        public long overflow() {
            return c.overflow();
        }
    }

    /**
     * Refused privileged access: three refused elevation requests or approvals by one person within an
     * hour (probing), and every refused break-glass attempt (HIGH: someone holds or guesses an emergency
     * credential). PAM already throttles its own refusal records, so a count here is a lower bound.
     */
    static final class PamRefused implements Rule {
        private final WindowCounter c;

        PamRefused(int maxKeys) {
            c = new WindowCounter(Duration.ofHours(1), 3, maxKeys, false);
        }

        @Override
        public void observe(AuditEvent e, Consumer<Hit> hits) {
            boolean breakGlass = e.type().equals("BREAK_GLASS_REFUSED");
            if (!breakGlass && !e.type().equals("ELEVATION_REFUSED") && !e.type().equals("ELEVATION_APPROVAL_REFUSED")) {
                return;
            }
            Optional<Entity> who = entity(Entity.Kind.SUBJECT, e.field("who").or(() -> Optional.of(e.actor())));
            String role = e.field("role").orElse("-");
            if (breakGlass) {
                hits.accept(new Hit(BREAK_GLASS_REFUSED, Severity.HIGH, who.orElseThrow().id(), List.of(who.get()),
                        List.of(e.sequence()), e.at(), "refused break-glass attempt for account " + who.get().id()));
                return;
            }
            List<WindowCounter.Entry> hit = c.add(who.orElseThrow().id(), e.at(), e.sequence(), role);
            if (!hit.isEmpty()) {
                hits.accept(new Hit(PAM_REFUSED, Severity.MEDIUM, who.get().id(), List.of(who.get()), sequences(hit),
                        e.at(), hit.size() + " refused privileged-access requests or approvals by " + who.get().id()
                        + " within an hour"));
            }
        }

        @Override
        public int stateSize() {
            return c.size();
        }

        @Override
        public long overflow() {
            return c.overflow();
        }
    }
}
