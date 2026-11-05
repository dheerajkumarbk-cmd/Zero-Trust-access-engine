package dev.dwarpal.analytics;

import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.pip.AttributeDirectory;
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.risk.SignalSnapshot;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * What-If replay of a proposed policy (model M8): the change set
 * {@code Delta = { r : D_P1(r) != D_P2(r) }} measured on recorded or simulated requests.
 *
 * <p><b>Same everything but the policy.</b> The proposed engine is {@code current.withPolicySet(proposed)}:
 * same directory, keys, gates, scorers, aggregator and costs. Both see the same frozen
 * {@link SignalSnapshot} for the whole run. So every difference is caused by the policy edit.
 *
 * <p><b>No side effects.</b> Only a {@link PolicyEngine} is accepted, never a general
 * {@code DecisionPoint}: the engine is pure (it reads its stores, never writes them), while the live
 * pipeline learns behaviour and writes audit records. A What-If that ran through the pipeline would
 * teach the behaviour model the replayed logins and flood the audit trail (red-team finding C1).
 *
 * <p><b>Frozen clock.</b> The engine takes time only from each request's own timestamp, so replay
 * evaluates every request at the moment it was made. The one clock reader, {@code FreshnessGate},
 * would deny every historical request under both policies and make the diff look empty; a replay in
 * which that gate fired is marked invalid instead of reporting "no change" (finding C2).
 *
 * <p><b>Authoritative classification.</b> Whether a change grants something new to a RESTRICTED
 * resource is decided from the directory, never from the request's claimed classification; a resource
 * the directory does not know counts as RESTRICTED (finding C3). Gains on ADMIN actions are flagged too.
 */
public final class WhatIf {

    public static final int MAX_REQUESTS = 200_000;
    public static final int MAX_CHANGES_KEPT = 10_000;
    public static final int MAX_LISTED = 50;
    static final String FRESHNESS_GATE = "hard-gate:freshness";

    /** Which way access moved for one request. */
    public enum Direction { GAIN, LOSS }

    /**
     * One request decided differently. Only identifiers that say who gains or loses what: no request id,
     * address, device or evidence.
     */
    public record Change(String subject, String resource, Action action, DataClassification classification,
                         Outcome before, boolean restrictedBefore, String policyBefore,
                         Outcome after, boolean restrictedAfter, String policyAfter, Direction direction,
                         boolean sensitive) {
    }

    /** Counts of gains and losses for one key (a policy, subject, resource or action). */
    public record Tally(String key, long gains, long losses) {
        public long total() {
            return gains + losses;
        }
    }

    public record Result(long replayed, long unchanged, long gains, long losses, List<Change> changes,
                         long changesNotKept, List<Change> sensitiveGrants, List<Tally> byPolicy,
                         List<Tally> bySubject, List<Tally> byResource, List<Tally> byAction,
                         Optional<Long> fidelityMismatches, long liveVerifiedDevices, List<String> invalid,
                         String currentVersion, String proposedVersion) {
        public Result {
            changes = List.copyOf(changes);
            sensitiveGrants = List.copyOf(sensitiveGrants);
            byPolicy = List.copyOf(byPolicy);
            bySubject = List.copyOf(bySubject);
            byResource = List.copyOf(byResource);
            byAction = List.copyOf(byAction);
            Objects.requireNonNull(fidelityMismatches, "fidelityMismatches");
            invalid = List.copyOf(invalid);
        }

        /** False when the replay could not measure the edit (see {@link #invalid()}). */
        public boolean valid() {
            return invalid.isEmpty();
        }

        public Report report(DataSource source) {
            Report.Builder b = Report.builder("What-If replay (M8): policy " + currentVersion + " -> "
                    + proposedVersion, source.withRequests(replayed));
            b.section("Validity").text("status", valid() ? "VALID" : "INVALID");
            for (String why : invalid) {
                b.text("problem", why);
            }
            b.section("Summary").count("replayed", replayed).count("unchanged", unchanged)
                    .count("gain access", gains).count("lose access", losses)
                    .count("new grants to RESTRICTED resources or ADMIN actions", sensitiveGrants.size());
            if (fidelityMismatches.isPresent()) {
                b.count("replay under current policy differs from live decision", fidelityMismatches.get())
                        .count("live decisions with a verified device (replayed without evidence)", liveVerifiedDevices)
                        .text("note", "recorded requests replay without their signed evidence (data minimisation);"
                                + " both policies see the same stripped request");
            }
            b.section("Sensitive grants (review before installing)");
            listChanges(b, sensitiveGrants);
            tallies(b, "By policy (each change counts for the policy it left and the one it went to)", byPolicy);
            tallies(b, "By subject", bySubject);
            tallies(b, "By resource", byResource);
            tallies(b, "By action", byAction);
            b.section("Changes");
            listChanges(b, changes);
            if (changesNotKept > 0) {
                b.count("changes counted but not listed", changesNotKept);
            }
            return b.build();
        }

        private static void listChanges(Report.Builder b, List<Change> list) {
            int n = 0;
            for (Change c : list) {
                if (n++ == MAX_LISTED) {
                    b.count("more not shown", list.size() - MAX_LISTED);
                    break;
                }
                b.text(c.direction() + " " + c.subject() + " " + c.action() + " " + c.resource(),
                        c.before() + (c.restrictedBefore() ? "+restricted" : "") + " (" + c.policyBefore() + ") -> "
                                + c.after() + (c.restrictedAfter() ? "+restricted" : "") + " (" + c.policyAfter()
                                + ")" + (c.sensitive() ? " [" + c.classification() + "]" : ""));
            }
            if (list.isEmpty()) {
                b.text("none", "-");
            }
        }

        private static void tallies(Report.Builder b, String name, List<Tally> list) {
            b.section(name);
            int n = 0;
            for (Tally t : list) {
                if (n++ == MAX_LISTED) {
                    b.count("more keys not shown", list.size() - MAX_LISTED);
                    break;
                }
                b.text(t.key(), "+" + t.gains() + " / -" + t.losses());
            }
            if (list.isEmpty()) {
                b.text("none", "-");
            }
        }
    }

    private final PolicyEngine current;
    private final PolicyEngine proposed;
    private final AttributeDirectory directory;

    /**
     * @throws IllegalArgumentException if the proposed set has linter errors (it could never be installed,
     *                                  so there is nothing to compare: fail closed rather than report)
     */
    public WhatIf(PolicyEngine current, PolicySet proposed, AttributeDirectory directory) {
        // Replay copies: the live freshness gate would call every old request stale and hide the diff.
        this.current = Objects.requireNonNull(current, "current").forReplay();
        this.proposed = this.current.withPolicySet(Objects.requireNonNull(proposed, "proposed"));
        this.directory = Objects.requireNonNull(directory, "directory");
    }

    /** Replays simulated or freshly built requests. */
    public Result replay(List<AccessRequest> requests, SignalSnapshot signals) {
        Objects.requireNonNull(requests, "requests");
        checkSize(requests.size());
        return run(requests.stream().map(r -> new Item(r, null)).toList(), signals);
    }

    /** Replays what a {@link RequestRecorder} kept, and measures drift from the live decisions. */
    public Result replayRecorded(List<RecordedRequest> recorded, SignalSnapshot signals) {
        Objects.requireNonNull(recorded, "recorded");
        checkSize(recorded.size());
        return run(recorded.stream().map(r -> new Item(r.request(), r)).toList(), signals);
    }

    private static void checkSize(int n) {
        if (n > MAX_REQUESTS) {
            throw new IllegalArgumentException("at most " + MAX_REQUESTS + " requests per replay");
        }
    }

    private record Item(AccessRequest request, RecordedRequest live) {
    }

    private Result run(List<Item> items, SignalSnapshot signals) {
        Objects.requireNonNull(signals, "signals");
        List<Change> changes = new ArrayList<>();
        List<Change> sensitive = new ArrayList<>();
        Map<String, long[]> byPolicy = new HashMap<>();
        Map<String, long[]> bySubject = new HashMap<>();
        Map<String, long[]> byResource = new HashMap<>();
        Map<String, long[]> byAction = new HashMap<>();
        long unchanged = 0;
        long gains = 0;
        long losses = 0;
        long notKept = 0;
        long stale = 0;
        long mismatches = 0;
        long verified = 0;
        boolean recorded = false;
        for (Item it : items) {
            AccessRequest r = Objects.requireNonNull(it.request(), "request");
            Decision before = current.decide(r, signals);
            Decision after = proposed.decide(r, signals);
            if (FRESHNESS_GATE.equals(before.matchedPolicyId()) || FRESHNESS_GATE.equals(after.matchedPolicyId())) {
                stale++;
            }
            if (it.live() != null) {
                recorded = true;
                if (before.outcome() != it.live().liveOutcome() || before.restricted() != it.live().liveRestricted()) {
                    mismatches++;
                }
                if (it.live().liveDeviceVerified()) {
                    verified++;
                }
            }
            int delta = accessRank(after) - accessRank(before);
            if (delta == 0) {
                unchanged++;
                continue;
            }
            Direction dir = delta > 0 ? Direction.GAIN : Direction.LOSS;
            DataClassification cls = directory.resource(r.resource().id()).map(Resource::classification)
                    .orElse(DataClassification.RESTRICTED);
            boolean isSensitive = dir == Direction.GAIN
                    && (cls == DataClassification.RESTRICTED || r.action() == Action.ADMIN);
            Change c = new Change(r.subject().id(), r.resource().id(), r.action(), cls,
                    before.outcome(), before.restricted(), before.matchedPolicyId(),
                    after.outcome(), after.restricted(), after.matchedPolicyId(), dir, isSensitive);
            if (dir == Direction.GAIN) {
                gains++;
            } else {
                losses++;
            }
            if (changes.size() < MAX_CHANGES_KEPT) {
                changes.add(c);
            } else {
                notKept++;
            }
            if (isSensitive && sensitive.size() < MAX_CHANGES_KEPT) {
                sensitive.add(c);
            }
            int idx = dir == Direction.GAIN ? 0 : 1;
            byPolicy.computeIfAbsent(after.matchedPolicyId(), k -> new long[2])[idx]++;
            if (!after.matchedPolicyId().equals(before.matchedPolicyId())) {
                byPolicy.computeIfAbsent(before.matchedPolicyId(), k -> new long[2])[idx]++;
            }
            bySubject.computeIfAbsent(c.subject(), k -> new long[2])[idx]++;
            byResource.computeIfAbsent(c.resource(), k -> new long[2])[idx]++;
            byAction.computeIfAbsent(c.action().name(), k -> new long[2])[idx]++;
        }
        List<String> invalid = new ArrayList<>();
        if (stale > 0) {
            invalid.add(stale + " replayed requests were denied by the freshness gate: build the replay engine"
                    + " without FreshnessGate, or the diff is meaningless");
        }
        return new Result(items.size(), unchanged, gains, losses, changes, notKept, sensitive,
                sorted(byPolicy), sorted(bySubject), sorted(byResource), sorted(byAction),
                recorded ? Optional.of(mismatches) : Optional.empty(), verified, invalid,
                current.policySet().version(), proposed.policySet().version());
    }

    /**
     * How much access a decision gives: DENY lowest, then STEP_UP, ALLOW_LIMITED, ALLOW; within one
     * outcome a restricted decision gives less than an unrestricted one.
     */
    static int accessRank(Decision d) {
        int byOutcome = Outcome.values().length - 1 - d.outcome().ordinal();
        return byOutcome * 2 + (d.restricted() ? 0 : 1);
    }

    private static List<Tally> sorted(Map<String, long[]> m) {
        return m.entrySet().stream().map(e -> new Tally(e.getKey(), e.getValue()[0], e.getValue()[1]))
                .sorted(Comparator.comparingLong(Tally::total).reversed().thenComparing(Tally::key)).toList();
    }
}
