package dev.dwarpal.analytics;

import dev.dwarpal.Fixtures;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.engine.FreshnessGate;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.pip.InMemoryDirectory;
import dev.dwarpal.policy.CombiningAlgorithm;
import dev.dwarpal.policy.Conditions;
import dev.dwarpal.policy.Effect;
import dev.dwarpal.policy.Policy;
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.risk.BayesianRiskAggregator;

import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * A hand-built world small enough to know every decision by heart: two people, three resources, no risk
 * scorers (so every posterior is the prior 0.001 and the cost model says ALLOW), and policies built in code.
 */
final class SmallWorld {

    static final Subject ALICE = new Subject("alice", SubjectType.HUMAN, Set.of("engineer"), "engineering");
    static final Subject BOB = new Subject("bob", SubjectType.HUMAN, Set.of("analyst"), "finance");
    static final Resource WIKI = new Resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL);
    static final Resource DESIGN = new Resource("design-docs", ResourceKind.PRIVATE_APP, DataClassification.CONFIDENTIAL);
    static final Resource PAYROLL = new Resource("payroll", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED);
    static final InMemoryDirectory DIRECTORY = new InMemoryDirectory(List.of(ALICE, BOB),
            List.of(WIKI, DESIGN, PAYROLL), List.of("laptop-alice"));

    static final Policy INTERNAL_APPS = new Policy("P-01-internal", "employees use internal apps",
            new Conditions.AllOf(List.of(new Conditions.SubjectTypeIs(SubjectType.HUMAN),
                    new Conditions.ResourceKindIs(ResourceKind.PRIVATE_APP),
                    new Conditions.ClassificationAtMost(DataClassification.INTERNAL))), Effect.PERMIT);
    static final Policy ENGINEERING_READS_CONFIDENTIAL = new Policy("P-02-eng-confidential",
            "engineering may read confidential apps",
            new Conditions.AllOf(List.of(new Conditions.DepartmentIn(Set.of("engineering")),
                    new Conditions.ClassificationAtMost(DataClassification.CONFIDENTIAL),
                    new Conditions.ActionIn(Set.of(Action.READ)))), Effect.PERMIT);
    static final Policy ENGINEERING_READS_PAYROLL = new Policy("P-03-eng-payroll", "a dangerous edit",
            new Conditions.AllOf(List.of(new Conditions.DepartmentIn(Set.of("engineering")),
                    new Conditions.ResourceIdIn(Set.of("payroll")))), Effect.PERMIT);

    private SmallWorld() {
    }

    static PolicySet policies(String version, Policy... ps) {
        return new PolicySet(version, CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY, List.of(ps));
    }

    static PolicyEngine.Builder builder(PolicySet set) {
        return PolicyEngine.builder().policySet(set).directory(DIRECTORY).keyRing(Fixtures.KEYRING)
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05));
    }

    static PolicyEngine engine(PolicySet set) {
        return builder(set).build();
    }

    /** A live engine with a freshness gate whose clock is a year after the traffic. */
    static PolicyEngine liveEngine(PolicySet set) {
        return builder(set).gate(new FreshnessGate(Clock.fixed(Fixtures.T0.plus(Duration.ofDays(365)), ZoneOffset.UTC),
                Duration.ofMinutes(5))).build();
    }

    static AccessRequest request(String id, Subject s, Resource r, Action a) {
        return Fixtures.request().id(id).subject(s.id()).roles(s.roles().toArray(String[]::new))
                .resource(r.id(), r.kind(), r.classification()).action(a).build();
    }

    /** Every (subject, resource, action) combination once: 2 x 3 x 3 = 18 requests. */
    static List<AccessRequest> everything() {
        List<AccessRequest> out = new ArrayList<>();
        int i = 0;
        for (Subject s : List.of(ALICE, BOB)) {
            for (Resource r : List.of(WIKI, DESIGN, PAYROLL)) {
                for (Action a : List.of(Action.READ, Action.WRITE, Action.ADMIN)) {
                    out.add(request("r" + i++, s, r, a));
                }
            }
        }
        return out;
    }
}
