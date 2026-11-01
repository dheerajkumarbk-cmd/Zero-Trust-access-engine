package dev.dwarpal;

import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.policy.Conditions;
import dev.dwarpal.risk.RiskAssessment;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Evidence for the narrow EI_EXPOSE_REP suppression in spotbugs-exclude.xml: every collection a
 * record hands out is unmodifiable, so callers cannot alter a decision, a role set or a policy
 * condition after construction (e.g. grant themselves a role).
 */
class ImmutabilityTest {

    private static void unmodifiable(Executable mutation) {
        assertThrows(UnsupportedOperationException.class, mutation);
    }

    @Test
    void exposedCollectionsCannotBeMutated() {
        Subject s = new Subject("a", SubjectType.HUMAN, new HashSet<>(Set.of("r")), "d");
        unmodifiable(() -> s.roles().add("admin"));

        Decision d = new Decision("q", Outcome.DENY, false, false, "p", "v", RiskAssessment.notEvaluated(0.1),
                new ArrayList<>(List.of("x")), Fixtures.T0);
        unmodifiable(() -> d.reasons().add("forged"));

        var all = new Conditions.AllOf(new ArrayList<>(List.of(new Conditions.Always())));
        unmodifiable(() -> all.parts().clear());
        var any = new Conditions.AnyOf(new ArrayList<>(List.of(new Conditions.Always())));
        unmodifiable(() -> any.parts().clear());

        unmodifiable(() -> new Conditions.RoleIn(new HashSet<>(Set.of("r"))).roles().add("x"));
        unmodifiable(() -> new Conditions.DepartmentIn(new HashSet<>(Set.of("d"))).departments().add("x"));
        unmodifiable(() -> new Conditions.CountryIn(new HashSet<>(Set.of("IN"))).countries().add("X"));
        unmodifiable(() -> new Conditions.RegionIn(new HashSet<>(Set.of("m"))).regions().add("x"));
        unmodifiable(() -> new Conditions.ResourceIdIn(new HashSet<>(Set.of("w"))).ids().add("x"));

        var intel = new dev.dwarpal.pip.ThreatIntel(new HashSet<>(Set.of("1.2.3.4")), new HashSet<>(), new HashSet<>());
        unmodifiable(() -> intel.abuseIps().clear());          // nobody can quietly delist an attacker
        unmodifiable(() -> intel.torExitIps().add("x"));
        unmodifiable(() -> intel.hostingAsns().add("x"));
    }
}
