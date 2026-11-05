package dev.dwarpal.ueba;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import dev.dwarpal.sim.SimTelemetry.Activity;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Asset;
import dev.dwarpal.soc.AssetCatalog;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.InMemoryAssetCatalog;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;

/**
 * Layer 5.2 part E on the labelled simulation (seed 7, 60 users, 8 days of firewall, endpoint and cloud telemetry
 * written into the audit chain). These numbers measure consistency with the threat model on data built by the same
 * team, not real-world accuracy.
 */
class UebaSimulationTest {

    static SimTrail trail;
    static Ueba ueba;
    static List<Alert> alerts = new ArrayList<>();
    static List<RankedAlert> ranked = new ArrayList<>();
    static AssetCatalog assets;

    static AssetCatalog catalog(SimTrail t) {
        List<Asset> list = new ArrayList<>();
        Set<String> admins = Set.copyOf(t.telemetry.admins());
        for (var u : t.org.users) {
            String dept = t.telemetry.departments().get(u.id());
            int c = admins.contains(u.id()) ? 4 : 3;
            list.add(new Asset(Entity.subject(u.id()), c, u.id(), Set.of(dept), true));
            list.add(new Asset(Entity.device(u.laptop()), c, u.id(), Set.of(dept, "laptop"), true));
        }
        return new InMemoryAssetCatalog(list);
    }

    @BeforeAll
    static void run() {
        trail = SimTrail.reference();
        assets = catalog(trail);
        ueba = Ueba.reference(PeerGroups.of(trail.telemetry.departments(), assets), assets, a -> alerts.add(a));
        var cursor = trail.cursor();
        while (ueba.poll(cursor, 5_000) > 0) {
            // read the whole chain
        }
        for (Alert a : alerts) {
            ranked.add(ueba.rank(a, a.raisedAt()));
        }
    }

    static Set<Activity> activities(Alert a) {
        Set<Activity> s = EnumSet.noneOf(Activity.class);
        for (long q : a.evidence()) {
            SimTrail.Label l = trail.labels.get(q);
            if (l != null) {
                s.add(l.activity());
            }
        }
        return s;
    }

    static String user(Entity e) {
        return e.id().startsWith("laptop-") ? e.id().substring("laptop-".length()) : e.id();
    }

    /** For each activity, the best priority reached per user. */
    static Map<Activity, Map<String, Priority>> best() {
        Map<Activity, Map<String, Priority>> m = new EnumMap<>(Activity.class);
        for (RankedAlert r : ranked) {
            for (Activity act : activities(r.alert())) {
                m.computeIfAbsent(act, x -> new TreeMap<>()).merge(user(r.alert().entities().get(0)), r.priority(),
                        (a, b) -> a.atLeast(b) ? a : b);
            }
        }
        return m;
    }

    @Test
    void theChainWasReadWholeAndNothingWasGuessed() {
        var s = ueba.stats();
        assertTrue(s.chainProblem().isEmpty());
        assertEquals(0, s.malformed());
        assertEquals(trail.labels.size(), s.events());
        assertEquals(4, trail.refused, "the four noise lines are refused by the test collector");
    }

    @Test
    void attacksRankP1orP2() {
        Map<Activity, Map<String, Priority>> best = best();
        System.out.println("UEBA simulation, best priority per user: " + best);
        for (String u : trail.telemetry.cast().get(Activity.A8_BEACONING)) {
            assertTrue(best.get(Activity.A8_BEACONING).get(u).atLeast(Priority.P2), "A8 " + u);
        }
        for (String u : trail.telemetry.cast().get(Activity.A9_CLOUD_EXFIL)) {
            assertTrue(best.get(Activity.A9_CLOUD_EXFIL).get(u).atLeast(Priority.P2), "A9 " + u);
        }
        Map<String, Priority> a6 = best.get(Activity.A6_STOLEN_LAPTOP_AT_HOME);
        for (var u : trail.org.users) {
            assertTrue(a6.containsKey(u.id()) && a6.get(u.id()).atLeast(Priority.P2), "A6 " + u.id());
        }
    }

    @Test
    void legitimateLookalikesDoNotRankP1() {
        for (RankedAlert r : ranked) {
            Set<Activity> act = activities(r.alert());
            boolean lookalike = act.contains(Activity.L5_BIG_LEGIT_DOWNLOAD) || act.contains(Activity.L6_ADMIN_POWERSHELL);
            // u11 is also an A6 victim on the same morning: an alert mixing both is judged as A6, not L5.
            if (lookalike && act.stream().noneMatch(Activity::attack)) {
                assertFalse(r.priority() == Priority.P1, r.alert().summary() + " " + r.reasons());
            }
        }
    }

    @Test
    void summary() {
        Map<String, Map<Priority, Integer>> table = new TreeMap<>();
        for (RankedAlert r : ranked) {
            Set<Activity> act = activities(r.alert());
            String k = act.stream().filter(Activity::attack).findFirst().map(Enum::name)
                    .orElse(act.contains(Activity.L5_BIG_LEGIT_DOWNLOAD) ? "L5" : act.contains(Activity.L6_ADMIN_POWERSHELL)
                            ? "L6" : "NORMAL");
            table.computeIfAbsent(k, x -> new EnumMap<>(Priority.class)).merge(r.priority(), 1, Integer::sum);
        }
        Map<Boolean, Integer> actionable = new HashMap<>();
        ranked.forEach(r -> actionable.merge(r.actionable(), 1, Integer::sum));
        System.out.println("UEBA simulation alerts by label and priority: " + table + "; actionable " + actionable
                + "; " + ueba.stats());
        // Every alert's entity risk is explained contribution by contribution.
        for (RankedAlert r : ranked) {
            Entity e = r.alert().entities().get(0);
            double sum = ueba.contributions(e, r.alert().raisedAt()).stream()
                    .mapToDouble(dev.dwarpal.soc.EntityRisk.Contribution::weight).sum();
            double z = Math.log(0.001 / 0.999) + sum;
            double score = Math.max(0, 100 * (1 / (1 + Math.exp(-z)) - 0.001) / 0.999);
            assertEquals(score, ueba.view(e, r.alert().raisedAt()).score(), 1e-6);
            assertFalse(ueba.anomaliesOf(r.alert().id()).isEmpty());
        }
        assertEquals(10, ueba.top(10, trail.end()).size());
        assertFalse(ranked.isEmpty());
    }
}
