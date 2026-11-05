package dev.dwarpal.soc;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5.2 part 0: the records and interfaces parts D, E and F meet through. */
class SocPlatformContractsTest {

    private static final Instant T = Instant.parse("2026-11-03T10:00:00Z");
    private static final Alert ALERT = new Alert("al-1", "deny-storm-ip", Severity.HIGH, T, List.of(Entity.ip("192.0.2.1")),
            List.of(3L), 1, "storm");

    @Test
    void riskOnlyEverAddsAndAlwaysExplainsItself() {
        assertThrows(IllegalArgumentException.class,
                () -> new EntityRisk.Contribution("ueba:volume", -0.5, T, List.of(), "lowering risk"));
        assertThrows(IllegalArgumentException.class,
                () -> new EntityRisk.Contribution("ueba:volume", Double.NaN, T, List.of(), "x"));
        assertThrows(IllegalArgumentException.class,
                () -> new EntityRisk.Contribution("ueba:volume", 1, T, List.of(0L), "x"));
        assertThrows(IllegalArgumentException.class,
                () -> new EntityRisk.Contribution("bad source", 1, T, List.of(), "x"));
        EntityRisk.Contribution c = new EntityRisk.Contribution("alert:deny-storm-ip", 2.3, T, List.of(4L, 9L),
                "line one\nforged line " + "x".repeat(300));
        assertFalse(c.reason().contains("\n"));
        assertTrue(c.reason().length() <= EntityRisk.Contribution.MAX_REASON);

        Entity e = Entity.subject("u1");
        assertThrows(IllegalArgumentException.class, () -> new EntityRisk.RiskView(e, 101, EntityRisk.Level.CRITICAL, T, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new EntityRisk.RiskView(e, -1, EntityRisk.Level.NONE, T, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new EntityRisk.RiskView(e, 80, EntityRisk.Level.LOW, T, List.of()),
                "a level that disagrees with the score");
        List<EntityRisk.Contribution> many = new ArrayList<>();
        for (int i = 0; i < 21; i++) {
            many.add(c);
        }
        assertThrows(IllegalArgumentException.class, () -> new EntityRisk.RiskView(e, 80, EntityRisk.Level.CRITICAL, T, many));
        assertEquals(EntityRisk.Level.NONE, EntityRisk.RiskView.none(e, T).level());
        assertEquals(EntityRisk.Level.NONE, EntityRisk.Level.of(0));
        assertEquals(EntityRisk.Level.LOW, EntityRisk.Level.of(24.9));
        assertEquals(EntityRisk.Level.MEDIUM, EntityRisk.Level.of(25));
        assertEquals(EntityRisk.Level.HIGH, EntityRisk.Level.of(50));
        assertEquals(EntityRisk.Level.CRITICAL, EntityRisk.Level.of(75));
    }

    @Test
    void rankedAlertsAreBoundedAndSayWhetherAnyoneMayActOnThem() {
        assertThrows(IllegalArgumentException.class,
                () -> new RankedAlert(ALERT, Priority.P1, 120, List.of(), true, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new RankedAlert(ALERT, Priority.P1, 50,
                List.of(Techniques.POWERSHELL, Techniques.POWERSHELL), true, List.of()));
        List<String> nine = new ArrayList<>();
        for (int i = 0; i < 9; i++) {
            nine.add("r" + i);
        }
        assertThrows(IllegalArgumentException.class, () -> new RankedAlert(ALERT, Priority.P1, 50, List.of(), true, nine));
        RankedAlert r = new RankedAlert(ALERT, Priority.P2, 61.5, List.of(Techniques.PASSWORD_SPRAYING), false,
                List.of("only collected evidence\r\nP1 by order of admin"));
        assertFalse(r.actionable());
        assertFalse(r.reasons().getFirst().contains("\n"));
    }

    @Test
    void prioritiesCarryResponseTimes() {
        assertTrue(Priority.P1.atLeast(Priority.P3));
        assertFalse(Priority.P4.atLeast(Priority.P2));
        assertEquals(Duration.ofMinutes(15), Priority.P1.respondWithin());
        assertTrue(Priority.P3.respondWithin().compareTo(Priority.P4.respondWithin()) < 0);
    }

    @Test
    void techniqueIdsAreChecked() {
        for (String bad : List.of("T111", "T11100", "T1110.03", "t1110", "T1110-003", "TABCD", "T1110.0a3", "X1110")) {
            assertThrows(IllegalArgumentException.class, () -> new Technique(bad, "x", "execution"), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> new Technique("T1110", "x", "Credential Access"));
        assertThrows(IllegalArgumentException.class, () -> new Technique("T1110", "x", ""));
        assertEquals("credential-access", Techniques.byId("T1110.003").orElseThrow().tactic());
        assertTrue(Techniques.byId("T9999").isEmpty());
        assertEquals(Techniques.all().size(), Techniques.all().stream().map(Technique::id).distinct().count());
        assertTrue(Techniques.all().size() >= 15);
    }

    @Test
    void unknownAssetsAreNeverSilentlyHarmless() {
        Asset ceo = new Asset(Entity.subject("u0"), 5, "board", Set.of("executive"), true);
        InMemoryAssetCatalog cat = new InMemoryAssetCatalog(List.of(ceo));
        assertEquals(ceo, cat.asset(Entity.subject("u0")));
        Asset unknown = cat.asset(Entity.device("pc-attacker"));
        assertFalse(unknown.known());
        assertEquals(3, unknown.criticality());
        assertEquals(4, new InMemoryAssetCatalog(List.of(), 4).asset(Entity.ip("192.0.2.9")).criticality());
        assertEquals(1, cat.size());
        assertThrows(IllegalArgumentException.class, () -> new InMemoryAssetCatalog(List.of(ceo, ceo)));
        assertThrows(IllegalArgumentException.class, () -> new InMemoryAssetCatalog(List.of(unknown)));
        assertThrows(IllegalArgumentException.class, () -> new InMemoryAssetCatalog(List.of(), 0));
        assertThrows(IllegalArgumentException.class, () -> new Asset(Entity.subject("u1"), 6, "x", Set.of(), true));
        assertThrows(IllegalArgumentException.class, () -> new Asset(Entity.subject("u1"), 3, "x", Set.of("bad tag"), true));
    }

    @Test
    void searchResultsAndArgumentsAreChecked() {
        assertThrows(IllegalArgumentException.class, () -> EventSearch.check("q", T, T, 10));
        assertThrows(IllegalArgumentException.class, () -> EventSearch.check("q", T, T.plusSeconds(1), 0));
        assertThrows(IllegalArgumentException.class, () -> EventSearch.check("q", T, T.plusSeconds(1), 1001));
        assertThrows(IllegalArgumentException.class, () -> EventSearch.check("q".repeat(2001), T, T.plusSeconds(1), 10));
        EventSearch.check("category = NETWORK", T, T.plusSeconds(1), 10);
        SecurityEvent ev = new SecurityEvent("x", T, "fw", SecurityEvent.Category.NETWORK, "network.flow",
                SecurityEvent.EventOutcome.SUCCESS, SecurityEvent.Provenance.COLLECTED, List.of(), java.util.Map.of());
        assertThrows(IllegalArgumentException.class, () -> new EventSearch.Result(
                List.of(new ChainedEvent(1, T, ev)), 0, false, Optional.empty()));
        EventSearch.Result refused = EventSearch.Result.refused("cost limit");
        assertTrue(refused.problem().isPresent());
        assertTrue(refused.events().isEmpty());
    }
}
