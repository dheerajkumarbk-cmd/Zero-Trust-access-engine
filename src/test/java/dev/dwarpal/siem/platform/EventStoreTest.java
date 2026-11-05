package dev.dwarpal.siem.platform;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.AuditSource;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.soc.ChainedEvent;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EventSearch;
import dev.dwarpal.soc.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Part D: the event store reads only the verified chain, answers within its cost limits and says when it stopped. */
class EventStoreTest {

    private static final Instant T = Fx.T0;
    private static final Instant FROM = T.minus(Duration.ofDays(1));
    private static final Instant TO = T.plus(Duration.ofDays(1));

    private static SecurityEvent flow(int i, String device, String dst) {
        return new SecurityEvent("fw-" + i, T.plusSeconds(i), "firewall", SecurityEvent.Category.NETWORK,
                "network.flow", SecurityEvent.EventOutcome.SUCCESS, SecurityEvent.Provenance.COLLECTED,
                List.of(Entity.device(device), Entity.ip(dst)), Map.of("dst", dst, "bytes", Integer.toString(i)));
    }

    private static EventStore filled(Fx.Trail t, int n, int capacity) {
        return filled(t, n, capacity, EventStore.MAX_EXAMINED);
    }

    private static EventStore filled(Fx.Trail t, int n, int capacity, int maxExamined) {
        for (int i = 0; i < n; i++) {
            t.collected(flow(i, "laptop-" + (i % 10), "10.0.0." + (i % 3 + 1)), T.plusSeconds(i));
        }
        EventStore s = new EventStore(t.cursor(), capacity, maxExamined);
        while (s.refresh(10_000).read() > 0) {
            // read everything
        }
        return s;
    }

    // ---- abuse first ----------------------------------------------------------------------------------------

    @Test
    void aRecordForgedWithAnotherKeyAndEverythingAfterItIsNeverSearchable() {
        Fx.Trail t = new Fx.Trail();
        t.collected(flow(1, "laptop-1", "10.0.0.1"), T);
        AuditRecord good = t.sink.snapshot().getFirst();
        InMemoryAuditSink forged = new InMemoryAuditSink();
        forged.write(good);
        AuditLog other = new AuditLog(Fx.key(), new InMemoryAuditSink(), new AuditLog.Head(1, good.mac()));
        AuditRecord fake = other.append("SECURITY_EVENT", "collector:firewall", T, Map.of("x", "y"));
        forged.write(fake);
        EventStore s = new EventStore(AuditCursor.fromStart(forged, t.key), 100);
        EventStore.Refresh r = s.refresh(100);
        assertTrue(r.broken().isPresent());
        assertEquals(1, s.size());
        EventSearch.Result res = s.search("", FROM, TO, 10);
        assertEquals(1, res.events().size());
        assertTrue(res.problem().orElseThrow().contains("broken"), "every answer says the trail is broken");
        assertTrue(res.truncated());
    }

    @Test
    void badArgumentsAreAnswersWithAProblemNotExceptions() {
        EventStore s = filled(new Fx.Trail(), 10, 100);
        assertTrue(s.search("dataset =", FROM, TO, 10).problem().isPresent());
        assertTrue(s.search("x".repeat(EventSearch.MAX_QUERY + 1), FROM, TO, 10).problem().isPresent());
        assertTrue(s.search("", TO, FROM, 10).problem().isPresent());
        assertTrue(s.search("", FROM, TO, 0).problem().isPresent());
        assertTrue(s.search("", FROM, TO, EventSearch.MAX_LIMIT + 1).problem().isPresent());
        assertTrue(s.search("", Instant.MIN, Instant.MAX, 10).problem().isPresent());
        assertTrue(s.search("a = 1 | count by a", FROM, TO, 10).problem().orElseThrow().contains("counts"));
        assertTrue(s.counts("a = 1", FROM, TO).problem().isPresent());
        assertTrue(s.counts("a = ", FROM, TO).problem().isPresent());
        assertTrue(s.counts("| count by a", Instant.MIN, Instant.MAX).problem().isPresent());
        assertThrows(IllegalArgumentException.class, () -> new EventStore(new Fx.Trail().cursor(), 0));
        assertThrows(IllegalArgumentException.class, () -> new EventStore(new Fx.Trail().cursor(), 1, 0));
    }

    @Test
    void aBroadQueryOverAHugeStoreStopsAtItsCostLimitAndSaysSo() {
        Fx.Trail t = new Fx.Trail();
        EventStore s = filled(t, 5_000, 5_000, 2_000);
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            EventSearch.Result r = s.search("bytes = never", FROM, TO, 10);
            assertTrue(r.truncated());
            assertTrue(r.problem().orElseThrow().contains("stopped after examining"));
            EventStore.Counts c = s.counts("* | count by bytes", FROM, TO);
            assertTrue(c.truncated());
            assertEquals(EventStore.MAX_GROUPS, c.groups().size(), "groups are capped");
            EventSearch.Result narrow = s.search("device = laptop-3 and dst = 10.0.0.1", FROM, TO, 5);
            assertTrue(narrow.problem().isEmpty(), "an index narrows the search below the limit");
            assertEquals(5, narrow.events().size());
        });
    }

    @Test
    void theStoreIsBoundedAndSaysWhatItNoLongerHas() {
        Fx.Trail t = new Fx.Trail();
        EventStore s = filled(t, 50, 20);
        assertEquals(20, s.size());
        assertEquals(30, s.evicted());
        EventSearch.Result r = s.search("", FROM, TO, 100);
        assertEquals(20, r.events().size());
        assertTrue(r.problem().orElseThrow().contains("no longer in memory"));
        EventSearch.Result recent = s.search("", T.plusSeconds(40), TO, 100);
        assertTrue(recent.problem().isEmpty(), "a range after the evicted events is complete");
        assertEquals(10, recent.events().size());
    }

    // ---- meaning --------------------------------------------------------------------------------------------

    @Test
    void searchIsNewestFirstWithinTheRangeAndUsesIndexes() {
        Fx.Trail t = new Fx.Trail();
        EventStore s = filled(t, 100, 1_000);
        t.decision("DENY", "u1", "laptop-1", "198.51.100.66", T.plusSeconds(500));
        t.log.append("SECURITY_EVENT", "collector:firewall", T, Map.of("dataset", "firewall"));
        EventStore.Refresh r = s.refresh(100);
        assertEquals(2, r.read());
        assertEquals(1, r.malformed());
        assertEquals(1, s.malformed());
        EventSearch.Result all = s.search("device = laptop-3", FROM, TO, 3);
        assertEquals(List.of("fw-93", "fw-83", "fw-73"), all.events().stream().map(c -> c.event().id()).toList());
        assertEquals(10, all.matched());
        assertTrue(all.truncated());
        EventSearch.Result range = s.search("dataset = firewall", T.plusSeconds(10), T.plusSeconds(20), 100);
        assertEquals(10, range.events().size(), "from inclusive, to exclusive");
        assertFalse(range.truncated());
        assertEquals(1, s.search("category = access and subject = u1 and outcome = failure", FROM, TO, 10).matched());
        assertEquals(0, s.search("ip = \"bad id!\"", FROM, TO, 10).matched());
        assertEquals(0, s.search("category = cloud", FROM, TO, 10).matched());
        assertEquals(0, s.search("dataset = cloud", FROM, TO, 10).matched());
        ChainedEvent c = s.search("id = fw-7", FROM, TO, 1).events().getFirst();
        assertEquals(8, c.sequence());

        EventStore.Counts counts = s.counts("dataset = firewall | count by dst", FROM, TO);
        assertEquals(3, counts.groups().size());
        assertEquals(34, counts.groups().getFirst().count());
        assertEquals(100, counts.matched());
        EventStore.Counts missing = s.counts("dataset = firewall | count by nothing", FROM, TO);
        assertEquals(List.of("-"), missing.groups().getFirst().values());
    }

    @Test
    void evictionKeepsIndexesConsistent() {
        Fx.Trail t = new Fx.Trail();
        EventStore s = filled(t, 300, 100);
        for (int i = 0; i < 10; i++) {
            List<ChainedEvent> got = new ArrayList<>(s.search("device = laptop-" + i, FROM, TO, 100).events());
            assertEquals(10, got.size());
            assertTrue(got.stream().allMatch(c -> c.sequence() > 200));
        }
        assertEquals(100, s.counts("* | count by device", T.plusSeconds(200), TO).matched());
        AuditSource src = t.sink;
        assertEquals(300, src.lastSequence());
    }
}
