package dev.dwarpal.soar;

import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.soc.Priority;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Simulated connectors: files, never the network; bounded; nothing but ids and fixed text. */
class ConnectorTest {

    private final SimOrganisation.SimClock clock = new SimOrganisation.SimClock();

    private Connector.Notification note(String title) {
        return new Connector.Notification("case-1", "al-1", "mfa-fatigue", Priority.P1, PlaybookSet.Template.ACTION_TAKEN,
                title, clock.instant());
    }

    @Test
    void writesOneSanitisedJsonLinePerNotification(@TempDir Path dir) throws IOException {
        FileConnector c = new FileConnector("ticket", Connector.Kind.TICKET, dir, 10, clock);
        assertTrue(c.send(note("first\nFORGED: second line")));
        assertTrue(c.send(note("x".repeat(500))));
        List<String> lines = Files.readAllLines(dir.resolve("ticket.jsonl"));
        assertEquals(2, lines.size(), "a line break in a title cannot forge a second record");
        assertTrue(lines.getFirst().startsWith("{\"connector\":\"ticket\",\"kind\":\"ticket\""));
        assertTrue(lines.get(1).length() < 500);
        assertEquals(2, c.sent());
        assertEquals("ticket", c.name());
        assertEquals(Connector.Kind.TICKET, c.kind());
    }

    @Test
    void floodsAndFullFilesAreRefusedAndCounted(@TempDir Path dir) throws IOException {
        FileConnector c = new FileConnector("chat", Connector.Kind.CHAT, dir, 2, clock);
        assertTrue(c.send(note("a")));
        assertTrue(c.send(note("b")));
        assertFalse(c.send(note("c")), "rate limited");
        clock.set(clock.instant().plus(Duration.ofMinutes(2)));
        Files.write(dir.resolve("chat.jsonl"), new byte[(int) FileConnector.MAX_FILE_BYTES]);
        assertFalse(c.send(note("d")), "file full");
        assertEquals(2, c.refused());
    }

    @Test
    void anUnwritableFileIsAFailureNotACrash(@TempDir Path dir) throws IOException {
        Files.createDirectory(dir.resolve("email.jsonl"));
        FileConnector c = new FileConnector("email", Connector.Kind.EMAIL, dir, 2, clock);
        assertFalse(c.send(note("a")));
        assertEquals(1, c.refused());
    }

    @Test
    void configurationIsChecked(@TempDir Path dir) {
        assertThrows(IllegalArgumentException.class, () -> new FileConnector("../x", Connector.Kind.TICKET, dir, 1, clock));
        assertThrows(IllegalArgumentException.class, () -> new FileConnector("a/b", Connector.Kind.TICKET, dir, 1, clock));
        assertThrows(IllegalArgumentException.class, () -> new FileConnector("t", Connector.Kind.TICKET,
                dir.resolve("missing"), 1, clock));
        assertThrows(IllegalArgumentException.class, () -> new FileConnector("t", Connector.Kind.TICKET, dir, 0, clock));
        assertThrows(IllegalArgumentException.class, () -> new Connector.Notification("case 1", "al-1", "r", Priority.P1,
                PlaybookSet.Template.ACTION_TAKEN, "t", clock.instant()));
    }

    @Test
    void theSimulatedSensorOnlyAnswersForEnrolledDevices() {
        SimulatedSensor s = new SimulatedSensor(clock);
        IsolationCommand cmd = new IsolationCommand("iso-1", "laptop-x", IsolationCommand.Action.ISOLATE, "case-1",
                clock.instant());
        assertFalse(s.deliver(cmd));
        assertTrue(s.drain().isEmpty());
        assertFalse(s.isolated("laptop-x"));
        assertTrue(cmd.ackBody().contains("\"action\":\"isolate\""));
        assertThrows(IllegalArgumentException.class, () -> new SensorAck("d", "k", 0, clock.instant(), "{}", "s"));
        assertThrows(IllegalArgumentException.class, () -> new SensorAck("d", "k", 1, clock.instant(),
                "x".repeat(SensorAck.MAX_BODY + 1), "s"));
    }
}
