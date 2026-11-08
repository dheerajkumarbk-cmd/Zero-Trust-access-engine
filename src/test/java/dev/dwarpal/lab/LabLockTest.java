package dev.dwarpal.lab;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** One running lab per directory: a second one must not disturb the first (it used to stop the first one's clock). */
class LabLockTest {

    @TempDir
    Path dir;

    @Test
    void aSecondLabIsRefusedBeforeItTouchesTheFirstLabsAnchor() throws Exception {
        LabConfig config = LabConfig.defaults(dir).withPort(0);
        LabWorld first = LabWorld.create(config);
        try {
            Path anchor = dir.resolve("audit.anchor");
            Files.writeString(anchor, "the first lab's anchor");

            IllegalStateException e = assertThrows(IllegalStateException.class, () -> LabWorld.create(config));

            assertTrue(e.getMessage().contains("in use by a running lab"), e.getMessage());
            assertEquals("the first lab's anchor", Files.readString(anchor));
        } finally {
            first.close();
        }
    }

    @Test
    void aLabThatClosedLeavesItsDirectoryFree() throws Exception {
        LabConfig config = LabConfig.defaults(dir).withPort(0);
        LabWorld.create(config).close();
        LabWorld.create(config).close();
    }
}
