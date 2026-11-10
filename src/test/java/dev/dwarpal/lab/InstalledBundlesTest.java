package dev.dwarpal.lab;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The saved bundles: kept sealed, read back only when intact. */
class InstalledBundlesTest {

    private static final String YAML = "version: \"v-9\"\nalgorithm: DENY_OVERRIDES\ndefault: DENY\npolicies: []\n";
    private static final InstalledBundles.Kind POLICY = InstalledBundles.Kind.POLICY;

    @Test
    void aSavedBundleComesBackWithItsFields() throws IOException {
        Path dir = Files.createTempDirectory("dwarpal-bundles");
        InstalledBundles b = new InstalledBundles(dir);
        assertFalse(b.exists(POLICY));
        assertTrue(b.load(POLICY).isEmpty());
        assertEquals(0, b.refusedCount(), "no file is not a refusal");
        b.save(POLICY, 4, YAML, List.of("ada", "ray"));
        InstalledBundles again = new InstalledBundles(dir);
        InstalledBundles.Saved s = again.load(POLICY).orElseThrow();
        assertEquals(4, s.sequence());
        assertEquals(YAML, s.yaml());
        assertEquals(List.of("ada", "ray"), s.approvers());
        assertEquals(POLICY, s.kind());
        assertTrue(again.load(InstalledBundles.Kind.PLAYBOOK).isEmpty());
        b.save(POLICY, 5, YAML + "# more\n", List.of("ada", "ray"));
        assertEquals(5, again.load(POLICY).orElseThrow().sequence());
        assertEquals(0, again.refusedCount());
    }

    @Test
    void oneFlippedByteAnywhereIsRefused() throws IOException {
        Path dir = Files.createTempDirectory("dwarpal-bundles");
        InstalledBundles b = new InstalledBundles(dir);
        b.save(POLICY, 2, YAML, List.of("ada", "ray"));
        Path f = b.file(POLICY);
        byte[] good = Files.readAllBytes(f);
        for (int i = 0; i < good.length; i++) {
            byte[] bad = good.clone();
            bad[i] ^= 0x01;
            Files.write(f, bad);
            assertTrue(new InstalledBundles(dir).load(POLICY).isEmpty(), "byte " + i + " changed");
        }
        Files.write(f, Arrays.copyOf(good, good.length - 1));
        assertTrue(new InstalledBundles(dir).load(POLICY).isEmpty(), "cut short");
        Files.write(f, Arrays.copyOf(good, good.length + 1));
        assertTrue(new InstalledBundles(dir).load(POLICY).isEmpty(), "extended");
        Files.write(f, good);
        assertTrue(new InstalledBundles(dir).load(POLICY).isPresent(), "the untouched file is fine");
    }

    @Test
    void aRefusalIsCountedAndNamedWithoutAnyContent() throws IOException {
        Path dir = Files.createTempDirectory("dwarpal-bundles");
        InstalledBundles b = new InstalledBundles(dir);
        b.save(POLICY, 2, YAML, List.of("ada", "ray"));
        byte[] bad = Files.readAllBytes(b.file(POLICY));
        bad[bad.length / 2] ^= 0x01;
        Files.write(b.file(POLICY), bad);
        assertTrue(b.load(POLICY).isEmpty());
        assertEquals(1, b.refusedCount());
        assertFalse(b.lastRefusal().isBlank());
        assertFalse(b.lastRefusal().contains("v-9"));
    }

    @Test
    void aFileOfTheWrongKindIsRefused() throws IOException {
        Path dir = Files.createTempDirectory("dwarpal-bundles");
        InstalledBundles b = new InstalledBundles(dir);
        b.save(POLICY, 2, YAML, List.of("ada", "ray"));
        // a genuine, sealed policy file put where the playbook file belongs
        Files.copy(b.file(POLICY), b.file(InstalledBundles.Kind.PLAYBOOK));
        InstalledBundles again = new InstalledBundles(dir);
        assertTrue(again.exists(InstalledBundles.Kind.PLAYBOOK));
        assertTrue(again.load(InstalledBundles.Kind.PLAYBOOK).isEmpty());
        assertEquals(1, again.refusedCount());
    }

    @Test
    void aMissingOrChangedKeyRefusesAndASaveNeverRemakesTheKey() throws IOException {
        Path dir = Files.createTempDirectory("dwarpal-bundles");
        InstalledBundles b = new InstalledBundles(dir);
        b.save(POLICY, 2, YAML, List.of("ada", "ray"));
        Path key = dir.resolve(InstalledBundles.KEY_DIR).resolve(InstalledBundles.KEY);
        assertEquals(32, Files.size(key));
        byte[] raw = Files.readAllBytes(key);
        Files.delete(key);
        assertTrue(new InstalledBundles(dir).load(POLICY).isEmpty(), "no key, no trust");
        assertThrows(IOException.class, () -> new InstalledBundles(dir).save(POLICY, 3, YAML, List.of("ada")),
                "a new key would orphan the saved file");
        assertFalse(Files.exists(key), "the key was not remade");
        raw[0] ^= 0x01;
        Files.write(key, raw);
        assertTrue(new InstalledBundles(dir).load(POLICY).isEmpty(), "another key does not open it");
    }

    @Test
    void noPartialFileIsLeftBehind() throws IOException {
        Path dir = Files.createTempDirectory("dwarpal-bundles");
        InstalledBundles b = new InstalledBundles(dir);
        for (int i = 1; i <= 5; i++) {
            b.save(POLICY, i, YAML, List.of("ada", "ray"));
        }
        try (var files = Files.list(dir.resolve(InstalledBundles.DIR))) {
            assertEquals(List.of("policy.bundle"), files.map(p -> p.getFileName().toString()).toList());
        }
        assertTrue(new String(Files.readAllBytes(b.file(POLICY)), StandardCharsets.ISO_8859_1).endsWith("\n"));
    }

    @Test
    void nonsenseIsNotKept() throws IOException {
        InstalledBundles b = new InstalledBundles(Files.createTempDirectory("dwarpal-bundles"));
        assertThrows(IllegalArgumentException.class, () -> b.save(POLICY, 0, YAML, List.of()));
        assertThrows(IllegalArgumentException.class, () -> b.save(POLICY, 1, "", List.of()));
        assertThrows(IllegalArgumentException.class, () -> b.save(POLICY, 1, YAML, List.of("a,b\n")));
    }
}
