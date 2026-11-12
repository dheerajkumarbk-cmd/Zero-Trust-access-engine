package dev.dwarpal.lab;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.sim.SimOrganisation;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The administrators, installers, privileged access and request recorder the admin views work with. */
class LabAdminWiringTest {

    @Test
    void theAdministratorsKeysAreTrustedForExactlyTheirPurposesAndBoundToThem() throws Exception {
        try (LabWorld w = LabWorld.create(LabConfig.defaults(Files.createTempDirectory("dwarpal-admin")).withPort(0)
                .withUsers(30))) {
            w.warmUp(1);
            Instant now = w.now();
            byte[] msg = "anything".getBytes();
            for (String who : LabWorld.ADMINS) {
                var key = who.equals("ada") ? SimOrganisation.ADMIN_ADA : SimOrganisation.ADMIN_RAY;
                SignatureProof p = new SignatureProof("pol-" + who, now, Ed25519.sign(key.getPrivate(), msg));
                assertTrue(w.org.keys.verify(KeyPurpose.POLICY_SIGNER, who, p, msg, now, Duration.ofMinutes(5)).valid());
                assertFalse(w.org.keys.verify(KeyPurpose.POLICY_SIGNER, "ana", p, msg, now, Duration.ofMinutes(5)).valid(),
                        "bound to the administrator");
                assertFalse(w.org.keys.verify(KeyPurpose.SOC_ANALYST, who, p, msg, now, Duration.ofMinutes(5)).valid(),
                        "an administrator key is not an analyst key");
            }
            assertEquals(0, w.playbooks.sequence());
            // what the engine decided while the lab warmed up was recorded for what-if replay
            assertTrue(w.recorder.stats().kept() > 0, "requests are recorded: " + w.recorder.stats());
            assertEquals(w.requestsDecided(), w.recorder.stats().recorded());
            assertTrue(w.pages.isEmpty());
        }
    }
}
