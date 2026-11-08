package dev.dwarpal.console.admin;

import dev.dwarpal.admin.PolicyInstaller;
import dev.dwarpal.analytics.RequestRecorder;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.directory.Directory;
import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.lab.scenarios.LabSession;
import dev.dwarpal.pam.PrivilegedAccessManager;
import dev.dwarpal.pip.AttributeDirectory;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.sim.SimRequests;
import dev.dwarpal.soar.DeviceIsolation;
import dev.dwarpal.soar.PlaybookCompiler;
import dev.dwarpal.soar.PlaybookInstaller;
import dev.dwarpal.soar.RuleCatalogue;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * {@link AdminServices} over the running lab. It always asks the {@link LabSession} for the current world, because a
 * reset replaces it. The lab holds the signing keys of its two administrators, {@code ada} and {@code ray}, as it holds
 * the analysts' keys: the lab's stand-in for hardware-bound keys, used only after the host has checked a fresh
 * second factor for the person signed in under that name.
 */
public final class LabAdminServices implements AdminServices {

    private final LabSession session;
    private final Directory people;
    private final PlaybookCompiler compiler = new PlaybookCompiler(RuleCatalogue.reference(), ResponseSettings.defaults(),
            Set.of("ticket", "chat"), true);
    private final Object lock = new Object();
    private long generation = -1;
    private String playbookYaml;

    public LabAdminServices(LabSession session) {
        this(session, null);
    }

    /** @param people the directory database, or null when the lab runs without it */
    public LabAdminServices(LabSession session, Directory people) {
        this.session = session;
        this.people = people;
    }

    @Override
    public Optional<Directory> people() {
        return Optional.ofNullable(people);
    }

    private LabWorld world() {
        return session.world();
    }

    @Override
    public PolicyInstaller policies() {
        return world().policies;
    }

    @Override
    public PlaybookInstaller playbooks() {
        return world().playbooks;
    }

    @Override
    public PlaybookCompiler playbookCompiler() {
        return compiler;
    }

    @Override
    public String activePlaybookYaml() {
        synchronized (lock) {
            if (generation != session.generation() || playbookYaml == null) {
                generation = session.generation();
                playbookYaml = reference();
            }
            return playbookYaml;
        }
    }

    @Override
    public void playbookInstalled(String yaml) {
        synchronized (lock) {
            generation = session.generation();
            playbookYaml = yaml;
        }
    }

    private static String reference() {
        try (InputStream in = PlaybookCompiler.class.getResourceAsStream(PlaybookCompiler.REFERENCE)) {
            if (in == null) {
                throw new IllegalStateException("reference playbooks missing from the build");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public PrivilegedAccessManager pam() {
        return world().pam;
    }

    @Override
    public RequestRecorder recorder() {
        return world().recorder;
    }

    @Override
    public AttributeDirectory directory() {
        return world().org.directory;
    }

    @Override
    public SignalSnapshot signals() {
        LabWorld w = world();
        return w.org.signals.snapshot(w.now());
    }

    @Override
    public Clock clock() {
        return world().org.clock;
    }

    @Override
    public List<AuditRecord> recentAudit(int max) {
        LabWorld w = world();
        long last = w.org.sink.lastSequence();
        List<AuditRecord> out = new ArrayList<>();
        long from = Math.max(0, last - max);
        while (true) {
            List<AuditRecord> batch = w.org.sink.after(from, 5_000);
            if (batch.isEmpty()) {
                return out;
            }
            out.addAll(batch);
            from = batch.getLast().sequence();
        }
    }

    @Override
    public Optional<KeyPair> signingKey(String adminId) {
        return switch (adminId) {
            case "ada" -> Optional.of(SimOrganisation.ADMIN_ADA);
            case "ray" -> Optional.of(SimOrganisation.ADMIN_RAY);
            default -> Optional.empty();
        };
    }

    @Override
    public String keyId(String adminId, KeyPurpose purpose) {
        return (purpose == KeyPurpose.POLICY_SIGNER ? "pol-" : "elev-") + adminId;
    }

    @Override
    public String idpKeyId() {
        return SimRequests.IDP_KEY_ID;
    }

    @Override
    public KeyPair idpKey() {
        return SimRequests.IDP;
    }

    @Override
    public Map<String, String> isolations() {
        Map<String, String> out = new LinkedHashMap<>();
        for (DeviceIsolation.Isolation i : world().isolation.all()) {
            out.put(i.deviceId(), i.state().name());
        }
        return out;
    }

    @Override
    public boolean resetting() {
        return session.resetting();
    }

    @Override
    public void resetLab() throws IOException, InterruptedException {
        session.reset();
    }

    @Override
    public List<Revoked> revocations() {
        List<Revoked> out = new ArrayList<>();
        for (LabWorld.Revocation r : world().revocations) {
            out.add(new Revoked(r.kind(), r.id(), r.actor(), r.at()));
        }
        return out;
    }
}
