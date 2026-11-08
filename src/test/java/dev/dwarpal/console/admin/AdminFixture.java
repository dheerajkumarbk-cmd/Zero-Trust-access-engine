package dev.dwarpal.console.admin;

import dev.dwarpal.admin.PolicyInstaller;
import dev.dwarpal.analytics.RequestRecorder;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.pam.PamSettings;
import dev.dwarpal.pam.PrivilegedAccessManager;
import dev.dwarpal.pip.AttributeDirectory;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.runtime.DecisionPipeline;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.sim.SimRequests;
import dev.dwarpal.soar.PlaybookCompiler;
import dev.dwarpal.soar.PlaybookInstaller;
import dev.dwarpal.soar.RuleCatalogue;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * A small administrable system for the admin module's tests, built from the real components the lab will wire: the
 * policy installer in front of the engine, the playbook installer, the privileged access manager and the request
 * recorder, on a simulated organisation with two administrators, ada and ray.
 */
final class AdminFixture implements AdminServices {

    static final KeyPair ADA = Ed25519.generateKeyPair();
    static final KeyPair RAY = Ed25519.generateKeyPair();
    static final KeyPair BREAK_GLASS = Ed25519.generateKeyPair();

    final SimOrganisation org = SimOrganisation.create(7, 12);
    final KeyRing keys;
    final PolicyInstaller installer;
    final PlaybookInstaller playbooks;
    final PlaybookCompiler compiler = new PlaybookCompiler(RuleCatalogue.reference(), ResponseSettings.defaults(),
            Set.of("ticket", "chat"), true);
    final PrivilegedAccessManager pam;
    final RequestRecorder recorder;
    final DecisionPoint pipeline;
    final List<String> pagerAlerts = new ArrayList<>();
    final List<String> installedPlaybooks = new ArrayList<>();
    final Map<String, String> isolations = new HashMap<>();
    final List<Revoked> revoked = new ArrayList<>();
    private String playbookYaml;

    AdminFixture() {
        Instant from = SimOrganisation.DAY_ZERO.minus(Duration.ofDays(400));
        Instant to = SimOrganisation.DAY_ZERO.plus(Duration.ofDays(400));
        List<TrustedKey> ks = new ArrayList<>();
        for (String id : List.of("ada", "ray")) {
            KeyPair k = id.equals("ada") ? ADA : RAY;
            ks.add(new TrustedKey("pol-" + id, KeyPurpose.POLICY_SIGNER, id, k.getPublic(), from, to));
            ks.add(new TrustedKey("elev-" + id, KeyPurpose.ELEVATION_APPROVER, id, k.getPublic(), from, to));
        }
        ks.add(new TrustedKey(SimRequests.IDP_KEY_ID, KeyPurpose.IDENTITY_PROVIDER, "corp-idp", SimRequests.IDP.getPublic(),
                from, to));
        ks.add(new TrustedKey("bg-root", KeyPurpose.BREAK_GLASS, "bg-root", BREAK_GLASS.getPublic(), from, to));
        keys = new KeyRing(ks);
        org.clock.set(SimOrganisation.DAY_ZERO.plus(Duration.ofDays(1)));
        installer = new PolicyInstaller(org.engine(), 0, keys, 2, org.audit, org.clock);
        pipeline = DecisionPipeline.standard(installer, org.audit, org.history, org.trust, org.clock);
        recorder = new RequestRecorder(pipeline, 20_000, 500);
        playbooks = new PlaybookInstaller(compiler, keys, 2, 0, org.audit, org.clock, i -> { });
        pam = new PrivilegedAccessManager(keys, Map.of("ada", Set.of("prod-admin"), "ray", Set.of("prod-admin"),
                "u3", Set.of("db-reader")), Map.of("bg-root", Set.of("prod-admin")), PamSettings.defaults(), org.audit,
                org.clock, pagerAlerts::add);
        try (var in = PlaybookCompiler.class.getResourceAsStream(PlaybookCompiler.REFERENCE)) {
            playbookYaml = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
        // some history: the first requests of the simulated organisation, decided through the recorder
        List<SimOrganisation.Step> steps = org.traffic();
        org.clock.set(steps.getFirst().at());
        org.run(recorder, steps.subList(0, Math.min(steps.size(), 120)));
    }

    @Override
    public PolicyInstaller policies() {
        return installer;
    }

    @Override
    public PlaybookInstaller playbooks() {
        return playbooks;
    }

    @Override
    public PlaybookCompiler playbookCompiler() {
        return compiler;
    }

    @Override
    public String activePlaybookYaml() {
        return playbookYaml;
    }

    @Override
    public void playbookInstalled(String yaml) {
        playbookYaml = yaml;
        installedPlaybooks.add(yaml);
    }

    @Override
    public PrivilegedAccessManager pam() {
        return pam;
    }

    @Override
    public RequestRecorder recorder() {
        return recorder;
    }

    @Override
    public AttributeDirectory directory() {
        return org.directory;
    }

    @Override
    public SignalSnapshot signals() {
        return org.signals.snapshot(org.clock.instant());
    }

    @Override
    public Clock clock() {
        return org.clock;
    }

    @Override
    public List<AuditRecord> recentAudit(int max) {
        List<AuditRecord> all = org.sink.snapshot();
        return all.size() > max ? all.subList(all.size() - max, all.size()) : all;
    }

    @Override
    public Optional<KeyPair> signingKey(String adminId) {
        return switch (adminId) {
            case "ada" -> Optional.of(ADA);
            case "ray" -> Optional.of(RAY);
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
        return isolations;
    }

    @Override
    public List<Revoked> revocations() {
        return revoked;
    }

    boolean resetCalled;

    /** The directory the page reads; null means the lab runs without its database. */
    dev.dwarpal.directory.Directory people;

    @Override
    public java.util.Optional<dev.dwarpal.directory.Directory> people() {
        return java.util.Optional.ofNullable(people);
    }

    @Override
    public boolean resetting() {
        return false;
    }

    @Override
    public void resetLab() {
        resetCalled = true;
    }

    /** The default policy text with its version replaced. */
    String policyWithVersion(String version) {
        try (var in = SimRequests.class.getResourceAsStream("/policies/default-policy.yaml")) {
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8)
                    .replace("\"2026.11.03-1\"", "\"" + version + "\"");
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
