package dev.dwarpal.console.admin;

import dev.dwarpal.admin.PolicyInstaller;
import dev.dwarpal.analytics.RequestRecorder;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.directory.Directory;
import dev.dwarpal.pam.PrivilegedAccessManager;
import dev.dwarpal.pip.AttributeDirectory;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.soar.PlaybookCompiler;
import dev.dwarpal.soar.PlaybookInstaller;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * What the admin module needs from the running system. The lab implements it over its own objects; a test implements
 * it over a small composition. The module never builds a policy engine, a PAM or an installer itself, so what an
 * administrator does through the console is exactly what the real components accept or refuse.
 */
public interface AdminServices {

    /** The single door for policy changes (two distinct administrators, rollback protection, audit first). */
    PolicyInstaller policies();

    PlaybookInstaller playbooks();

    /** A strict compiler of the same kind the playbook installer uses, for previews. */
    PlaybookCompiler playbookCompiler();

    /** The playbook set the SOAR runs now, as text (the shipped reference set until a change is installed). */
    String activePlaybookYaml();

    /** Called after a playbook change was installed, with the exact text that was installed. */
    void playbookInstalled(String yaml);

    PrivilegedAccessManager pam();

    /** Recent requests the engine decided (data-minimised, without signed evidence), for what-if replay. */
    RequestRecorder recorder();

    AttributeDirectory directory();

    /** The current signals (deny lists, watches) for replays. */
    SignalSnapshot signals();

    Clock clock();

    /** The directory of people, when the lab runs with its database; empty when the database is switched off. */
    default Optional<Directory> people() {
        return Optional.empty();
    }

    /** The newest {@code max} records of the audit chain, oldest first. */
    List<AuditRecord> recentAudit(int max);

    /**
     * The lab's stand-in for an administrator's hardware-bound key: the key pair for this person, if the lab holds
     * one. A person without a key cannot approve anything. The key never leaves this call's caller.
     */
    Optional<KeyPair> signingKey(String adminId);

    /** The id under which {@code adminId}'s key of this purpose is registered in the key ring. */
    String keyId(String adminId, KeyPurpose purpose);

    /** The id of the identity provider's key and the signer the lab uses to vouch for a fresh step-up. */
    String idpKeyId();

    KeyPair idpKey();

    /** Isolation state per device id (PENDING_ACK, ISOLATED, ...), for the devices page. */
    Map<String, String> isolations();

    /** What the SOC's playbooks revoked or denied, newest last. */
    List<Revoked> revocations();

    /** True while the lab is being rebuilt by a reset. */
    boolean resetting();

    /** Puts the lab back to day zero (takes seconds). */
    void resetLab() throws java.io.IOException, InterruptedException;

    /** One revocation. */
    record Revoked(String kind, String id, String actor, Instant at) {
    }
}
