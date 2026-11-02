package dev.dwarpal.session;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.engine.DenyListGate;
import dev.dwarpal.engine.HoneytokenGate;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.pip.InMemoryDirectory;
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.risk.BayesianRiskAggregator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;

/** Shared world for the Layer 3 tests: one engine, a directory, a settable clock, an audit trail. */
final class SessionFixtures {

    static final Instant T = Fixtures.T0;

    /** Alice is an engineer with finance rights; Carol is an engineer. */
    static final InMemoryDirectory DIRECTORY = new InMemoryDirectory(
            List.of(new Subject("alice", SubjectType.HUMAN, Set.of("engineer", "finance"), "engineering"),
                    new Subject("carol", SubjectType.HUMAN, Set.of("engineer"), "engineering")),
            List.of(new Resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL),
                    new Resource("drive", ResourceKind.SAAS_DATA, DataClassification.INTERNAL),
                    new Resource("vault", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED)),
            List.of("laptop-alice", "laptop-carol"));

    private SessionFixtures() {
    }

    /** A clock the test moves by hand. */
    static final class MutableClock extends Clock {
        private volatile Instant now = T;

        Instant now() {
            return now;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** No risk scorers: every request sits at the prior, so outcomes come from policy and gates. */
    static PolicyEngine engine(PolicySet policies) {
        return PolicyEngine.builder()
                .policySet(policies).directory(DIRECTORY).keyRing(Fixtures.KEYRING)
                .gate(new HoneytokenGate()).gate(new DenyListGate())
                .scorers(List.of())
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05))
                .build();
    }

    static PolicyEngine engine() {
        return engine(PolicyEngineTest.POLICIES);
    }

    static SecretKey auditKey() {
        try {
            return KeyGenerator.getInstance("HmacSHA256").generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static AuditLog auditLog(InMemoryAuditSink sink) {
        return new AuditLog(auditKey(), sink);
    }

    /** What the client does on every use: sign this exact request with its session key. */
    static SignatureProof prove(KeyPair sessionKey, String sessionId, AccessRequest r, Instant at) {
        return new SignatureProof(sessionId, at, Ed25519.sign(sessionKey.getPrivate(),
                SignedMessages.sessionUse(sessionId, r.requestId(), r.subject().id(), r.device().id(),
                        r.resource().id(), r.action().name(), at)));
    }

    /**
     * What the endpoint agent does when its device opens a session: sign the session key for this login.
     * Null when the request carries no signed posture (no agent on that device).
     */
    static SignatureProof bind(AccessRequest r, KeyPair sessionKey, Instant at) {
        if (r.evidence().postureProof().isEmpty()) {
            return null;
        }
        return new SignatureProof(Fixtures.DEVICE_KEY_ID, at, Ed25519.sign(Fixtures.DEVICE_AGENT.getPrivate(),
                SignedMessages.sessionBinding(r.device().id(), r.requestId(), Digests.thumbprint(sessionKey.getPublic()),
                        at)));
    }

    static long count(InMemoryAuditSink sink, String type) {
        return sink.snapshot().stream().map(AuditRecord::type).filter(type::equals).count();
    }
}
