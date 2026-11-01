package dev.dwarpal.risk.scorers;

import dev.dwarpal.behavior.LoginEvent;
import dev.dwarpal.behavior.TrustLedger;
import dev.dwarpal.behavior.TrustView;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;

import java.util.Locale;
import java.util.Optional;

/**
 * Reputation of the subject or the device (model M4), from the Beta ledger.
 *
 * <p>The log-odds that the entity is behaving badly, under the Beta posterior, is
 * <pre>
 *   LLR = ln( (1 - E) / E ) = ln( (s + 1) / (r + 1) )
 * </pre>
 * which is 0 for an unknown entity (E = 0.5), negative for a clean record and positive after
 * incidents. With no evidence at all the scorer stays silent: unknown is not suspicious by
 * itself (novelty scoring handles first sight).
 */
public final class TrustScorer implements RiskScorer {

    public enum Entity { SUBJECT, DEVICE }

    private final TrustView ledger;
    private final Entity entity;

    public TrustScorer(TrustView ledger, Entity entity) {
        this.ledger = ledger;
        this.entity = entity;
    }

    @Override
    public String name() {
        return entity == Entity.SUBJECT ? "subject-trust" : "device-trust";
    }

    @Override
    public Optional<RiskFactor> score(AccessRequest request, SignalSnapshot signals) {
        if (entity == Entity.DEVICE && !LoginEvent.deviceProven(request)) {
            return Optional.empty(); // an unproven device id must not borrow the real device's reputation
        }
        String key = entity == Entity.SUBJECT
                ? TrustLedger.subjectKey(request.subject().id())
                : TrustLedger.deviceKey(request.device().id());
        TrustLedger.Trust t = ledger.trust(key, request.timestamp());
        if (!t.hasEvidence()) {
            return Optional.empty();
        }
        double llr = Math.log((t.bad() + 1) / (t.good() + 1));
        return Optional.of(new RiskFactor(name(), llr, String.format(Locale.ROOT,
                "E=%.3f from %.1f good / %.1f bad recent events (uncertainty %.3f)",
                t.expectation(), t.good(), t.bad(), t.uncertainty())));
    }
}
