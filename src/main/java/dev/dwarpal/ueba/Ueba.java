package dev.dwarpal.ueba;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.response.VerdictGate;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertRanker;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.AssetCatalog;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EntityRisk;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.Verdict;

/**
 * Part E wired together: one evidence index, the detectors, entity risk, the technique table and the ranker.
 * <pre>
 *   AuditCursor -> engine.poll -> anomalies -> risk        (entity risk, EntityRisk)
 *                              -> ueba-anomaly alerts -> alertSink (the case book, the queue)
 *   other rules' alerts -> alerted(alert): risk + kept out of the baselines
 *   ranker.rank(alert, now) -> RankedAlert             (AlertRanker)
 * </pre>
 * Part F reads it as {@link EntityRisk} and {@link AlertRanker}; the alert pipeline sends every other rule's alert to
 * it as an {@link AlertSink}.
 */
public final class Ueba implements EntityRisk, AlertRanker, AlertSink {

    private final EvidenceIndex index;
    private final UebaRisk risk;
    private final UebaEngine engine;
    private final TechniqueMap techniques;
    private final RiskRanker ranker;

    public Ueba(UebaSettings settings, UebaRisk.Settings riskSettings, PeerGroups peers, AssetCatalog assets,
                TechniqueMap.Builder techniques, AlertSink alertSink) {
        Objects.requireNonNull(settings, "settings");
        this.index = new EvidenceIndex(settings.maxEvidenceIndex());
        this.risk = new UebaRisk(riskSettings, index);
        this.engine = new UebaEngine(settings, peers, index, risk::add, alertSink);
        this.techniques = techniques.perAlert(engine::techniques).build();
        this.ranker = new RiskRanker(risk, assets, index, this.techniques);
    }

    /** With the reference settings and part A's rules in the technique table. */
    public static Ueba reference(PeerGroups peers, AssetCatalog assets, AlertSink alertSink) {
        return new Ueba(UebaSettings.reference(), UebaRisk.Settings.reference(), peers, assets, TechniqueMap.standard(),
                alertSink);
    }

    /** An alert of any other rule: it raises its entities' risk, and its evidence is kept out of the baselines. */
    public void alerted(Alert alert) {
        engine.alerted(alert);
        risk.raise(alert);
    }

    /**
     * A verdict on an alert. A false positive admitted by the gate (signed by a SOC analyst, fresh, single use)
     * removes what the alert added to risk and, for a UEBA alert, teaches its values to the baseline.
     *
     * @return whether the verdict lowered anything
     */
    public boolean falsePositive(Verdict verdict, VerdictGate gate) {
        Objects.requireNonNull(verdict, "verdict");
        Objects.requireNonNull(gate, "gate");
        if (verdict.outcome() != Verdict.Outcome.FALSE_POSITIVE || gate.admit(verdict).isPresent()) {
            return false;
        }
        List<Anomaly> parts = engine.anomaliesOf(verdict.alertId());
        risk.removeAlert(verdict.alertId(), parts);
        engine.learnFalsePositive(verdict.alertId());
        return true;
    }

    /** Reads and judges up to {@code max} records of the chain; see {@link UebaEngine#poll}. */
    public int poll(AuditCursor cursor, int max) {
        return engine.poll(cursor, max);
    }

    public UebaEngine.Stats stats() {
        return engine.stats();
    }

    /** The anomalies behind a UEBA alert, for the analyst's view of it. */
    public List<Anomaly> anomaliesOf(String alertId) {
        return engine.anomaliesOf(alertId);
    }

    /** Every contribution of an entity now, not cut at {@link RiskView#MAX_CONTRIBUTIONS}. */
    public List<Contribution> contributions(Entity entity, Instant now) {
        return risk.contributions(entity, now);
    }

    @Override
    public RiskView view(Entity entity, Instant now) {
        return risk.view(entity, now);
    }

    @Override
    public List<RiskView> top(int n, Instant now) {
        return risk.top(n, now);
    }

    @Override
    public RankedAlert rank(Alert alert, Instant now) {
        return ranker.rank(alert, now);
    }

    /** Same as {@link #alerted}; lets part E sit behind the shared alert sink. */
    @Override
    public boolean raise(Alert alert) {
        alerted(alert);
        return true;
    }

    UebaEngine engine() {
        return engine;
    }

    UebaRisk risk() {
        return risk;
    }

    public RiskRanker ranker() {
        return ranker;
    }

    public TechniqueMap techniques() {
        return techniques;
    }

    EvidenceIndex evidence() {
        return index;
    }
}
