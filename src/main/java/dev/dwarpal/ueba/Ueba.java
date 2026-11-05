package dev.dwarpal.ueba;

import java.util.List;
import java.util.Objects;

import dev.dwarpal.response.VerdictGate;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.AssetCatalog;
import dev.dwarpal.soc.Verdict;

/**
 * Part E wired together: one evidence index, the detectors, entity risk, the technique table and the ranker.
 * <pre>
 *   AuditCursor -> engine.poll -> anomalies -> risk        (entity risk, EntityRisk)
 *                              -> ueba-anomaly alerts -> alertSink (the case book, the queue)
 *   other rules' alerts -> alerted(alert): risk + kept out of the baselines
 *   ranker.rank(alert, now) -> RankedAlert             (AlertRanker)
 * </pre>
 */
public final class Ueba {

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

    public UebaEngine engine() {
        return engine;
    }

    public UebaRisk risk() {
        return risk;
    }

    public RiskRanker ranker() {
        return ranker;
    }

    public TechniqueMap techniques() {
        return techniques;
    }

    public EvidenceIndex evidence() {
        return index;
    }
}
