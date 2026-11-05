package dev.dwarpal.ueba;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertRanker;
import dev.dwarpal.soc.Asset;
import dev.dwarpal.soc.AssetCatalog;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EntityRisk;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.Severity;

/**
 * Places alerts in the queue (implements {@link AlertRanker}) with a points table an analyst can add up:
 * <pre>
 *   score = severity points (LOW 10, MEDIUM 25, HIGH 40, CRITICAL 55)
 *         + 0.30 x the highest entity risk among the alert's entities (0 to 30)
 *         + 3.75 x (highest asset criticality - 1)                    (0 to 15)
 *   P1 from 75, P2 from 55, P3 from 35, else P4
 * </pre>
 * {@code actionable} is computed from the evidence through the {@link EvidenceIndex}: true only if at least one
 * cited record is known and more than {@code COLLECTED}. An alert that is not actionable is still ranked and
 * shown, never hidden, but it is labelled, and it can be at most P2: forged collected events must not be able to
 * put anyone at the top of the queue on their own. Unknown assets use the catalogue's default criticality and are
 * labelled unknown, never treated as low.
 */
public final class RiskRanker implements AlertRanker {

    public static final double P1 = 75;
    public static final double P2 = 55;
    public static final double P3 = 35;

    private final EntityRisk risk;
    private final AssetCatalog assets;
    private final EvidenceIndex index;
    private final TechniqueMap techniques;

    public RiskRanker(EntityRisk risk, AssetCatalog assets, EvidenceIndex index, TechniqueMap techniques) {
        this.risk = Objects.requireNonNull(risk, "risk");
        this.assets = Objects.requireNonNull(assets, "assets");
        this.index = Objects.requireNonNull(index, "index");
        this.techniques = Objects.requireNonNull(techniques, "techniques");
    }

    static double severityPoints(Severity s) {
        return switch (s) {
            case LOW -> 10;
            case MEDIUM -> 25;
            case HIGH -> 40;
            case CRITICAL -> 55;
        };
    }

    @Override
    public RankedAlert rank(Alert alert, Instant now) {
        Objects.requireNonNull(alert, "alert");
        Objects.requireNonNull(now, "now");
        List<String> reasons = new ArrayList<>();
        double sev = severityPoints(alert.severity());
        reasons.add(String.format(Locale.ROOT, "severity %s: %.0f points", alert.severity(), sev));

        EntityRisk.RiskView riskiest = null;
        Asset critical = null;
        boolean unknownAsset = false;
        for (Entity e : alert.entities()) {
            EntityRisk.RiskView v = risk.view(e, now);
            if (riskiest == null || v.score() > riskiest.score()) {
                riskiest = v;
            }
            Asset a = assets.asset(e);
            unknownAsset |= !a.known();
            if (critical == null || a.criticality() > critical.criticality()) {
                critical = a;
            }
        }
        // Entities are 1 to 16 (Alert's contract), so both are set.
        Objects.requireNonNull(riskiest, "riskiest");
        Objects.requireNonNull(critical, "critical");
        double riskPoints = 0.30 * riskiest.score();
        reasons.add(String.format(Locale.ROOT, "risk of %s %s is %.0f (%s): %.1f points",
                riskiest.entity().kind().name().toLowerCase(Locale.ROOT), riskiest.entity().id(), riskiest.score(),
                riskiest.level(), riskPoints));
        double assetPoints = 3.75 * (critical.criticality() - 1);
        reasons.add(String.format(Locale.ROOT, "asset %s criticality %d%s: %.1f points", critical.entity().id(),
                critical.criticality(), critical.known() ? "" : " (unknown asset, catalogue default)", assetPoints));
        if (unknownAsset && critical.known()) {
            reasons.add("some entities are not in the asset catalogue");
        }

        double score = Math.max(0, Math.min(100, sev + riskPoints + assetPoints));
        Priority p = score >= P1 ? Priority.P1 : score >= P2 ? Priority.P2 : score >= P3 ? Priority.P3 : Priority.P4;

        boolean actionable = index.anyActionable(alert.evidence());
        if (!actionable) {
            long unknown = index.unknown(alert.evidence());
            reasons.add(unknown > 0
                    ? "evidence not verifiable here (" + unknown + " records unknown): not actionable"
                    : "only collected evidence: watch and investigate, no destructive action");
            if (p == Priority.P1) {
                p = Priority.P2;
                reasons.add("capped at P2 because no evidence is more than collected");
            }
        }
        reasons.add(String.format(Locale.ROOT, "score %.1f: %s", score, p));
        return new RankedAlert(alert, p, score, techniques.of(alert), actionable, reasons);
    }
}
