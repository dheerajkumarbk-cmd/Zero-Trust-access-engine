package dev.dwarpal.ueba;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.soc.Entity;

/**
 * Every limit and threshold of the UEBA detectors, in one place, so a deployer can see and change them and a
 * report can print them. The values of {@link #reference()} are design assumptions checked on the simulated
 * organisation, not calibrated on real data.
 *
 * @param baselined          which entity kinds get a baseline (people and devices by default)
 * @param maxProfiles        at most this many baselined entities; new entities beyond it are counted, never
 *                           allowed to evict an existing baseline
 * @param maxActions         per entity, at most this many actions with a volume baseline
 * @param volumeWindow       how many active hours a volume baseline remembers (168 = a week of active hours)
 * @param volumeZ            z-score from which an hour's count is unusual
 * @param minCount           and the hour has at least this many events (a z-score on 3 events means little)
 * @param minRate            floor for the expected rate per hour, so a first-ever action is not divided by 0
 * @param attackRateFactor   assumption: activity under attack is this many times the usual rate (Poisson LR)
 * @param bytesRatio         an hour's bytes this many times the usual hour's bytes is unusual
 * @param minBytes           and at least this many bytes
 * @param noveltyFields      the event fields whose first-time values are judged (plus the action itself)
 * @param noveltyWindow      w of the rule of succession: the last w observations of a field (M1)
 * @param minHistory         at least this many observations of a field before a new value is judged
 * @param maxValues          per entity and field, at most this many remembered values (least recent dropped)
 * @param pNewAttack         assumption: P(value is new | attack) in the novelty likelihood ratio
 * @param minNovelty         a new value is reported only if its log-likelihood ratio is at least this
 * @param timeMinSamples     at least this many learned event times before the time of day is judged (M6)
 * @param timeThreshold      log-likelihood ratio from which an hour of day is unusual
 * @param kappa              von Mises concentration of the time-of-day density (M6)
 * @param maxDetectorWeight  cap on one anomaly's weight in log-odds
 * @param peerMinSize        a peer group needs this many members to be compared with
 * @param peerRareFraction   a value known to fewer than this fraction of peers is rare for the peers too
 * @param peerBonus          extra log-odds when a value is new for the person and rare for the peers
 * @param quarantine         events wait this long before they are learned, so an alert raised on them in the
 *                           meantime (by any rule) keeps them out of the baseline
 * @param maxQuarantine      at most this many events waiting; when full the oldest is dropped from learning
 * @param maxEvidenceIndex   how many audit sequence numbers the evidence index remembers (provenance lookup)
 * @param correlationWindow  anomalies of one entity within this window are summed into one alert
 * @param alertMedium        window sum (log-odds) for a MEDIUM UEBA alert
 * @param alertHigh          for HIGH
 * @param alertCritical      for CRITICAL
 * @param beaconMinIntervals connections to one destination needed before their timing is judged
 * @param beaconMaxCv        intervals whose coefficient of variation (sd / mean) is at most this are machine-regular
 * @param beaconWeight       assumption: log-odds of regular connections to a destination new for the entity
 * @param driftRatio         a volume baseline at least this many times its lowest daily level of the last 30 days
 *                           is drifting (slow poisoning)
 */
public record UebaSettings(Set<Entity.Kind> baselined, int maxProfiles, int maxActions, int volumeWindow,
                           double volumeZ, int minCount, double minRate, double attackRateFactor, double bytesRatio,
                           long minBytes, List<String> noveltyFields, int noveltyWindow, int minHistory, int maxValues,
                           double pNewAttack, double minNovelty, int timeMinSamples, double timeThreshold, double kappa,
                           double maxDetectorWeight, int peerMinSize, double peerRareFraction, double peerBonus,
                           Duration quarantine, int maxQuarantine, int maxEvidenceIndex, Duration correlationWindow,
                           double alertMedium, double alertHigh, double alertCritical, int beaconMinIntervals,
                           double beaconMaxCv, double beaconWeight, double driftRatio) {

    public static final int MAX_FIELDS = 32;

    public UebaSettings {
        baselined = Set.copyOf(baselined);
        if (baselined.isEmpty()) {
            throw new IllegalArgumentException("baseline at least one entity kind");
        }
        between(maxProfiles, 1, 10_000_000, "maxProfiles");
        between(maxActions, 1, 1024, "maxActions");
        between(volumeWindow, 2, 10_000, "volumeWindow");
        between(minCount, 1, 1_000_000, "minCount");
        between(noveltyWindow, 2, 10_000, "noveltyWindow");
        between(minHistory, 1, noveltyWindow, "minHistory");
        between(maxValues, 1, 100_000, "maxValues");
        between(timeMinSamples, 1, 10_000, "timeMinSamples");
        between(peerMinSize, 2, 1_000_000, "peerMinSize");
        between(maxQuarantine, 1, 10_000_000, "maxQuarantine");
        between(maxEvidenceIndex, 1, 50_000_000, "maxEvidenceIndex");
        positive(volumeZ, "volumeZ");
        positive(minRate, "minRate");
        positive(bytesRatio, "bytesRatio");
        positive(kappa, "kappa");
        positive(maxDetectorWeight, "maxDetectorWeight");
        positive(alertMedium, "alertMedium");
        between(beaconMinIntervals, 3, Baselines.BEACON_TIMES - 1, "beaconMinIntervals");
        positive(beaconMaxCv, "beaconMaxCv");
        positive(beaconWeight, "beaconWeight");
        if (!(driftRatio > 1) || !Double.isFinite(driftRatio)) {
            throw new IllegalArgumentException("driftRatio must be above 1");
        }
        if (attackRateFactor <= 1 || !Double.isFinite(attackRateFactor)) {
            throw new IllegalArgumentException("attackRateFactor must be above 1");
        }
        if (minBytes < 0) {
            throw new IllegalArgumentException("minBytes must not be negative");
        }
        Validate.probability(pNewAttack, "pNewAttack");
        Validate.probability(peerRareFraction, "peerRareFraction");
        Validate.finite(minNovelty, "minNovelty");
        Validate.finite(timeThreshold, "timeThreshold");
        Validate.finite(peerBonus, "peerBonus");
        if (peerBonus < 0 || minNovelty < 0 || timeThreshold < 0) {
            throw new IllegalArgumentException("peerBonus, minNovelty and timeThreshold must not be negative");
        }
        if (!(alertMedium < alertHigh && alertHigh < alertCritical) || !Double.isFinite(alertCritical)) {
            throw new IllegalArgumentException("alert thresholds must rise: medium < high < critical");
        }
        noveltyFields = List.copyOf(noveltyFields);
        if (noveltyFields.size() > MAX_FIELDS) {
            throw new IllegalArgumentException("at most " + MAX_FIELDS + " novelty fields");
        }
        noveltyFields.forEach(dev.dwarpal.soc.SecurityEvent::name);
        Objects.requireNonNull(quarantine, "quarantine");
        Objects.requireNonNull(correlationWindow, "correlationWindow");
        if (quarantine.isNegative() || correlationWindow.isNegative() || correlationWindow.isZero()
                || quarantine.compareTo(Duration.ofDays(7)) > 0 || correlationWindow.compareTo(Duration.ofDays(7)) > 0) {
            throw new IllegalArgumentException("quarantine 0 to 7 days, correlation window above 0 to 7 days");
        }
    }

    /** The reference values (assumptions, stated in docs/layer-5-2/part-e.md). */
    public static UebaSettings reference() {
        return new UebaSettings(Set.of(Entity.Kind.SUBJECT, Entity.Kind.DEVICE), 200_000, 64, 168,
                4.0, 10, 0.5, 10.0, 10.0, 50_000_000L,
                List.of("process", "parent", "dst", "dport", "share", "vendor", "country"), 200, 20, 256,
                0.5, Math.log(2), 20, Math.log(10), 8.0,
                Math.log(100), 5, 0.10, Math.log(2),
                Duration.ofHours(1), 1_000_000, 2_000_000, Duration.ofHours(2),
                Math.log(20), Math.log(1000), Math.log(100_000), 10, 0.1, Math.log(100), 3.0);
    }

    /** The same settings with another profile limit. */
    public UebaSettings withMaxProfiles(int max) {
        return new UebaSettings(baselined, max, maxActions, volumeWindow, volumeZ, minCount, minRate, attackRateFactor,
                bytesRatio, minBytes, noveltyFields, noveltyWindow, minHistory, maxValues, pNewAttack, minNovelty,
                timeMinSamples, timeThreshold, kappa, maxDetectorWeight, peerMinSize, peerRareFraction, peerBonus,
                quarantine, maxQuarantine, maxEvidenceIndex, correlationWindow, alertMedium, alertHigh, alertCritical,
                beaconMinIntervals, beaconMaxCv, beaconWeight, driftRatio);
    }

    private static void between(int v, int lo, int hi, String name) {
        if (v < lo || v > hi) {
            throw new IllegalArgumentException(name + " must be " + lo + " to " + hi);
        }
    }

    private static void positive(double v, String name) {
        if (!(v > 0) || !Double.isFinite(v)) {
            throw new IllegalArgumentException(name + " must be positive and finite");
        }
    }
}
