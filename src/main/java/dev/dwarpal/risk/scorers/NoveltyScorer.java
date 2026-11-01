package dev.dwarpal.risk.scorers;

import dev.dwarpal.behavior.BehaviorHistory;
import dev.dwarpal.behavior.Feature;
import dev.dwarpal.behavior.LoginEvent;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * "Has this user been seen with this value before?" as a likelihood ratio (model M1).
 *
 * <p>Adapted from Freeman et al. (NDSS 2016): their score compares how likely a feature value is
 * for the user with how likely it is in general, backing off along the hierarchy
 * IP &rarr; ASN &rarr; country when a value is unseen. Their attacker model is the global login
 * population; we instead model <em>novelty</em>, which needs no global data and handles new users:
 * <pre>
 *   P(new value | legit)  = (k + 1) / (w + 2)     Laplace's rule of succession
 *                                                   (k of the user's last w logins brought a new value)
 *   P(new value | attack) = configured per level   e.g. 0.90 for ASN
 * </pre>
 * Walking the levels from most specific, every unseen level adds ln(P_att(new)/P_legit(new)) and
 * the first known level adds ln(P_att(known)/P_legit(known)), then stops.
 *
 * <p>Properties worth defending in a viva:
 * <ul>
 *   <li><b>No cold-start hack.</b> A brand-new user has w=0, so P_legit(new)=1/2 and novelty is only
 *       mild evidence: the first login steps up, it is not denied.</li>
 *   <li><b>Habit-aware, and habits may change.</b> A user who changes IP daily gets little penalty
 *       for a new IP; a user always on one ISP gets a strong one for a new ASN. Only the last 200
 *       logins count, so someone who moved house a year ago is judged on how they behave now.</li>
 *   <li><b>Spoof-limited.</b> "Known value" is reassurance, which the aggregator caps, because known
 *       IPs can be replayed. Device ids count only when proven by an agent signature; unproven
 *       devices share one "unverified" value that can raise risk but never lower it.</li>
 * </ul>
 */
public final class NoveltyScorer implements RiskScorer {

    private final String name;
    private final BehaviorHistory history;
    private final List<Feature> levels;
    private final Map<Feature, Double> newGivenAttack;

    /**
     * @param levels         features from most to least specific (e.g. IP, ASN, COUNTRY)
     * @param newGivenAttack P(value is new for this user | attack), per level; an assumption to calibrate
     */
    public NoveltyScorer(String name, BehaviorHistory history, List<Feature> levels, Map<Feature, Double> newGivenAttack) {
        this.name = Validate.id(name, "scorer.name");
        this.history = history;
        this.levels = List.copyOf(levels);
        if (this.levels.isEmpty()) {
            throw new IllegalArgumentException("at least one level");
        }
        this.newGivenAttack = new EnumMap<>(Feature.class);
        for (Feature f : this.levels) {
            Double p = newGivenAttack.get(f);
            if (p == null || !(p > 0 && p < 1)) {
                throw new IllegalArgumentException("P(new | attack) for " + f + " must be in (0,1)");
            }
            this.newGivenAttack.put(f, p);
        }
    }

    /** Network novelty: IP, then ASN (the ISP), then country. */
    public static NoveltyScorer network(BehaviorHistory h) {
        return new NoveltyScorer("network-novelty", h, List.of(Feature.IP, Feature.ASN, Feature.COUNTRY),
                Map.of(Feature.IP, 0.99, Feature.ASN, 0.90, Feature.COUNTRY, 0.60));
    }

    /** Device novelty: attackers rarely hold the victim's own laptop. */
    public static NoveltyScorer device(BehaviorHistory h) {
        return new NoveltyScorer("device-novelty", h, List.of(Feature.DEVICE), Map.of(Feature.DEVICE, 0.95));
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public Optional<RiskFactor> score(AccessRequest request, SignalSnapshot signals) {
        String subject = request.subject().id();
        LoginEvent now = LoginEvent.of(request, LoginEvent.deviceProven(request));
        long n = history.logins(subject);
        double llr = 0;
        List<String> parts = new ArrayList<>();
        for (Feature level : levels) {
            String value = now.value(level);
            double pNewLegit = history.novelty(subject, level).pNew();
            double pNewAttack = newGivenAttack.get(level);
            if (history.seen(subject, level, value)) {
                llr += Math.log((1 - pNewAttack) / (1 - pNewLegit));
                parts.add("known " + level + " " + value);
                break;
            }
            llr += Math.log(pNewAttack / pNewLegit);
            parts.add(String.format(Locale.ROOT, "new %s %s (user changes %s %.0f%% of the time)",
                    level, value, level, 100 * pNewLegit));
        }
        if (levels.contains(Feature.DEVICE) && LoginEvent.UNVERIFIED_DEVICE.equals(now.deviceId())) {
            // An unproven device may raise risk (this user normally proves their device) but never lower it.
            llr = Math.max(0, llr);
        }
        return Optional.of(new RiskFactor(name, llr, String.join("; ", parts) + " [n=" + n + "]"));
    }
}
