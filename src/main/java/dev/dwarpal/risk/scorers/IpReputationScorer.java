package dev.dwarpal.risk.scorers;

import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.pip.ThreatIntel;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Source reputation: the {@code p(attack | x)} term of Freeman et al. (NDSS 2016), which the
 * novelty model alone leaves out. Credential stuffing overwhelmingly arrives through proxies,
 * Tor and rented cloud servers, while employees log in from homes, offices and mobile networks.
 *
 * <p>Only the strongest matching category counts (one source, one piece of evidence: no double
 * counting). The hosting-provider rule applies to humans only; workloads legitimately run in
 * clouds. Unlisted addresses give no evidence: absence from a blocklist proves nothing.
 *
 * <p>Default likelihood ratios are assumptions to be calibrated: abuse-listed x50, Tor x20,
 * hosting x10.
 */
public final class IpReputationScorer implements RiskScorer {

    private final Supplier<ThreatIntel> feed;
    private final double abuseLogLr;
    private final double torLogLr;
    private final double hostingLogLr;

    public IpReputationScorer(Supplier<ThreatIntel> feed, double abuseLr, double torLr, double hostingLr) {
        this.feed = Objects.requireNonNull(feed, "feed");
        this.abuseLogLr = Math.log(atLeastOne(abuseLr, "abuseLr"));
        this.torLogLr = Math.log(atLeastOne(torLr, "torLr"));
        this.hostingLogLr = Math.log(atLeastOne(hostingLr, "hostingLr"));
    }

    public static IpReputationScorer withDefaults(Supplier<ThreatIntel> feed) {
        return new IpReputationScorer(feed, 50, 20, 10);
    }

    private static double atLeastOne(double lr, String name) {
        Validate.positive(lr, name);
        if (lr < 1) {
            throw new IllegalArgumentException(name + " must be >= 1: being listed can only add risk");
        }
        return lr;
    }

    @Override
    public String name() {
        return "ip-reputation";
    }

    @Override
    public Optional<RiskFactor> score(AccessRequest request, SignalSnapshot signals) {
        ThreatIntel intel = Objects.requireNonNull(feed.get(), "threat intel snapshot");
        String ip = request.network().ip();
        if (intel.abuseIps().contains(ip)) {
            return Optional.of(new RiskFactor(name(), abuseLogLr, ip + " is on an abuse blocklist"));
        }
        if (intel.torExitIps().contains(ip)) {
            return Optional.of(new RiskFactor(name(), torLogLr, ip + " is a Tor exit node"));
        }
        if (request.subject().type() == SubjectType.HUMAN && intel.hostingAsns().contains(request.network().asn())) {
            return Optional.of(new RiskFactor(name(), hostingLogLr,
                    request.network().asn() + " is a hosting provider; people do not log in from data centres"));
        }
        return Optional.empty();
    }
}
