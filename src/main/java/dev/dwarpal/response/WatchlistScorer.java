package dev.dwarpal.response;

import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;

import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * Risk from the SOC's watch list: the decayed watch weights the {@link SignalFeed} holds on the
 * request's person, device and source address, added up (each is already a log-likelihood ratio) and
 * capped at {@link #MAX_LOG_LR} (x1000), like every attack factor.
 *
 * <p>Weights decay with time, so the time matters: it is the earlier of the request's own time and
 * this scorer's clock. A request dated in the future cannot make a watch look faded (red-team finding
 * B-R3); a request dated in the past only sees more risk.
 *
 * <p>Watches only add risk, so the factor is never negative and the scorer is silent when nothing is
 * watched. Evidence names which entities are watched and by how much, never the analysts' reasons.
 */
public final class WatchlistScorer implements RiskScorer {

    public static final String NAME = "soc-watchlist";
    public static final double MAX_LOG_LR = SignalFeed.MAX_WATCH_LOG_LR;

    private final SignalFeed feed;
    private final Clock clock;

    public WatchlistScorer(SignalFeed feed, Clock clock) {
        this.feed = Objects.requireNonNull(feed, "feed");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Optional<RiskFactor> score(AccessRequest request, SignalSnapshot signals) {
        Instant now = clock.instant();
        Instant at = request.timestamp().isBefore(now) ? request.timestamp() : now;
        double subject = feed.watchLogLr(SignalFeed.Kind.SUBJECT, request.subject().id(), at);
        double device = feed.watchLogLr(SignalFeed.Kind.DEVICE, request.device().id(), at);
        double ip = feed.watchLogLr(SignalFeed.Kind.IP, request.network().ip(), at);
        double total = subject + device + ip;
        if (!(total > 0)) {
            return Optional.empty();
        }
        return Optional.of(new RiskFactor(NAME, Math.min(MAX_LOG_LR, total), String.format(Locale.ROOT,
                "watched by the SOC: person %.2f, device %.2f, address %.2f (log-likelihood ratios, decayed)",
                subject, device, ip)));
    }
}
