package dev.dwarpal.risk.scorers;

import dev.dwarpal.behavior.FailureView;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

/**
 * Failed-authentication bursts as a Poisson likelihood ratio.
 *
 * <p>Count k failures in a sliding window. Legitimate users fail at a low rate (typos), attackers
 * at a high one; with both counts Poisson:
 * <pre>
 *   LLR(k) = ln( Pois(k; lambda_attack) / Pois(k; lambda_legit) )
 *          = k ln(lambda_attack / lambda_legit) - (lambda_attack - lambda_legit)
 * </pre>
 * <b>Clamped at zero.</b> For small k the formula is negative ("one failure looks like a typo"), so
 * an attacker could fail once on purpose to <em>lower</em> their risk. Failures may only ever add
 * risk; their absence says nothing (an attacker with the right password fails zero times).
 *
 * <p>Two modes: {@link Mode#BRUTE_FORCE} counts failures on this account (T1110.001);
 * {@link Mode#PASSWORD_SPRAY} counts distinct accounts that failed from this source IP
 * (T1110.003). Spray rates assume a shared NAT/office IP can see several users mistype.
 */
public final class FailureRateScorer implements RiskScorer {

    public enum Mode { BRUTE_FORCE, PASSWORD_SPRAY }

    private final FailureView log;
    private final Mode mode;
    private final Duration window;
    private final double lambdaLegit;
    private final double lambdaAttack;

    public FailureRateScorer(FailureView log, Mode mode, Duration window, double lambdaLegit, double lambdaAttack) {
        this.log = log;
        this.mode = mode;
        this.window = window;
        if (window.isNegative() || window.isZero()) {
            throw new IllegalArgumentException("window must be positive");
        }
        this.lambdaLegit = Validate.positive(lambdaLegit, "lambdaLegit");
        this.lambdaAttack = Validate.positive(lambdaAttack, "lambdaAttack");
        if (lambdaAttack <= lambdaLegit) {
            throw new IllegalArgumentException("attack rate must exceed legitimate rate");
        }
    }

    /** 15-minute window; a user mistypes ~0.2 times per window, a guesser ~5 times (assumptions). */
    public static FailureRateScorer bruteForce(FailureView log) {
        return new FailureRateScorer(log, Mode.BRUTE_FORCE, Duration.ofMinutes(15), 0.2, 5);
    }

    /** 15-minute window; ~0.5 distinct failing users per IP normally (shared NAT), ~10 in a spray. */
    public static FailureRateScorer passwordSpray(FailureView log) {
        return new FailureRateScorer(log, Mode.PASSWORD_SPRAY, Duration.ofMinutes(15), 0.5, 10);
    }

    @Override
    public String name() {
        return mode == Mode.BRUTE_FORCE ? "brute-force" : "password-spray";
    }

    @Override
    public Optional<RiskFactor> score(AccessRequest request, SignalSnapshot signals) {
        Instant to = request.timestamp();
        Instant from = to.minus(window);
        long k = mode == Mode.BRUTE_FORCE
                ? log.subjectFailures(request.subject().id(), from, to)
                : log.distinctSubjectsFromIp(request.network().ip(), from, to);
        if (k == 0) {
            return Optional.empty();
        }
        double llr = Math.max(0, k * Math.log(lambdaAttack / lambdaLegit) - (lambdaAttack - lambdaLegit));
        String what = mode == Mode.BRUTE_FORCE
                ? k + " failed logins on this account"
                : k + " different accounts failed from " + request.network().ip();
        return Optional.of(new RiskFactor(name(), llr, String.format(Locale.ROOT, "%s in the last %d min",
                what, window.toMinutes())));
    }
}
