package dev.dwarpal.risk.scorers;

import java.util.List;

/**
 * Directional statistics for times of day (Mardia &amp; Jupp, <i>Directional Statistics</i>, 2000).
 *
 * <p>Time of day is circular: 23:30 and 00:30 are an hour apart, but their arithmetic mean is noon.
 * Minutes are mapped to angles on a 24-hour clock face, and densities use the von Mises
 * distribution, the circular counterpart of the normal distribution.
 */
public final class CircularStats {

    public static final double MINUTES_PER_DAY = 1440.0;

    private CircularStats() {
    }

    public static double toAngle(int minuteOfDay) {
        return 2 * Math.PI * minuteOfDay / MINUTES_PER_DAY;
    }

    /** Modified Bessel function of the first kind, order 0, by its power series; accurate for 0 <= x <= 50. */
    public static double besselI0(double x) {
        double term = 1.0;
        double sum = 1.0;
        double q = x * x / 4;
        for (int k = 1; k < 500; k++) {
            term *= q / ((double) k * k);
            sum += term;
            if (term < 1e-17 * sum) {
                break;
            }
        }
        return sum;
    }

    /**
     * Circular kernel density estimate, relative to a uniform day:
     * <pre>
     *   f(theta) = (1/n) sum_i vM(theta; theta_i, kappa)          each past login votes for nearby times
     *   returns ln( f(theta) / (1/2pi) ) = ln( (1/n) sum_i exp(kappa cos(theta - theta_i)) ) - ln I0(kappa)
     * </pre>
     * Positive: this time is more typical than a random time. It handles users with several habitual
     * times (morning and afternoon logins), which a single fitted bell curve cannot. Computed with
     * the log-sum-exp trick for numerical stability. Bounded by +/- (kappa + ln I0(kappa)).
     */
    public static double logDensityRatio(double theta, List<Integer> minutes, double kappa) {
        if (minutes.isEmpty()) {
            throw new IllegalArgumentException("no samples");
        }
        double max = Double.NEGATIVE_INFINITY;
        double[] e = new double[minutes.size()];
        for (int i = 0; i < e.length; i++) {
            e[i] = kappa * Math.cos(theta - toAngle(minutes.get(i)));
            max = Math.max(max, e[i]);
        }
        double sum = 0;
        for (double v : e) {
            sum += Math.exp(v - max);
        }
        return max + Math.log(sum / e.length) - Math.log(besselI0(kappa));
    }

    /**
     * The time of day (minute) where the density is highest, on a 15-minute grid. Used only for the
     * explanation text, so it works on a 96-slot histogram with a precomputed kernel table instead of
     * re-evaluating the exact density 96 times (measured: 0.8 ms down to microseconds).
     */
    public static int busiestMinute(List<Integer> minutes, double kappa) {
        int slots = 96;
        long[] counts = new long[slots];
        for (int m : minutes) {
            counts[Math.floorMod(Math.round(m / 15.0f), slots)]++;
        }
        double[] kernel = new double[slots];
        for (int d = 0; d < slots; d++) {
            kernel[d] = Math.exp(kappa * Math.cos(2 * Math.PI * d / slots));
        }
        int best = 0;
        double bestValue = Double.NEGATIVE_INFINITY;
        for (int g = 0; g < slots; g++) {
            double v = 0;
            for (int b = 0; b < slots; b++) {
                v += counts[b] * kernel[Math.floorMod(g - b, slots)];
            }
            if (v > bestValue) {
                bestValue = v;
                best = g;
            }
        }
        return best * 15;
    }
}
