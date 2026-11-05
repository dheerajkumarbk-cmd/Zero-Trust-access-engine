package dev.dwarpal.analytics;

/**
 * The special functions the estimators need, written out so the project stays on the JDK alone:
 * log-gamma (Lanczos, g = 7, n = 9), the regularised incomplete beta function (Lentz's continued
 * fraction) and the regularised lower incomplete gamma function (series below a + 1, continued
 * fraction above), and their inverses by bisection. Accurate to about 1e-10, far below the
 * sampling error of any interval reported here.
 */
final class Stats {

    private static final double EPS = 1e-15;
    private static final double TINY = 1e-300;
    private static final int MAX_ITER = 10_000;
    private static final double[] LANCZOS = {
            0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313,
            -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6,
            1.5056327351493116e-7};

    private Stats() {
    }

    static double logGamma(double x) {
        if (!(x > 0) || !Double.isFinite(x)) {
            throw new IllegalArgumentException("logGamma needs a positive finite argument");
        }
        if (x < 0.5) {
            // Reflection: Gamma(x) Gamma(1 - x) = pi / sin(pi x)
            return Math.log(Math.PI / Math.sin(Math.PI * x)) - logGamma(1 - x);
        }
        double z = x - 1;
        double a = LANCZOS[0];
        double t = z + 7.5;
        for (int i = 1; i < LANCZOS.length; i++) {
            a += LANCZOS[i] / (z + i);
        }
        return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(a);
    }

    /** I_x(a, b): the Beta(a, b) cumulative distribution at x. */
    static double betaCdf(double x, double a, double b) {
        checkShape(a, b);
        if (x <= 0) {
            return 0;
        }
        if (x >= 1) {
            return 1;
        }
        double front = Math.exp(logGamma(a + b) - logGamma(a) - logGamma(b) + a * Math.log(x) + b * Math.log1p(-x));
        if (x < (a + 1) / (a + b + 2)) {
            return front * betaFraction(x, a, b) / a;
        }
        return 1 - front * betaFraction(1 - x, b, a) / b;
    }

    private static double betaFraction(double x, double a, double b) {
        double qab = a + b;
        double qap = a + 1;
        double qam = a - 1;
        double c = 1;
        double d = 1 - qab * x / qap;
        d = Math.abs(d) < TINY ? TINY : d;
        d = 1 / d;
        double h = d;
        for (int m = 1; m <= MAX_ITER; m++) {
            int m2 = 2 * m;
            double aa = m * (b - m) * x / ((qam + m2) * (a + m2));
            d = 1 + aa * d;
            d = Math.abs(d) < TINY ? TINY : d;
            c = 1 + aa / c;
            c = Math.abs(c) < TINY ? TINY : c;
            d = 1 / d;
            h *= d * c;
            aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
            d = 1 + aa * d;
            d = Math.abs(d) < TINY ? TINY : d;
            c = 1 + aa / c;
            c = Math.abs(c) < TINY ? TINY : c;
            d = 1 / d;
            double del = d * c;
            h *= del;
            if (Math.abs(del - 1) < EPS) {
                return h;
            }
        }
        return h;
    }

    /** P(a, x): the Gamma(shape a, rate 1) cumulative distribution at x. */
    static double gammaCdf(double x, double a) {
        if (!(a > 0) || !Double.isFinite(a)) {
            throw new IllegalArgumentException("gamma shape must be positive and finite");
        }
        if (x <= 0) {
            return 0;
        }
        if (x < a + 1) {
            double sum = 1 / a;
            double term = sum;
            for (int n = 1; n <= MAX_ITER; n++) {
                term *= x / (a + n);
                sum += term;
                if (Math.abs(term) < Math.abs(sum) * EPS) {
                    break;
                }
            }
            return sum * Math.exp(-x + a * Math.log(x) - logGamma(a));
        }
        double b = x + 1 - a;
        double c = 1 / TINY;
        double d = 1 / b;
        double h = d;
        for (int i = 1; i <= MAX_ITER; i++) {
            double an = -i * (i - a);
            b += 2;
            d = an * d + b;
            d = Math.abs(d) < TINY ? TINY : d;
            c = b + an / c;
            c = Math.abs(c) < TINY ? TINY : c;
            d = 1 / d;
            double del = d * c;
            h *= del;
            if (Math.abs(del - 1) < EPS) {
                break;
            }
        }
        return 1 - Math.exp(-x + a * Math.log(x) - logGamma(a)) * h;
    }

    static double betaQuantile(double q, double a, double b) {
        checkShape(a, b);
        checkQ(q);
        double lo = 0;
        double hi = 1;
        for (int i = 0; i < 200; i++) {
            double mid = (lo + hi) / 2;
            if (betaCdf(mid, a, b) < q) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        return (lo + hi) / 2;
    }

    /** Quantile of Gamma(shape a, rate 1). */
    static double gammaQuantile(double q, double a) {
        checkQ(q);
        double hi = Math.max(1, a);
        while (gammaCdf(hi, a) < q) {
            hi *= 2;
            if (hi > 1e15) {
                throw new IllegalArgumentException("gamma quantile out of range");
            }
        }
        double lo = 0;
        for (int i = 0; i < 200; i++) {
            double mid = (lo + hi) / 2;
            if (gammaCdf(mid, a) < q) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        return (lo + hi) / 2;
    }

    private static void checkShape(double a, double b) {
        if (!(a > 0) || !(b > 0) || !Double.isFinite(a) || !Double.isFinite(b)) {
            throw new IllegalArgumentException("beta shapes must be positive and finite");
        }
    }

    private static void checkQ(double q) {
        if (!(q > 0 && q < 1)) {
            throw new IllegalArgumentException("quantile level must be in (0, 1)");
        }
    }
}
