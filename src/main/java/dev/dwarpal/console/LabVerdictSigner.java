package dev.dwarpal.console;

import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.soc.Verdict;

import java.util.Optional;

/** Signs with the lab's own analyst keys ({@link LabWorld#signVerdict}); only "ana" and "ben" have one. */
public final class LabVerdictSigner implements VerdictSigner {

    public static final String NOTICE = "Signed by the lab's analyst key, held by the console server as a stand-in for "
            + "your own hardware-bound key.";

    private final LabHandle lab;

    public LabVerdictSigner(LabHandle lab) {
        this.lab = lab;
    }

    @Override
    public Optional<Verdict> sign(String analystId, String alertId, Verdict.Outcome outcome) {
        try {
            return Optional.of(lab.world().signVerdict(analystId, alertId, outcome));
        } catch (IllegalArgumentException noKey) {
            return Optional.empty();
        }
    }

    @Override
    public String notice() {
        return NOTICE;
    }
}
