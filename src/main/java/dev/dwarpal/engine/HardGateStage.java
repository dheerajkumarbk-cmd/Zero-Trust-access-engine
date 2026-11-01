package dev.dwarpal.engine;

import dev.dwarpal.decision.Outcome;

import java.util.List;
import java.util.Optional;

/** Stage 1: near-certain evidence denies before any scoring. A failing gate also denies. */
final class HardGateStage implements DecisionStage {

    private final List<HardGate> gates;

    HardGateStage(List<HardGate> gates) {
        this.gates = List.copyOf(gates);
    }

    @Override
    public String name() {
        return "hard-gates";
    }

    @Override
    public void apply(DecisionContext ctx) {
        for (HardGate gate : gates) {
            Optional<String> hit;
            try {
                hit = gate.check(ctx.request(), ctx.signals());
            } catch (RuntimeException e) {
                ctx.terminate(Outcome.DENY, "hard-gate:" + gate.name(),
                        "hard gate '" + gate.name() + "' failed; failing closed");
                return;
            }
            if (hit.isPresent()) {
                ctx.terminate(Outcome.DENY, "hard-gate:" + gate.name(), hit.get());
                return;
            }
        }
    }
}
