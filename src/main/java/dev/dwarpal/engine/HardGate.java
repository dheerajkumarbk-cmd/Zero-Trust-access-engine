package dev.dwarpal.engine;

import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.risk.SignalSnapshot;

import java.util.Optional;

/**
 * A check that denies outright, before any scoring, when it fires. Reserved for near-certain
 * evidence (honeytoken use, analyst block) so that risk maths can never "average away" it.
 */
public interface HardGate {

    String name();

    /** The reason for denial, or empty when the gate does not fire. */
    Optional<String> check(AccessRequest request, SignalSnapshot signals);
}
