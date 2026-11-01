package dev.dwarpal.engine;

import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.risk.SignalSnapshot;

import java.util.Optional;

/**
 * Denies any use of a honeytoken: a decoy account, device or credential that no legitimate
 * process ever touches. A hit is close to proof of compromise (MITRE Engage), which is why it
 * is a hard gate rather than a risk factor.
 */
public final class HoneytokenGate implements HardGate {

    @Override
    public String name() {
        return "honeytoken";
    }

    @Override
    public Optional<String> check(AccessRequest request, SignalSnapshot signals) {
        if (signals.honeytokenIds().contains(request.subject().id())) {
            return Optional.of("honeytoken identity used: " + request.subject().id());
        }
        if (signals.honeytokenIds().contains(request.device().id())) {
            return Optional.of("honeytoken device used: " + request.device().id());
        }
        return Optional.empty();
    }
}
