package dev.dwarpal.engine;

import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.risk.SignalSnapshot;

import java.util.Optional;

/** Denies subjects, devices and source addresses an analyst or threat feed has blocked. */
public final class DenyListGate implements HardGate {

    @Override
    public String name() {
        return "deny-list";
    }

    @Override
    public Optional<String> check(AccessRequest request, SignalSnapshot signals) {
        if (signals.deniedSubjects().contains(request.subject().id())) {
            return Optional.of("subject is deny-listed");
        }
        if (signals.deniedDevices().contains(request.device().id())) {
            return Optional.of("device is deny-listed");
        }
        if (signals.deniedIps().contains(request.network().ip())) {
            return Optional.of("source address is deny-listed");
        }
        return Optional.empty();
    }
}
