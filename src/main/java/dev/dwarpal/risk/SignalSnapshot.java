package dev.dwarpal.risk;

import java.util.Set;

/**
 * Point-in-time copy of the externally pushed signals (Policy Information Points). The engine
 * reads only this snapshot, never live services, so decisions stay fast and deterministic
 * (stress-test weakness W8).
 *
 * @param honeytokenIds  identities, devices or credentials that must never be used (W12)
 * @param deniedSubjects subjects blocked by an analyst
 * @param deniedDevices  devices blocked by an analyst
 * @param deniedIps      source addresses blocked by an analyst or threat intel
 */
public record SignalSnapshot(Set<String> honeytokenIds, Set<String> deniedSubjects,
                             Set<String> deniedDevices, Set<String> deniedIps) {

    public SignalSnapshot {
        honeytokenIds = Set.copyOf(honeytokenIds);
        deniedSubjects = Set.copyOf(deniedSubjects);
        deniedDevices = Set.copyOf(deniedDevices);
        deniedIps = Set.copyOf(deniedIps);
    }

    public static SignalSnapshot empty() {
        return new SignalSnapshot(Set.of(), Set.of(), Set.of(), Set.of());
    }
}
