package dev.dwarpal.pip;

import dev.dwarpal.domain.Validate;

import java.util.Set;

/**
 * An immutable snapshot of IP reputation feeds (a Policy Information Point). Refreshed by
 * swapping in a new snapshot, never by editing one in place, so a decision always sees one
 * consistent version.
 *
 * @param abuseIps     addresses on abuse/credential-stuffing blocklists
 * @param torExitIps   Tor exit relays (the public Tor exit list)
 * @param hostingAsns  cloud and hosting providers' ASNs: people do not log in from data centres
 */
public record ThreatIntel(Set<String> abuseIps, Set<String> torExitIps, Set<String> hostingAsns) {

    /** Bound on feed size; real feeds are far smaller, a larger one is likely corrupt or hostile. */
    public static final int MAX_ENTRIES = 2_000_000;

    public ThreatIntel {
        abuseIps = checked(abuseIps, "abuseIps");
        torExitIps = checked(torExitIps, "torExitIps");
        hostingAsns = checked(hostingAsns, "hostingAsns");
    }

    public static ThreatIntel empty() {
        return new ThreatIntel(Set.of(), Set.of(), Set.of());
    }

    private static Set<String> checked(Set<String> s, String name) {
        if (s.size() > MAX_ENTRIES) {
            throw new IllegalArgumentException(name + " has more than " + MAX_ENTRIES + " entries");
        }
        Set<String> copy = Set.copyOf(s);
        copy.forEach(v -> Validate.id(v, name));
        return copy;
    }
}
