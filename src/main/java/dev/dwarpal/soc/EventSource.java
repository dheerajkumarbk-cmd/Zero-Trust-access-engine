package dev.dwarpal.soc;

import java.util.List;

/**
 * A collector: raw input from one source, normalised into {@link SecurityEvent}s. Input it cannot parse or
 * refuses is counted (and, by part D's collectors, kept as a parse-failure event), never dropped silently.
 */
public interface EventSource {

    /** The dataset its events carry, for example {@code firewall}. */
    String name();

    /** Up to {@code max} normalised events, oldest first; empty when nothing is waiting. */
    List<SecurityEvent> poll(int max);

    /** Input refused so far (unparseable, over a limit, bad signature, replayed batch). */
    long refused();
}
