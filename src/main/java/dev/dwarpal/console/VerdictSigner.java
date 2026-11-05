package dev.dwarpal.console;

import dev.dwarpal.soc.Verdict;

import java.util.Optional;

/**
 * Where a verdict gets its signature. The first implementation signs on the console server with the lab's analyst
 * key after a fresh step-up, and the page says so; a WebAuthn or WebCrypto signature made in the analyst's own
 * browser or security key replaces it behind this interface (standards section 2: the console server that carries
 * requests should not be able to sign for an analyst, and in the lab it can; the difference is named in the notes).
 */
public interface VerdictSigner {

    /** A signed verdict by this analyst, or empty when the person has no signing key (leads sign none). */
    Optional<Verdict> sign(String analystId, String alertId, Verdict.Outcome outcome);

    /** The text the page shows next to a signed verdict: who held the key. */
    String notice();
}
