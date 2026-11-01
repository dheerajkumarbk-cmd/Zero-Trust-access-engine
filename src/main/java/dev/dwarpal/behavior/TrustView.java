package dev.dwarpal.behavior;

import java.time.Instant;

/** Read-only view of the reputation ledger: scorers read trust but can never award or remove it. */
public interface TrustView {

    TrustLedger.Trust trust(String entity, Instant now);
}
