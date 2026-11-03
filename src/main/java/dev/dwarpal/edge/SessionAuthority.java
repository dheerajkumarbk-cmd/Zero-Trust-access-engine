package dev.dwarpal.edge;

import dev.dwarpal.crypto.SignatureProof;

import java.security.PublicKey;
import java.util.Optional;

/**
 * The one contract every enforcement point (ZTNA gateway, web gateway, CASB) uses to ask Dwarpal.
 *
 * <p>Two implementations: {@link LocalSessionAuthority} in-process, and the HTTPS client built in
 * Layer 4 part A. Both must behave the same; enforcement points must not care which one they hold.
 *
 * <p>Contract for implementations: never throw for a bad request or an internal failure; answer
 * DENIED or REJECTED instead (fail-closed). Threat signals (deny-lists, honeytokens) are supplied on the
 * engine side; an enforcement point cannot choose them.
 */
public interface SessionAuthority {

    /**
     * Decides a login and, if allowed, opens a session bound to {@code sessionKey}.
     *
     * @param deviceBinding required when the login carries signed device posture (see
     *                      {@link ClientProofs#bindDevice})
     */
    EdgeResult open(EdgeRequest login, PublicKey sessionKey, Optional<SignatureProof> deviceBinding);

    /** Checks one request made on a session (token and proof of possession), then decides it again. */
    EdgeResult use(String token, SignatureProof proof, EdgeRequest request);

    /** A single decision outside any session (for example a web destination). Audited, never learned from. */
    EdgeResult decide(EdgeRequest request);
}
