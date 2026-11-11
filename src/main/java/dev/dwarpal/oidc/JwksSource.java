package dev.dwarpal.oidc;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * The keys of one provider, fetched from the {@code jwks_uri} found by {@link OidcDiscovery} and
 * nowhere else.
 *
 * <ul>
 *   <li>A fetched set is fresh for 10 minutes; {@link #current()} then returns it without any request.
 *   <li>The provider is asked for keys at most once every 30 seconds, however many callers there
 *       are and whether the last attempt worked or not. Calls run one at a time, so a crowd of
 *       callers causes one request, not many.
 *   <li>A failed fetch (network, status, size, media type) or an unacceptable key set never replaces
 *       a good one (a set with no usable key at all counts as unacceptable). The old set is still used while it is under one hour old; after that
 *       {@code current()} throws {@code KEYS_UNAVAILABLE}: the source fails closed.
 * </ul>
 *
 * Every time decision uses the injected clock.
 */
public final class JwksSource {

    static final Duration FRESH_FOR = Duration.ofMinutes(10);
    static final Duration MIN_REFETCH = Duration.ofSeconds(30);
    static final Duration MAX_STALE = Duration.ofHours(1);
    private static final Set<String> TYPES = Set.of("application/json", "application/jwk-set+json");

    private final OidcDiscovery discovery;
    private final OidcHttp http;
    private final Clock clock;

    private JwkSet cached;
    private Instant fetchedAt;
    private Instant lastAttempt;

    /** A source for the provider described by {@code discovery}; https only. */
    public JwksSource(OidcDiscovery discovery, Clock clock) {
        this(discovery, new OidcHttp(), clock);
    }

    JwksSource(OidcDiscovery discovery, OidcHttp http, Clock clock) {
        this.discovery = Objects.requireNonNull(discovery, "discovery");
        this.http = Objects.requireNonNull(http, "http");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * The key set to verify with. Fetches when none is held or the held one is older than 10 minutes
     * (subject to the 30 second limit).
     *
     * @throws OidcException {@code KEYS_UNAVAILABLE} when no set under one hour old can be had
     */
    public synchronized JwkSet current() {
        Instant now = clock.instant();
        Duration age = ageOf(now);
        if (cached != null && age != null && age.compareTo(FRESH_FOR) < 0) {
            return cached;
        }
        refetch(now);
        return usable(now);
    }

    /**
     * Called when a token names a key that {@link #current()} did not have: asks the provider again,
     * but only if the last attempt was 30 or more seconds ago; otherwise returns the held set unchanged.
     *
     * @throws OidcException {@code KEYS_UNAVAILABLE} when no set under one hour old is held
     */
    public synchronized JwkSet refreshForUnknownKey() {
        Instant now = clock.instant();
        refetch(now);
        return usable(now);
    }

    /** Age of the held set, or null if there is none or the clock has gone back past its fetch time. */
    private Duration ageOf(Instant now) {
        if (cached == null || fetchedAt == null || now.isBefore(fetchedAt)) {
            return null;
        }
        return Duration.between(fetchedAt, now);
    }

    private JwkSet usable(Instant now) {
        Duration age = ageOf(now);
        if (age == null || age.compareTo(MAX_STALE) >= 0) {
            throw new OidcException(OidcException.Reason.KEYS_UNAVAILABLE);
        }
        return cached;
    }

    private void refetch(Instant now) {
        if (lastAttempt != null && !now.isBefore(lastAttempt) && now.isBefore(lastAttempt.plus(MIN_REFETCH))) {
            return;
        }
        lastAttempt = now;
        try {
            JwkSet fresh = JwkSet.parse(http.get(discovery.jwksUri(), JwkSet.MAX_BYTES, TYPES));
            if (fresh.size() == 0) {
                // a set with no usable key would lock everybody out; treat it like any other bad answer
                return;
            }
            cached = fresh;
            fetchedAt = now;
        } catch (OidcException e) {
            // the old set stays; usable() decides whether it is still young enough
        }
    }
}
