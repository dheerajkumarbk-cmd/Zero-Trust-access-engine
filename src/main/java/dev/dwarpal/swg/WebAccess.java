package dev.dwarpal.swg;

import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.SessionAuthority;

import java.time.Clock;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Decides one web destination: the local filter first, then the engine through
 * {@link SessionAuthority#decide}, and the stricter of the two wins.
 *
 * <p>Every destination with a valid host is sent to the engine, also the ones the filter already
 * blocks, so the engine's audit trail and its deny-lists see all of them; a blocklisted host is
 * decided as the malicious web resource and refused whatever the engine answers. A destination is
 * allowed only when the filter has no objection <em>and</em> the engine says GRANTED (or GRANTED_LIMITED
 * for a plain GET or HEAD: a tunnel could carry anything, so read-only access cannot be enforced in it).
 */
public final class WebAccess {

    private final WebFilter filter;
    private final SessionAuthority authority;
    private final String pepRegion;
    private final Clock clock;
    private final Map<BlockReason, AtomicLong> blocked = new EnumMap<>(BlockReason.class);
    private final AtomicLong allowed = new AtomicLong();

    public WebAccess(WebFilter filter, SessionAuthority authority, String pepRegion, Clock clock) {
        this.filter = Objects.requireNonNull(filter, "filter");
        this.authority = Objects.requireNonNull(authority, "authority");
        this.pepRegion = Validate.label(pepRegion, "pepRegion");
        this.clock = Objects.requireNonNull(clock, "clock");
        for (BlockReason r : BlockReason.values()) {
            blocked.put(r, new AtomicLong());
        }
    }

    public WebFilter filter() {
        return filter;
    }

    /**
     * @param authority the destination ({@code host[:port]})
     * @param tunnel    a {@code CONNECT} tunnel (true) or a plain HTTP request (false)
     * @param action    what the request does: READ for GET and HEAD and for tunnels, WRITE otherwise
     */
    public WebVerdict check(WebIdentity who, String authority, boolean tunnel, Action action) {
        Objects.requireNonNull(who, "who");
        Objects.requireNonNull(action, "action");
        String reference = "swg-" + UUID.randomUUID();
        Optional<Destination> classified = filter.classify(authority, tunnel);
        if (classified.isEmpty()) {
            return block(BlockReason.BAD_HOST, Optional.empty(), reference);
        }
        Destination d = classified.get();
        if (d.localBlock().filter(r -> r == BlockReason.PORT_NOT_ALLOWED).isPresent()) {
            return block(BlockReason.PORT_NOT_ALLOWED, classified, reference);
        }
        EdgeResult r = decide(new EdgeRequest(reference, clock.instant(), who.subjectId(), who.deviceId(),
                who.claimedPosture(), d.resourceId(), action, who.network(), pepRegion, who.evidence()));
        if (d.localBlock().isPresent()) {
            return block(d.localBlock().get(), classified, reference);
        }
        return switch (r.status()) {
            case GRANTED -> allow(d, reference);
            case GRANTED_LIMITED -> !tunnel && action == Action.READ ? allow(d, reference)
                    : block(BlockReason.READ_ONLY, classified, reference);
            case STEP_UP -> block(BlockReason.STEP_UP_REQUIRED, classified, reference);
            case OPENED, DENIED, REJECTED -> block(BlockReason.DENIED, classified, reference);
        };
    }

    /** A refusal that happened before any destination could be classified (bad request, unknown client). */
    public WebVerdict refuse(BlockReason reason) {
        return block(reason, Optional.empty(), "swg-" + UUID.randomUUID());
    }

    /** Counts a refusal found after the decision (internal address, upstream failure). */
    WebVerdict refuseAfter(BlockReason reason, Destination d, String reference) {
        allowed.decrementAndGet();
        return block(reason, Optional.of(d), reference);
    }

    public long blocked(BlockReason reason) {
        return blocked.get(reason).get();
    }

    public long allowed() {
        return allowed.get();
    }

    private EdgeResult decide(EdgeRequest request) {
        try {
            EdgeResult r = authority.decide(request);
            return r != null ? r : denied(request.requestId());
        } catch (RuntimeException e) {
            return denied(request.requestId());
        }
    }

    private static EdgeResult denied(String reference) {
        return new EdgeResult(EdgeResult.Status.DENIED, reference,
                EdgeResult.genericMessage(EdgeResult.Status.DENIED, reference), false, Optional.empty(),
                Optional.empty(), false);
    }

    private WebVerdict allow(Destination d, String reference) {
        allowed.incrementAndGet();
        return WebVerdict.allow(d, reference);
    }

    private WebVerdict block(BlockReason reason, Optional<Destination> d, String reference) {
        blocked.get(reason).incrementAndGet();
        return WebVerdict.block(reason, d, reference);
    }
}
