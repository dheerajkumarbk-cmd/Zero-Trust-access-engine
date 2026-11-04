package dev.dwarpal.swg;

import dev.dwarpal.domain.Validate;

import java.util.Objects;
import java.util.Optional;

/**
 * Where a request goes, as the filter sees it: the canonical host and port, the web resource the engine
 * decides on, the category (if any), and a local block if the filter already knows the answer is no.
 */
public record Destination(HostName host, int port, String resourceId, Optional<String> category,
                          Optional<BlockReason> localBlock) {

    public Destination {
        Objects.requireNonNull(host, "host");
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port out of range");
        }
        Validate.id(resourceId, "resourceId");
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(localBlock, "localBlock");
    }

    /** {@code host:port} as it goes on the wire ({@code [v6]:port} for IPv6). */
    public String authority() {
        return host + ":" + port;
    }
}
