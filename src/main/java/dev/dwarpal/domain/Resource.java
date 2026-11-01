package dev.dwarpal.domain;

import java.util.Objects;

public record Resource(String id, ResourceKind kind, DataClassification classification, FailMode failMode) {

    public Resource {
        Validate.id(id, "resource.id");
        Objects.requireNonNull(kind, "resource.kind");
        Objects.requireNonNull(classification, "resource.classification");
        Objects.requireNonNull(failMode, "resource.failMode");
    }

    /** Secure default: unspecified fail mode means fail closed. */
    public Resource(String id, ResourceKind kind, DataClassification classification) {
        this(id, kind, classification, FailMode.FAIL_CLOSED);
    }
}
