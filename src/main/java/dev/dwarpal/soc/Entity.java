package dev.dwarpal.soc;

import dev.dwarpal.domain.Validate;

import java.util.Objects;

/**
 * Something an alert is about: a person, a device, a source address, a session or a resource. Alerts
 * name entities by id only, so cases can be grouped and playbooks can act without reading payloads.
 */
public record Entity(Kind kind, String id) {

    public enum Kind { SUBJECT, DEVICE, IP, SESSION, RESOURCE }

    public Entity {
        Objects.requireNonNull(kind, "kind");
        Validate.id(id, "entity.id");
    }

    public static Entity subject(String id) {
        return new Entity(Kind.SUBJECT, id);
    }

    public static Entity device(String id) {
        return new Entity(Kind.DEVICE, id);
    }

    public static Entity ip(String id) {
        return new Entity(Kind.IP, id);
    }
}
