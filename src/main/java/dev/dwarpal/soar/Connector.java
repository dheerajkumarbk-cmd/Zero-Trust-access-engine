package dev.dwarpal.soar;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.soc.Priority;

import java.time.Instant;
import java.util.Objects;

/**
 * An outbound action to people or systems outside Dwarpal: a ticket, a chat message, an email. Connectors are
 * configured by the deployment (where to write, which account to use); playbook files only name them, so no
 * secret ever sits in a playbook. A connector's failure never stops a response.
 */
public interface Connector {

    enum Kind { TICKET, CHAT, EMAIL }

    /** The name playbooks use, for example {@code ticket}. */
    String name();

    Kind kind();

    /** @return false if not sent (full, rate limited, unavailable); may throw, which counts as false */
    boolean send(Notification n);

    /**
     * What is sent: ids and fixed text only, never alert payloads, notes or secrets.
     *
     * @param title one sanitised line, at most {@link #MAX_TITLE} characters
     */
    record Notification(String caseId, String alertId, String rule, Priority priority, PlaybookSet.Template template,
                        String title, Instant at) {
        public static final int MAX_TITLE = 200;

        public Notification {
            Validate.id(caseId, "caseId");
            Validate.id(alertId, "alertId");
            Validate.id(rule, "rule");
            Objects.requireNonNull(priority, "priority");
            Objects.requireNonNull(template, "template");
            String t = Sanitize.text(Objects.requireNonNull(title, "title"), MAX_TITLE);
            title = t.length() > MAX_TITLE ? t.substring(0, MAX_TITLE) : t;
            Objects.requireNonNull(at, "at");
        }
    }
}
