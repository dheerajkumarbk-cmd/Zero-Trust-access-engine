package dev.dwarpal.console;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The contract between the console server (part G, which owns login, sessions, headers and routing) and the parts
 * that add pages and calls to it: the analyst console (H), the admin and user views (I) and the scenario lab (J).
 * A module never touches cookies, CSRF or TLS: it gets an authenticated {@link Principal} and answers a request.
 * The host checks the role and, for writes, the anti-forgery token and a recent step-up, before the module runs.
 *
 * <p>Front end side of the same contract: a module's pages live under {@code console/modules/<id>/} in the jar's
 * resources, with an {@code index.js} whose default export is {@code {id, title, requires, view}}; the shell lists
 * the modules the server reports at {@code /console/api/modules} and imports only those. No module adds inline
 * script, inline style or {@code innerHTML}.
 */
public interface ConsoleModule {

    enum Role { ANALYST, LEAD, ADMIN, USER, HR }

    /** Who is calling: set by the host from the session, never from anything the browser sends in the request. */
    record Principal(String id, Set<Role> roles, boolean stepUpFresh) {
        public Principal {
            Objects.requireNonNull(id, "id");
            roles = Set.copyOf(roles);
        }

        public boolean has(Role r) {
            return roles.contains(r);
        }
    }

    /** One call. {@code body} is the request body as text (JSON), already limited in size by the host. */
    record Request(Principal who, String method, String path, Map<String, String> query, String body) {
        public Request {
            Objects.requireNonNull(who, "who");
            query = Map.copyOf(query);
        }
    }

    /** One answer. Modules answer JSON; the host adds every security header. */
    record Response(int status, String body) {
        public static Response ok(String json) {
            return new Response(200, json);
        }

        public static Response error(int status, String publicMessage) {
            return new Response(status, "{\"error\":\"" + publicMessage.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}");
        }
    }

    @FunctionalInterface
    interface Handler {
        /** {@code params} are the values of the {@code {}} segments of the pattern, in order. */
        Response handle(Request request, List<String> params) throws Exception;
    }

    /** What a module registers. Patterns are paths below {@code /console/api/<id>/}, with {@code {}} for one segment. */
    interface Routes {
        /** A read. */
        void get(String pattern, Role minimum, Handler handler);

        /**
         * A write: the host demands the anti-forgery token, and when {@code needsStepUp} the person's step-up
         * authentication must be no older than five minutes. Every write is audited by the host under the person.
         */
        void post(String pattern, Role minimum, boolean needsStepUp, Handler handler);
    }

    /** Short lower-case name; the module's routes live under {@code /console/api/<id>/}. */
    String id();

    String title();

    /** The lowest role that sees the module at all. */
    Role minimum();

    void routes(Routes routes);

    /** What a module may do besides answering a request: both go through the console, never around it. */
    interface Host {
        /** Writes a record under {@code person} into the console's audit trail; false if the trail could not take it. */
        boolean audit(String type, String person, Map<String, String> fields);

        /** Ends every session of the person and refuses their next sign-in (a leaver). */
        void closeAccount(String personId);
    }

    /** Called once, before {@link #routes}, with the console's host. Most modules need nothing from it. */
    default void attach(Host host) {
    }
}
