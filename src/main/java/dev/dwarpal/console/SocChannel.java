package dev.dwarpal.console;

import dev.dwarpal.soc.Verdict;

import java.time.Instant;
import java.util.Optional;

/**
 * How the console server reaches the SOC API on behalf of one analyst. Nothing outside implementations of this
 * interface knows how the analyst is identified to the SOC API: the first implementation
 * ({@link CertificateSocChannel}) presents the analyst's own certificate over mutual TLS; part 0b replaces it with a
 * signed delegation from the console's certificate, and the console server, its routes and its pages do not change.
 *
 * <p>Every call answers with the SOC API's status and JSON body, or {@link Reply#unavailable()} when the SOC API
 * cannot be reached. The console never turns a failure into an empty list.
 */
public interface SocChannel {

    /** The SOC API's answer: its HTTP status and its JSON text (already checked to be well-formed JSON). */
    record Reply(int status, String body) {
        public static Reply unavailable() {
            return new Reply(503, "{\"error\":\"unavailable\"}");
        }

        public boolean ok() {
            return status == 200;
        }
    }

    /** One search: the SOC API's own query language over a time window. */
    record Search(String query, Instant from, Instant to, int limit) {
    }

    /** The calls one analyst may make. Every method is one SOC API call. */
    interface Calls {
        Reply queue();

        Reply cases();

        Reply caseDetail(String caseId);

        Reply timeline(String caseId);

        Reply note(String caseId, String text);

        Reply assign(String caseId, String assignee);

        Reply verdict(Verdict verdict);

        Reply riskTop();

        Reply risk(String kind, String id);

        Reply search(Search search);

        /** The query must end in {@code | count by <field>}; the limit of the search is not used. */
        Reply counts(Search search);

        Reply isolations();

        Reply metrics();

        Reply report(String name);
    }

    /** The calls for this analyst, or empty when the person has no standing in the SOC API (an administrator, a user). */
    Optional<Calls> forAnalyst(String analystId);
}
