package dev.dwarpal.soc;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Search over the events in the trail. The query language is part D's; callers such as the SOC API pass
 * the analyst's query through unchanged. A bad or too expensive query is an answer with a problem, never an
 * exception that a careless caller might turn into "no results".
 */
public interface EventSearch {

    int MAX_LIMIT = 1_000;
    int MAX_QUERY = 2_000;

    /**
     * @param query the analyst's query, at most {@link #MAX_QUERY} characters
     * @param from  inclusive
     * @param to    exclusive, after {@code from}
     * @param limit 1 to {@link #MAX_LIMIT}
     */
    Result search(String query, Instant from, Instant to, int limit);

    /**
     * @param events    matching events, newest first, at most the limit asked for
     * @param matched   how many matched in total (at least {@code events.size()})
     * @param truncated whether more matched than were returned, or the search stopped at its cost limit
     * @param problem   why the query was refused or stopped (parse error, cost limit), if it was
     */
    record Result(List<ChainedEvent> events, long matched, boolean truncated, Optional<String> problem) {
        public Result {
            events = List.copyOf(events);
            if (events.size() > MAX_LIMIT) {
                throw new IllegalArgumentException("at most " + MAX_LIMIT + " events per result");
            }
            if (matched < events.size()) {
                throw new IllegalArgumentException("matched cannot be less than the events returned");
            }
            Objects.requireNonNull(problem, "problem");
        }

        public static Result refused(String why) {
            return new Result(List.of(), 0, false, Optional.of(why));
        }
    }

    /** Checks the arguments every implementation must refuse. */
    static void check(String query, Instant from, Instant to, int limit) {
        Objects.requireNonNull(query, "query");
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
        if (query.length() > MAX_QUERY) {
            throw new IllegalArgumentException("query longer than " + MAX_QUERY + " characters");
        }
        if (!to.isAfter(from)) {
            throw new IllegalArgumentException("'to' must be after 'from'");
        }
        if (limit < 1 || limit > MAX_LIMIT) {
            throw new IllegalArgumentException("limit must be 1 to " + MAX_LIMIT);
        }
    }
}
