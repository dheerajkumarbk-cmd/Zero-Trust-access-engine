package dev.dwarpal.console;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

/**
 * Server-sent events, bounded: at most one stream per session (a new one replaces the old), at most {@code max}
 * streams in all, a small queue per stream (a client that does not keep up is cut off, it never slows the others), and
 * a keep-alive comment every 15 seconds so a dead connection is noticed. Events carry no case ids, names or text: they
 * only tell the page to ask again, and the asking is checked like any other request.
 */
final class StreamHub implements AutoCloseable {

    static final int QUEUE = 32;
    private static final String CLOSE = "\0close";

    private final class Stream implements Runnable {
        final String sessionId;
        final OutputStream out;
        final BlockingQueue<String> queue = new ArrayBlockingQueue<>(QUEUE);
        volatile boolean open = true;

        Stream(String sessionId, OutputStream out) {
            this.sessionId = sessionId;
            this.out = out;
        }

        void send(String frame) {
            if (open && !queue.offer(frame)) {
                close();
            }
        }

        void close() {
            open = false;
            queue.clear();
            while (!queue.offer(CLOSE)) {
                queue.poll();
            }
        }

        @Override
        public void run() {
            try {
                out.write("retry: 3000\n\n".getBytes(StandardCharsets.UTF_8));
                out.flush();
                while (open) {
                    String frame = queue.poll(15, TimeUnit.SECONDS);
                    if (CLOSE.equals(frame)) {
                        break;
                    }
                    out.write((frame == null ? ": keep-alive\n\n" : frame).getBytes(StandardCharsets.UTF_8));
                    out.flush();
                }
            } catch (IOException | RuntimeException e) {
                // the client went away; nothing to tell it
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                open = false;
                streams.remove(sessionId, this);
                try {
                    out.close();
                } catch (IOException | RuntimeException ignored) {
                    // already gone
                }
            }
        }
    }

    private final int max;
    private final Map<String, Stream> streams = new ConcurrentHashMap<>();

    StreamHub(int max) {
        this.max = max;
    }

    /** Takes over the response body of an open exchange; false when the server is already carrying its limit. */
    synchronized boolean open(String sessionId, OutputStream out) {
        Stream old = streams.get(sessionId);
        if (old == null && streams.size() >= max) {
            return false;
        }
        Stream s = new Stream(sessionId, out);
        streams.put(sessionId, s);
        if (old != null) {
            old.close();
        }
        Thread.ofVirtual().name("console-stream").start(s);
        return true;
    }

    /** One event to every stream that satisfies the filter (usually all of them). */
    void publish(String event, String json, Predicate<String> toSession) {
        String frame = "event: " + event + "\ndata: " + json + "\n\n";
        for (Stream s : new ArrayList<>(streams.values())) {
            if (toSession.test(s.sessionId)) {
                s.send(frame);
            }
        }
    }

    /** Ends the streams of sessions that no longer exist or have ended. */
    void closeWhere(Predicate<String> dead) {
        for (Stream s : new ArrayList<>(streams.values())) {
            if (dead.test(s.sessionId)) {
                s.close();
            }
        }
    }

    void closeSession(String sessionId) {
        Optional.ofNullable(streams.get(sessionId)).ifPresent(Stream::close);
    }

    int open() {
        return streams.size();
    }

    List<String> sessions() {
        return List.copyOf(streams.keySet());
    }

    @Override
    public void close() {
        for (Stream s : new ArrayList<>(streams.values())) {
            s.close();
        }
    }
}
