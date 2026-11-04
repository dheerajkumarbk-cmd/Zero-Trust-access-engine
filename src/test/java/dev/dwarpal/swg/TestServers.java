package dev.dwarpal.swg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/** Small local servers for the proxy tests: an echo server (tunnel target) and an HTTP origin. */
final class TestServers {

    private TestServers() {
    }

    /** Accepts connections on loopback and hands each one to {@code handler} on its own thread. */
    static final class Server implements AutoCloseable {
        final ServerSocket socket;
        final List<String> requests = new CopyOnWriteArrayList<>();
        /** Connections this server has accepted: proof that the proxy did (or did not) reach it. */
        final AtomicInteger accepted = new AtomicInteger();

        Server(Consumer<Socket> handler) throws IOException {
            socket = new ServerSocket();
            socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            Thread t = new Thread(() -> {
                while (!socket.isClosed()) {
                    try {
                        Socket s = socket.accept();
                        accepted.incrementAndGet();
                        Thread.ofVirtual().start(() -> handler.accept(s));
                    } catch (IOException e) {
                        return;
                    }
                }
            });
            t.setDaemon(true);
            t.start();
        }

        int port() {
            return socket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    /** A bound listener on a free loopback port, for {@link WebGateway#start}. */
    static ServerSocket loopbackListener() throws IOException {
        ServerSocket s = new ServerSocket();
        s.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 128);
        return s;
    }

    static Server echo() throws IOException {
        return new Server(s -> {
            try (s) {
                s.getInputStream().transferTo(s.getOutputStream());
            } catch (IOException ignored) {
                // test peer went away
            }
        });
    }

    /** An HTTP origin that records each request (head and body) and answers {@code hello}. */
    static Server origin() throws IOException {
        Server[] self = new Server[1];
        self[0] = new Server(s -> {
            try (s) {
                InputStream in = s.getInputStream();
                String head = readHead(in);
                int length = 0;
                for (String line : head.split("\r\n")) {
                    if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                        length = Integer.parseInt(line.substring(15).strip());
                    }
                }
                String body = new String(in.readNBytes(length), StandardCharsets.UTF_8);
                self[0].requests.add(head + body);
                OutputStream out = s.getOutputStream();
                out.write("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".getBytes(StandardCharsets.US_ASCII));
                out.flush();
            } catch (IOException | RuntimeException ignored) {
                // test peer went away
            }
        });
        return self[0];
    }

    static String readHead(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int state = 0;
        while (state < 4) {
            int c = in.read();
            if (c < 0) {
                break;
            }
            b.write(c);
            state = (c == '\r' && (state == 0 || state == 2)) || (c == '\n' && (state == 1 || state == 3)) ? state + 1
                    : (c == '\r' ? 1 : 0);
        }
        return b.toString(StandardCharsets.ISO_8859_1);
    }

    /** Sends {@code request} to the proxy and returns everything it answers until it closes. */
    static String exchange(int proxyPort, String request) throws IOException {
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), proxyPort)) {
            s.setSoTimeout(5000);
            s.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
            s.getOutputStream().flush();
            return new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }
}
