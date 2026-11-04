package dev.dwarpal.agent;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.devidp.SoftwareAuthenticator;
import dev.dwarpal.devidp.UserFile;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.gateway.RouteTable;
import dev.dwarpal.wire.JsonException;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * The client agent's command line (development use).
 *
 * <pre>
 *   enrol      --user ID --rp-id RP --authenticator FILE         new software authenticator; prints the user-file line
 *   device-key --device ID --key-id ID --out FILE                new endpoint-agent key; prints its public key
 *   request    --gateway URL --idp URL --routes FILE --user ID --device ID --authenticator FILE
 *              [--device-key FILE] [--body FILE] METHOD PATH    one request through the gateway
 * </pre>
 * The password is read from the console without echo (or, without a console, from the first line of
 * standard input). Key files hold private keys: they are created new, owner-only where the file system
 * allows it, and must never be committed (the pre-commit hook refuses {@code .key} files).
 */
public final class AgentMain {

    private static final SecureRandom RANDOM = new SecureRandom();

    private AgentMain() {
    }

    public static void main(String[] args) {
        Reader stdin = new InputStreamReader(System.in, StandardCharsets.UTF_8);
        System.exit(run(args, new BufferedReader(stdin), System.out, System.err, Clock.systemUTC()));
    }

    static int run(String[] args, BufferedReader in, PrintStream out, PrintStream err, Clock clock) {
        if (args.length == 0) {
            err.println("usage: enrol | device-key | request (see the class documentation)");
            return 2;
        }
        Map<String, String> opts = new HashMap<>();
        List<String> positional = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].startsWith("--") && i + 1 < args.length) {
                opts.put(args[i].substring(2), args[++i]);
            } else {
                positional.add(args[i]);
            }
        }
        try {
            return switch (args[0]) {
                case "enrol" -> enrol(opts, in, out);
                case "device-key" -> deviceKey(opts, out);
                case "request" -> request(opts, positional, in, out, clock);
                default -> {
                    err.println("unknown command");
                    yield 2;
                }
            };
        } catch (IllegalArgumentException | IOException | GeneralSecurityException e) {
            err.println("error: " + e.getMessage());
            return 1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            err.println("interrupted");
            return 1;
        }
    }

    private static int enrol(Map<String, String> o, BufferedReader in, PrintStream out) throws IOException {
        String user = need(o, "user");
        Path file = Path.of(need(o, "authenticator"));
        char[] pw = readPassword(in);
        KeyPair kp = Ed25519.generateKeyPair();
        byte[] id = new byte[16];
        RANDOM.nextBytes(id);
        SoftwareAuthenticator a = new SoftwareAuthenticator(need(o, "rp-id"), "cred-" + HexFormat.of().formatHex(id),
                kp, 0);
        Properties p = new Properties();
        p.setProperty("type", "authenticator");
        p.setProperty("rpId", a.rpId());
        p.setProperty("id", a.credentialId());
        p.setProperty("privateKey", Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
        p.setProperty("publicKey", WireFormat.publicKey(kp.getPublic()));
        writeNew(file, p);
        out.println(UserFile.line(user, pw, UserFile.DEFAULT_ITERATIONS, a.credentialId(), a.publicKey()));
        return 0;
    }

    private static int deviceKey(Map<String, String> o, PrintStream out) throws IOException {
        KeyPair kp = Ed25519.generateKeyPair();
        Properties p = new Properties();
        p.setProperty("type", "device");
        p.setProperty("device", need(o, "device"));
        p.setProperty("id", need(o, "key-id"));
        p.setProperty("privateKey", Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
        p.setProperty("publicKey", WireFormat.publicKey(kp.getPublic()));
        writeNew(Path.of(need(o, "out")), p);
        out.println(WireFormat.publicKey(kp.getPublic()));
        return 0;
    }

    private static int request(Map<String, String> o, List<String> positional, BufferedReader in,
                               PrintStream out, Clock clock)
            throws IOException, GeneralSecurityException, InterruptedException {
        if (positional.size() != 2) {
            throw new IllegalArgumentException("request needs METHOD and PATH");
        }
        RouteTable routes = RouteTable.parse(Files.readString(Path.of(need(o, "routes")), StandardCharsets.UTF_8));
        Properties auth = load(Path.of(need(o, "authenticator")), "authenticator");
        // The counter starts at the current time in seconds, so it keeps rising across runs without a state file
        // (at most one login per second per authenticator; a counter that does not rise is refused as a clone).
        SoftwareAuthenticator authenticator = new SoftwareAuthenticator(auth.getProperty("rpId"), auth.getProperty("id"),
                keyPair(auth), clock.instant().getEpochSecond());
        DevicePosture measured = new DevicePosture(true, true, true, AssuranceLevel.SELF_REPORTED);
        DeviceAgent device;
        if (o.containsKey("device-key")) {
            Properties d = load(Path.of(o.get("device-key")), "device");
            if (!need(o, "device").equals(d.getProperty("device"))) {
                throw new IllegalArgumentException("the device key belongs to another device");
            }
            device = DeviceAgent.managed(d.getProperty("device"), d.getProperty("id"), keyPair(d), measured);
        } else {
            device = DeviceAgent.unmanaged(need(o, "device"), measured);
        }
        char[] pw = readPassword(in);
        HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
                .proxy(HttpClient.Builder.NO_PROXY).connectTimeout(Duration.ofSeconds(5)).build();
        ClientAgent agent = ClientAgent.builder().gateway(URI.create(need(o, "gateway"))).routes(routes)
                .identityProvider(new HttpIdentityProvider(URI.create(need(o, "idp")), http, Duration.ofSeconds(10)))
                .subject(need(o, "user")).password(() -> pw.clone()).authenticator(authenticator).device(device)
                .clock(clock).http(http).build();
        try {
            byte[] body = o.containsKey("body") ? Files.readAllBytes(Path.of(o.get("body"))) : new byte[0];
            ClientAgent.Response r = agent.send(positional.get(0), positional.get(1), body);
            out.println(r.status() + (r.readOnly() ? " (read-only)" : ""));
            out.println(r.text());
            return r.status() / 100 == 2 ? 0 : 1;
        } finally {
            Arrays.fill(pw, (char) 0);
        }
    }

    private static String need(Map<String, String> o, String name) {
        String v = o.get(name);
        if (v == null) {
            throw new IllegalArgumentException("missing --" + name);
        }
        return v;
    }

    private static char[] readPassword(BufferedReader in) throws IOException {
        Console console = System.console();
        if (console != null) {
            char[] pw = console.readPassword("password: ");
            if (pw != null) {
                return pw;
            }
        }
        String line = in.readLine();
        if (line == null || line.isEmpty()) {
            throw new IllegalArgumentException("no password given");
        }
        return line.toCharArray();
    }

    private static KeyPair keyPair(Properties p) throws GeneralSecurityException {
        KeyFactory f = KeyFactory.getInstance("Ed25519");
        String pub = p.getProperty("publicKey");
        String priv = p.getProperty("privateKey");
        if (pub == null || priv == null) {
            throw new IllegalArgumentException("key file is invalid");
        }
        try {
            return new KeyPair(WireFormat.readPublicKey(pub),
                    f.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(priv))));
        } catch (IllegalArgumentException | JsonException e) {
            throw new IllegalArgumentException("key file is invalid");
        }
    }

    private static Properties load(Path file, String type) throws IOException {
        if (Files.size(file) > 16 * 1024) {
            throw new IllegalArgumentException("key file too large");
        }
        Properties p = new Properties();
        p.load(new StringReader(Files.readString(file, StandardCharsets.UTF_8)));
        if (!type.equals(p.getProperty("type"))) {
            throw new IllegalArgumentException("not a " + type + " key file");
        }
        return p;
    }

    private static void writeNew(Path file, Properties p) throws IOException {
        StringWriter w = new StringWriter();
        p.store(w, "Dwarpal development key: private, never commit");
        Files.writeString(file, w.toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE);
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        }
    }
}
