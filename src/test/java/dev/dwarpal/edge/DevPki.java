package dev.dwarpal.edge;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * A private development certificate authority, made with the JDK's own {@code keytool} (free, no
 * OpenSSL, no Docker). Used by tests and by local runs; certificates live in a temporary or
 * {@code target/} directory and are never committed.
 *
 * <p>Every certificate has extended key usage serverAuth and clientAuth and the subject alternative
 * names {@code localhost} and {@code 127.0.0.1}, so one certificate serves a component in both roles.
 * The store password is random per PKI and passed to {@code keytool} through an environment variable,
 * never on the command line.
 */
public final class DevPki {

    /** One component certificate. {@code startDaysAgo} and {@code validityDays} allow expired certificates in tests. */
    public record Leaf(String name, int startDaysAgo, int validityDays) {
        public static Leaf valid(String name) {
            return new Leaf(name, 0, 30);
        }

        public static Leaf expired(String name) {
            return new Leaf(name, 10, 1);
        }
    }

    private static final String PASS_ENV = "DWARPAL_DEV_PKI_PASS";

    private final Path dir;
    private final char[] password;
    private final Map<String, Path> keyStores = new LinkedHashMap<>();

    private DevPki(Path dir, char[] password) {
        this.dir = dir;
        this.password = password;
    }

    /** A CA named {@code caName} in {@code dir}, and one key store per leaf. */
    public static DevPki create(Path dir, String caName, List<Leaf> leaves) throws IOException, InterruptedException {
        // On Windows and macOS Gateway.p12 and gateway.p12 are one file: refuse names that differ only in case.
        java.util.Set<String> folded = new java.util.HashSet<>();
        for (Leaf leaf : leaves) {
            if (!folded.add(leaf.name().toLowerCase(java.util.Locale.ROOT)) || leaf.name().equalsIgnoreCase("ca")
                    || leaf.name().equalsIgnoreCase("trust")) {
                throw new IllegalArgumentException("leaf names must differ in more than case, and not be ca or trust");
            }
        }
        Files.createDirectories(dir);
        byte[] random = new byte[18];
        new SecureRandom().nextBytes(random);
        DevPki pki = new DevPki(dir, Base64.getUrlEncoder().withoutPadding().encodeToString(random).toCharArray());
        pki.keytool("-genkeypair", "-alias", "ca", "-keyalg", "EC", "-groupname", "secp384r1", "-dname", "CN=" + caName,
                "-ext", "bc:c", "-validity", "30", "-keystore", pki.path("ca.p12"), "-storetype", "PKCS12");
        pki.keytool("-exportcert", "-alias", "ca", "-keystore", pki.path("ca.p12"), "-rfc", "-file", pki.path("ca.pem"));
        pki.keytool("-importcert", "-noprompt", "-alias", "ca", "-file", pki.path("ca.pem"), "-keystore",
                pki.path("trust.p12"), "-storetype", "PKCS12");
        for (Leaf leaf : leaves) {
            String ks = pki.path(leaf.name() + ".p12");
            pki.keytool("-genkeypair", "-alias", leaf.name(), "-keyalg", "EC", "-groupname", "secp384r1",
                    "-dname", "CN=" + leaf.name(), "-validity", "30", "-keystore", ks, "-storetype", "PKCS12");
            pki.keytool("-certreq", "-alias", leaf.name(), "-keystore", ks, "-file", pki.path(leaf.name() + ".csr"));
            List<String> gen = new ArrayList<>(List.of("-gencert", "-alias", "ca", "-keystore", pki.path("ca.p12"),
                    "-infile", pki.path(leaf.name() + ".csr"), "-outfile", pki.path(leaf.name() + ".pem"), "-rfc",
                    "-validity", Integer.toString(leaf.validityDays()), "-ext", "ku:c=digitalSignature",
                    "-ext", "eku=serverAuth,clientAuth", "-ext", "san=dns:localhost,ip:127.0.0.1"));
            if (leaf.startDaysAgo() > 0) {
                gen.add("-startdate");
                gen.add("-" + leaf.startDaysAgo() + "d");
            }
            pki.keytool(gen.toArray(String[]::new));
            pki.keytool("-importcert", "-noprompt", "-alias", "ca", "-file", pki.path("ca.pem"), "-keystore", ks);
            pki.keytool("-importcert", "-alias", leaf.name(), "-file", pki.path(leaf.name() + ".pem"), "-keystore", ks);
            pki.keyStores.put(leaf.name(), dir.resolve(leaf.name() + ".p12"));
        }
        return pki;
    }

    public Path keyStore(String leaf) {
        Path p = keyStores.get(leaf);
        if (p == null) {
            throw new IllegalArgumentException("no leaf " + leaf);
        }
        return p;
    }

    public Path trustStore() {
        return dir.resolve("trust.p12");
    }

    /** The same password protects every store of this PKI. */
    public char[] password() {
        return password.clone();
    }

    private String path(String file) {
        return dir.resolve(file).toString();
    }

    private void keytool(String... args) throws IOException, InterruptedException {
        Path keytool = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT).contains("win") ? "keytool.exe" : "keytool");
        List<String> cmd = new ArrayList<>();
        cmd.add(keytool.toString());
        cmd.addAll(List.of(args));
        cmd.add("-storepass:env");
        cmd.add(PASS_ENV);
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(dir.resolve("keytool.log").toFile()));
        pb.environment().put(PASS_ENV, new String(password));
        Process p = pb.start();
        if (!p.waitFor(60, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IOException("keytool timed out");
        }
        if (p.exitValue() != 0) {
            throw new IOException("keytool failed (" + args[0] + "), see " + dir.resolve("keytool.log"));
        }
    }
}
