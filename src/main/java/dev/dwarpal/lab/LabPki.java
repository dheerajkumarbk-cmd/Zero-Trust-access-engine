package dev.dwarpal.lab;

import dev.dwarpal.edge.DevPki;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;

/**
 * The lab's certificate authority, kept between runs. The first start makes a private CA and one certificate per
 * component (with the JDK's own keytool, so nothing is installed or paid for); later starts reuse them, so a
 * browser that trusts the CA and an analyst's certificate keep working. Certificates are renewed before they
 * lapse: a lab that stops working after 30 days is a lab nobody trusts.
 *
 * <p>The key store password is random, written once to {@code pki/pki.pass}, and that file (like the key stores)
 * is readable by the owner only. This stands in for a hardware security module or a secrets manager.
 */
public final class LabPki {

    /** Certificates are valid 30 days; they are made again once they are this old. */
    public static final Duration RENEW_AFTER = Duration.ofDays(20);
    static final String PASS_FILE = "pki.pass";
    static final String STAMP_FILE = "pki.created";
    private static final SecureRandom RANDOM = new SecureRandom();

    private LabPki() {
    }

    /** The lab's PKI under {@code labDir/pki}, made or renewed if needed, with a certificate per name. */
    public static DevPki ensure(Path labDir, List<String> leaves, Instant now) throws IOException, InterruptedException {
        Path dir = labDir.resolve("pki");
        Files.createDirectories(dir);
        restrict(dir);
        Path pass = dir.resolve(PASS_FILE);
        Path stamp = dir.resolve(STAMP_FILE);
        if (Files.isRegularFile(pass) && Files.isRegularFile(stamp)) {
            try {
                Instant created = Instant.parse(Files.readString(stamp, StandardCharsets.UTF_8).trim());
                if (created.plus(RENEW_AFTER).isAfter(now)) {
                    return DevPki.open(dir, Files.readString(pass, StandardCharsets.UTF_8).trim().toCharArray(), leaves);
                }
            } catch (RuntimeException e) {
                // an unreadable stamp or a missing store means: make it again
            }
        }
        // renewal starts clean: keytool refuses to add an alias that a key store already has
        try (var old = Files.list(dir)) {
            for (Path f : (Iterable<Path>) old::iterator) {
                if (Files.isRegularFile(f)) {
                    Files.delete(f);
                }
            }
        }
        DevPki pki = DevPki.create(dir, "Dwarpal Lab CA", leaves.stream().map(DevPki.Leaf::valid).toList());
        Files.writeString(pass, new String(pki.password()), StandardCharsets.UTF_8);
        Files.writeString(stamp, now.toString(), StandardCharsets.UTF_8);
        restrict(pass);
        for (String leaf : leaves) {
            restrict(pki.keyStore(leaf));
        }
        restrict(pki.trustStore());
        return pki;
    }

    /** A random secret for a purpose of the lab (session keys, cookie keys), base64url. */
    public static String randomSecret(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** Owner-only access: POSIX mode 700 or 600 where it exists, otherwise an ACL naming only the owner. */
    static void restrict(Path path) throws IOException {
        if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(
                    Files.isDirectory(path) ? "rwx------" : "rw-------"));
            return;
        }
        AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
        if (view == null) {
            return;
        }
        AclEntry owner = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(view.getOwner())
                .setPermissions(EnumSet.allOf(AclEntryPermission.class)).build();
        view.setAcl(List.of(owner));
    }
}
