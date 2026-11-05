package dev.dwarpal.socapi;

import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.soar.Analyst;

import javax.security.auth.x500.X500Principal;
import java.util.Objects;

/**
 * One analyst allowed to call the SOC API: the exact subject (RFC 2253, compared case-sensitively) of the client
 * certificate they present, and who they are.
 */
public record SocCaller(String subject, Analyst analyst) {

    public SocCaller {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(analyst, "analyst");
        if (!new X500Principal(subject).getName(X500Principal.RFC2253).equals(subject)) {
            throw new IllegalArgumentException("subject must be in RFC 2253 form");
        }
    }

    /** An analyst with a development CA certificate {@code CN=<name>}. */
    public static SocCaller component(String certificateName, Analyst analyst) {
        return new SocCaller(TlsContexts.component(certificateName).getName(X500Principal.RFC2253), analyst);
    }
}
