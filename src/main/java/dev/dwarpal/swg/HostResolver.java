package dev.dwarpal.swg;

import java.io.IOException;
import java.net.InetAddress;
import java.util.List;

/** Turns a destination into addresses to connect to. Tests supply their own; production uses DNS. */
@FunctionalInterface
public interface HostResolver {

    List<InetAddress> resolve(HostName host) throws IOException;

    /** The system resolver; IP literals are converted without any lookup. */
    static HostResolver system() {
        return host -> host.ipLiteral() ? List.of(InetAddress.ofLiteral(host.value()))
                : List.of(InetAddress.getAllByName(host.value()));
    }
}
