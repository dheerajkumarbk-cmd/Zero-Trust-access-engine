package dev.dwarpal.swg;

import java.net.Inet4Address;
import java.net.InetAddress;

/**
 * Which addresses are "inside": the web gateway must never be talked into connecting to the machine
 * it runs on, the local network, a cloud metadata service (169.254.169.254) or any other address that
 * is not on the public internet, just because a public-looking name resolves to one (SSRF and DNS
 * rebinding).
 */
final class Addresses {

    private Addresses() {
    }

    static boolean internal(InetAddress a) {
        if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress() || a.isSiteLocalAddress()
                || a.isMulticastAddress()) {
            return true;
        }
        byte[] b = a.getAddress();
        if (a instanceof Inet4Address) {
            return internalV4(b[0] & 0xFF, b[1] & 0xFF, b[2] & 0xFF);
        }
        for (int i = 0; i < 10; i++) {
            if (b[i] != 0) {
                return internalV6(b);
            }
        }
        // ::/96 (includes :: and ::1) and ::ffff:0:0/96 (IPv4-mapped): never a public destination
        return true;
    }

    private static boolean internalV6(byte[] b) {
        int b0 = b[0] & 0xFF;
        if ((b0 & 0xFE) == 0xFC) {
            return true; // fc00::/7 unique local
        }
        if (b0 == 0x00 && b[1] == 0x64 && (b[2] & 0xFF) == 0xFF && b[3] == (byte) 0x9B && zero(b, 4, 12)) {
            return internalV4(b[12] & 0xFF, b[13] & 0xFF, b[14] & 0xFF); // 64:ff9b::/96 NAT64
        }
        if (b0 == 0x20 && b[1] == 0x02) {
            return internalV4(b[2] & 0xFF, b[3] & 0xFF, b[4] & 0xFF); // 2002::/16 6to4
        }
        return b0 == 0x20 && b[1] == 0x01 && b[2] == 0x0D && (b[3] & 0xFF) == 0xB8; // 2001:db8::/32 documentation
    }

    private static boolean zero(byte[] b, int from, int to) {
        for (int i = from; i < to; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean internalV4(int b0, int b1, int b2) {
        return b0 == 0 || b0 == 10 || b0 == 127 || (b0 == 100 && b1 >= 64 && b1 <= 127) || (b0 == 169 && b1 == 254)
                || (b0 == 172 && b1 >= 16 && b1 <= 31) || (b0 == 192 && b1 == 0 && b2 == 0) || (b0 == 192 && b1 == 168)
                || (b0 == 198 && (b1 == 18 || b1 == 19)) || b0 >= 224;
    }
}
