package dev.dwarpal.ueba;

import java.util.Locale;

/** A minimal JSON writer for the reports: strings escaped per RFC 8259, numbers finite, nothing else. */
final class JsonOut {

    private final StringBuilder b = new StringBuilder(4096);
    private boolean first = true;

    JsonOut open(char c) {
        comma();
        b.append(c);
        first = true;
        return this;
    }

    JsonOut close(char c) {
        b.append(c);
        first = false;
        return this;
    }

    JsonOut name(String n) {
        comma();
        str(n);
        b.append(':');
        first = true;
        return this;
    }

    JsonOut value(String s) {
        comma();
        str(s);
        first = false;
        return this;
    }

    JsonOut value(long n) {
        comma();
        b.append(n);
        first = false;
        return this;
    }

    JsonOut value(double d) {
        comma();
        if (!Double.isFinite(d)) {
            b.append("null");
        } else {
            b.append(String.format(Locale.ROOT, "%.4f", d));
        }
        first = false;
        return this;
    }

    JsonOut value(boolean v) {
        comma();
        b.append(v);
        first = false;
        return this;
    }

    JsonOut field(String n, String s) {
        return name(n).value(s);
    }

    JsonOut field(String n, long v) {
        return name(n).value(v);
    }

    JsonOut field(String n, double v) {
        return name(n).value(v);
    }

    private void comma() {
        if (!first) {
            b.append(',');
        }
        first = false;
    }

    private void str(String s) {
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x2028 || c == 0x2029 || (c >= 0x202A && c <= 0x202E)
                            || (c >= 0x2066 && c <= 0x2069)) {
                        b.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        b.append('"');
    }

    @Override
    public String toString() {
        return b.toString();
    }
}
