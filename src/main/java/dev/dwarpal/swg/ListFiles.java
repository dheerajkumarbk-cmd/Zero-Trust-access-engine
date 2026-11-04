package dev.dwarpal.swg;

import java.io.BufferedReader;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

/**
 * Reads the local list files (blocklists, category files) the same careful way the policy loader reads
 * policy files: regular files only, symbolic links not followed, strict UTF-8, a hard size cap and a
 * cap on line length. Nothing is ever downloaded; the operator puts the files in place.
 */
final class ListFiles {

    /** Large public hosts files are a few tens of MiB; anything far larger is a mistake or an attack. */
    static final long MAX_FILE_BYTES = 128L * 1024 * 1024;
    static final int MAX_LINE_CHARS = 1024;

    /** Receives each line; lines over {@link #MAX_LINE_CHARS} are reported as rejected, never cut short. */
    interface LineSink {
        void line(String line);

        void rejected();
    }

    private ListFiles() {
    }

    static void lines(Path file, LineSink sink) throws IOException {
        BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attrs.isRegularFile()) {
            throw new IOException("not a regular file (links are not followed)");
        }
        if (attrs.size() > MAX_FILE_BYTES) {
            throw new IOException("list file larger than " + MAX_FILE_BYTES + " bytes");
        }
        try (InputStream in = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            lines(new InputStreamReader(capped(in, MAX_FILE_BYTES), strictUtf8()), sink);
        }
    }

    static void lines(Reader reader, LineSink sink) throws IOException {
        try (BufferedReader r = new BufferedReader(reader)) {
            StringBuilder line = new StringBuilder();
            boolean tooLong = false;
            while (true) {
                int c = r.read();
                if (c == -1 || c == '\n') {
                    if (tooLong) {
                        sink.rejected();
                    } else if (c != -1 || !line.isEmpty()) {
                        int end = line.length() > 0 && line.charAt(line.length() - 1) == '\r' ? line.length() - 1
                                : line.length();
                        sink.line(line.substring(0, end));
                    }
                    if (c == -1) {
                        return;
                    }
                    line.setLength(0);
                    tooLong = false;
                } else if (!tooLong) {
                    if (line.length() >= MAX_LINE_CHARS) {
                        tooLong = true;
                    } else {
                        line.append((char) c);
                    }
                }
            }
        }
    }

    /** The stream, failing if more than {@code cap} bytes come out of it. */
    static InputStream capped(InputStream in, long cap) {
        return new CappedStream(in, cap);
    }

    private static CharsetDecoder strictUtf8() {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
    }

    /** Stops reading at the cap even if the file grows while it is read. */
    private static final class CappedStream extends FilterInputStream {
        private long left;

        CappedStream(InputStream in, long cap) {
            super(in);
            left = cap;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n <= 0 ? -1 : one[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            if (left <= 0) {
                if (super.read() != -1) {
                    throw new IOException("list file grew past the size cap");
                }
                return -1;
            }
            int n = super.read(b, off, (int) Math.min(len, left));
            if (n > 0) {
                left -= n;
            }
            return n;
        }
    }
}
