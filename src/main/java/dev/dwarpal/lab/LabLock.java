package dev.dwarpal.lab;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * One running lab per lab directory. A starting lab clears the audit anchor of the run before it, so a second lab on
 * the same directory would remove the anchor of a lab that is still running, and that lab would rightly stop its clock
 * on what looks like tampering. The lock is taken before anything in the directory is touched. The operating system
 * drops it when the process ends, so a crash leaves nothing to clean up.
 */
final class LabLock implements AutoCloseable {

    private final FileChannel channel;

    private LabLock(FileChannel channel) {
        this.channel = channel;
    }

    /** @throws IllegalStateException if a running lab holds this directory */
    static LabLock acquire(Path dir) throws IOException {
        Files.createDirectories(dir);
        Path file = dir.resolve("lab.lock");
        FileChannel channel = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        boolean held = false;
        try {
            FileLock lock = channel.tryLock();
            held = lock != null;
            if (!held) {
                throw inUse(dir);
            }
            return new LabLock(channel);
        } catch (OverlappingFileLockException e) {
            throw inUse(dir);
        } finally {
            if (!held) {
                channel.close();
            }
        }
    }

    private static IllegalStateException inUse(Path dir) {
        return new IllegalStateException("the lab directory " + dir.toAbsolutePath()
                + " is in use by a running lab: stop that lab, or start this one with another --dir");
    }

    @Override
    public void close() {
        try {
            channel.close();
        } catch (IOException e) {
            throw new UncheckedIOException("cannot release the lab directory", e);
        }
    }
}
