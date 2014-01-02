package test;

import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Path;
import java.nio.file.Paths;

import misc.Coder;

import org.junit.Test;

/*
 * Copyright (c) 2012-2013 Fabian Foerg
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

/**
 * Tests file locking support.
 * 
 * @author Fabian Foerg
 */
public final class LockTest {
    @Test
    public void lockFile() {
        Path test1 = Paths.get("files", "test1");
        FileLock writeLock = null;
        FileLock readLock1 = null;
        FileLock readLock2 = null;

        try (FileOutputStream out = new FileOutputStream(test1.toFile(), false);
                FileInputStream in = new FileInputStream(test1.toFile());) {
            // Try to acquire a write lock (exclusive).
            writeLock = out.getChannel().tryLock(0, Long.MAX_VALUE, false);

            if (writeLock != null) {
                boolean caughtException = false;
                out.write("asdf".getBytes(Coder.CHARSET));
                out.flush();
                // Must not receive read lock.
                try {
                    readLock1 = in.getChannel()
                            .tryLock(0, Long.MAX_VALUE, true);
                } catch (OverlappingFileLockException e) {
                    caughtException = true;
                }

                assertTrue(caughtException && (readLock1 == null));
                writeLock.release();
                out.close();

                // Write lock released. Now try to acquire a read lock (shared).
                readLock1 = in.getChannel().tryLock(0, Long.MAX_VALUE, true);
                assertTrue(readLock1 != null);

                if (readLock1.isShared()) {
                    boolean overlappingException = false;

                    // Try to acquire another read lock.
                    // This cannot be done, as an overlapping read lock already
                    // exists within the same program.
                    try {
                        readLock2 = in.getChannel().tryLock(0, Long.MAX_VALUE,
                                true);
                    } catch (OverlappingFileLockException e) {
                        overlappingException = true;
                    }

                    /*
                     * The thrown exception is expected, since
                     * http://docs.oracle
                     * .com/javase/7/docs/api/java/nio/channels/FileLock.html
                     * states: "File locks are held on behalf of the entire Java
                     * virtual machine. They are not suitable for controlling
                     * access to a file by multiple threads within the same
                     * virtual machine."
                     */
                    assertTrue(overlappingException && (readLock2 == null));
                } else {
                    System.out.println("Shared locks are not supported!");
                }
            } else {
                System.out.println(test1.toString() + " is locked.");
            }
        } catch (IOException | OverlappingFileLockException e) {
            e.printStackTrace();
        }

        // Locks are automatically released when the channel is closed.
    }
}
