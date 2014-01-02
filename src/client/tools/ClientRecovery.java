package client.tools;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;

import misc.FileHandler;

import org.json.simple.parser.ParseException;

import configuration.ClientConfiguration;

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
 * Removes possibly existing temporary files from the local and synchronization
 * directory of the client. Although temporary files are usually deleted, a
 * client crash might result in existing temporary files. A temporary file has
 * the suffix <code>FileHandler.TEMP_FILE_SUFFIX</code>. Hidden directories
 * apart from the synchronization directory are ignored. Note that a corrupted
 * synchronization directory might require manual recovery after a crash. Make
 * sure to back up your local and synchronization files before using this tool!
 * May only be called when the client daemon is not running! Otherwise, the
 * client might interfere.
 * 
 * @author Fabian Foerg
 */
public final class ClientRecovery {
    private final Path filesPath;
    private final Path syncPath;

    /**
     * Deletes temporary files found in the given local and synchronization
     * directory.
     * 
     * @param filesPath
     *            the local directory containing the client's files.
     * @param syncPath
     *            the synchronization directory of the client.
     */
    public ClientRecovery(Path filesPath, Path syncPath) {
        if ((filesPath == null) || !Files.isDirectory(filesPath)) {
            throw new IllegalArgumentException(
                    "filesPath must be an existing directory!");
        }
        if ((syncPath == null) || !Files.isDirectory(syncPath)) {
            throw new IllegalArgumentException(
                    "syncPath must be an existing directory!");
        }

        this.filesPath = filesPath;
        this.syncPath = syncPath;
    }

    /**
     * Starts the recovery process.
     * 
     * @return <code>true</code>, if this recovery was successfully executed.
     *         Otherwise, <code>false</code>.
     */
    public boolean execute() {
        try {
            if (Files.isHidden(syncPath) || !syncPath.startsWith(filesPath)) {
                Files.walkFileTree(syncPath,
                        new DeleteTempFileVisitor(syncPath));
            }
            Files.walkFileTree(filesPath, new DeleteTempFileVisitor(syncPath));
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Starts the recovery process at the given client folder.
     * 
     * @param args
     *            the path to the configuration file.
     */
    public static void main(String[] args) {
        Path configPath;

        if (args.length != 1) {
            throw new IllegalArgumentException(
                    "Path to configuration file must be present!");
        }

        configPath = Paths.get(args[0]);

        try {
            ClientConfiguration config = ClientConfiguration.parse(configPath);
            ClientRecovery recovery = new ClientRecovery(Paths.get(config
                    .getRootPath()), Paths.get(config.getSyncPath()));
            recovery.execute();
        } catch (IOException | ParseException e) {
            e.printStackTrace();
        }
    }

    /**
     * Deletes every found temporary file in sub-directories of the given
     * directories. A temporary file has the suffix
     * <code>FileHandler.TEMP_FILE_SUFFIX</code>.
     * 
     * @author Fabian Foerg
     */
    private static class DeleteTempFileVisitor extends SimpleFileVisitor<Path> {
        private final Path syncPath;

        /**
         * Constructor.
         * 
         * @param syncPath
         *            the synchronization directory of the client.
         */
        public DeleteTempFileVisitor(Path syncPath) {
            if ((syncPath == null) || !Files.isDirectory(syncPath)) {
                throw new IllegalArgumentException(
                        "syncPath must be an existing directory!");
            }

            this.syncPath = syncPath;
        }

        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            if (file.getFileName().toString()
                    .endsWith(FileHandler.TEMP_FILE_SUFFIX)) {
                try {
                    System.out.println(String.format(
                            "Deleting temporary file %s", file.toString()));
                    Files.delete(file);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult preVisitDirectory(Path dir,
                BasicFileAttributes attrs) {
            try {
                return (Files.isHidden(dir) && !dir.equals(syncPath)) ? FileVisitResult.SKIP_SUBTREE
                        : FileVisitResult.CONTINUE;
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println(String.format("Skipping sub-tree %s",
                        dir.toString()));
                return FileVisitResult.SKIP_SUBTREE;
            }
        }

        @Override
        public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFileFailed(Path file, IOException exc) {
            System.err.println(exc);
            return FileVisitResult.CONTINUE;
        }
    }
}
