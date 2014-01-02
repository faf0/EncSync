package test;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;

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
 * Initializes the server database and deletes files on the server as well as on
 * the client.
 * 
 * @author Fabian Foerg
 */
public final class InitClientAndServer {
    /**
     * Pattern for filenames of files in the client's root directory which are
     * to be deleted.
     */
    private static final PathMatcher CLIENT_ROOT_MATCHER = FileSystems
            .getDefault().getPathMatcher(
                    "glob:{file*,test*,.log.txt,.log.error.txt,.version}");

    /**
     * Starts testing.
     * 
     * @param args
     *            the path to the server configuration file.
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            throw new IllegalArgumentException(
                    "Path to configuration file must be present!");
        }
        /*
         * Initialize database.
         */
        DatabaseInit.main(args);

        /*
         * Delete files and folders.
         */
        try {
            Path joe1sync = Paths.get("files", "clients", "joe1", ".sync");
            Path joe2sync = Paths.get("files", "clients", "joe2", ".sync");
            Path sharer1sync = Paths
                    .get("files", "clients", "sharer1", ".sync");
            Path serverJoe1 = Paths.get("files", "server", "joe1");

            // file deletion
            Files.walkFileTree(Paths.get("files", "clients", "joe1"),
                    new DeleteVisitor(CLIENT_ROOT_MATCHER));
            if (Files.isDirectory(joe1sync)) {
                Files.walkFileTree(joe1sync, new DeleteVisitor(null));
            }
            if (Files.isDirectory(serverJoe1)) {
                Files.walkFileTree(serverJoe1, new DeleteVisitor(null));
            }

            Files.walkFileTree(Paths.get("files", "clients", "joe2"),
                    new DeleteVisitor(CLIENT_ROOT_MATCHER));
            if (Files.isDirectory(joe2sync)) {
                Files.walkFileTree(joe2sync, new DeleteVisitor(null));
            }

            Files.walkFileTree(Paths.get("files", "clients", "sharer1"),
                    new DeleteVisitor(CLIENT_ROOT_MATCHER));
            if (Files.isDirectory(sharer1sync)) {
                Files.walkFileTree(sharer1sync, new DeleteVisitor(null));
            }

            // folder deletion
            Files.deleteIfExists(Paths.get("files", "clients", "joe1", "sub1"));
            Files.deleteIfExists(Paths.get("files", "clients", "joe1", "sub2"));
            Files.deleteIfExists(Paths.get("files", "clients", "joe2", "sub1"));
            Files.deleteIfExists(Paths.get("files", "clients", "joe2", "sub1"));
            Files.deleteIfExists(Paths.get("files", "server", ".log.txt"));
            Files.deleteIfExists(Paths.get("files", "server", ".log.error.txt"));
            Files.deleteIfExists(Paths
                    .get("files", "server", "joe1", "private"));
            Files.deleteIfExists(Paths
                    .get("files", "server", "joe1", "folder1"));
            Files.deleteIfExists(Paths
                    .get("files", "server", "joe1", "folder2"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Deletes every found file, but not every found directory.
     * 
     * @author Fabian Foerg
     */
    private static class DeleteVisitor extends SimpleFileVisitor<Path> {
        private final PathMatcher matcher;

        public DeleteVisitor(PathMatcher matcher) {
            this.matcher = matcher;
        }

        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            System.out.format("visit file: %s%n", file.toString());

            if ((matcher == null) || matcher.matches(file.getFileName())) {
                try {
                    System.out.println("...DELETED");
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
            System.out.format("Directory: %s%n", dir);
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
            System.out.format("Directory: %s%n", dir);
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFileFailed(Path file, IOException exc) {
            System.err.println(exc);
            return FileVisitResult.CONTINUE;
        }
    }
}
