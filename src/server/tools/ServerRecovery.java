package server.tools;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.sql.SQLException;

import misc.FileHandler;

import org.json.simple.parser.ParseException;

import server.ServerConnectionHandler;
import server.database.DatabaseConnection;
import server.database.DatabaseQueries;
import configuration.ServerConfiguration;

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
 * Deletes orphan files, i.e. files that are present on the server's file system
 * and are not referenced in the server's database. Hidden directories are
 * ignored. May only be called when the server is not running! Otherwise, valid
 * files could be deleted, if the entry is added to the database. Make sure to
 * backup the server files before running this script.
 * 
 * @author Fabian Foerg
 */
public final class ServerRecovery {
    private final Path filesPath;

    /**
     * Constructor for server recovery.
     * 
     * @param filesPath
     *            the path to the client file directory on the server.
     */
    public ServerRecovery(Path filesPath) {
        if ((filesPath == null) || !Files.isDirectory(filesPath)) {
            throw new IllegalArgumentException(
                    "filesPath must be an existing directory!");
        }

        this.filesPath = filesPath.normalize();
    }

    /**
     * Starts the recovery process.
     * 
     * @return <code>true</code>, if this recovery was successfully executed.
     *         Otherwise, <code>false</code>.
     */
    public boolean execute() {
        try {
            Files.walkFileTree(filesPath, new DeleteOrphanVisitor(filesPath));
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Starts the server recovery on the given server file folder.
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
            ServerConfiguration config = ServerConfiguration.parse(configPath);
            // init the database connection
            DatabaseConnection.init(config.getDatabasePath());
            // delete orphaned files
            ServerRecovery recovery = new ServerRecovery(Paths.get(config
                    .getRootPath()));
            recovery.execute();
            DatabaseConnection.close();
        } catch (IOException | ParseException | ClassNotFoundException
                | SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Deletes every found orphaned file in sub-directories of the given
     * directory.
     * 
     * @author Fabian Foerg
     */
    private static class DeleteOrphanVisitor extends SimpleFileVisitor<Path> {
        private final Path filesPath;

        /**
         * Constructor.
         * 
         * @param filesPath
         *            the path to the client file directory on the server.
         */
        public DeleteOrphanVisitor(Path filesPath) {
            if ((filesPath == null) || !Files.isDirectory(filesPath)) {
                throw new IllegalArgumentException(
                        "filesPath must be an existing directory!");
            }

            this.filesPath = filesPath.normalize();
        }

        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            Path relativeFile = filesPath.relativize(file).normalize();
            int relativeFileNameCount = relativeFile.getNameCount();

            if ((relativeFileNameCount == 2) || (relativeFileNameCount > 3)) {
                /*
                 * file is in the sub-directory of filesPath or in a
                 * sub-directory of a sub-directory of filesPath. This may not
                 * happen, as files must be either in the private sub-directory
                 * or in a shared sub-directory. Delete it.
                 */
                try {
                    System.out.println(String.format(
                            "Deleting file %s due to invalid location",
                            file.toString()));
                    Files.delete(file);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else if (relativeFileNameCount == 3) {
                /*
                 * file is in a sub-directory of the filesPath. This is where
                 * files must be. Delete it, if it is orphaned.
                 */
                String owner = relativeFile.getName(0).toString();
                String folder = relativeFile.getName(1).toString();
                if (ServerConnectionHandler.PRIVATE_FOLDER.equals(folder)) {
                    folder = FileHandler.ROOT_PATH.toString();
                }
                Path parentDirectory = Paths.get(relativeFile.getName(0)
                        .toString(), relativeFile.getName(1).toString());
                String name = parentDirectory.relativize(relativeFile)
                        .toString();
                boolean delete = false;

                try {
                    int version = Integer.parseInt(name);

                    if ((version < 1)
                            || !DatabaseQueries.existsFileEntry(owner, folder,
                                    version)) {
                        /*
                         * The file has an invalid version number or is not
                         * present in the file table and therefore orphaned.
                         * Delete it.
                         */
                        delete = true;
                    }
                } catch (NumberFormatException e) {
                    // the file name is invalid
                    delete = true;
                }

                if (delete) {
                    System.out.println(String.format(
                            "Deleting orphaned file %s", file.toString()));
                    try {
                        Files.delete(file);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
            // else: ignore files with nameCount < 2

            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult preVisitDirectory(Path dir,
                BasicFileAttributes attrs) {
            try {
                return Files.isHidden(dir) ? FileVisitResult.SKIP_SUBTREE
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
