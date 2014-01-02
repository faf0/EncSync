package client.executors;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import client.ClientConnectionHandler;

import misc.Coder;
import misc.FileHandler;
import protocol.DataContainers;
import protocol.DataContainers.ActionData;
import protocol.DataContainers.GetSyncData;
import protocol.DataContainers.PutFolderData;
import configuration.ClientConfiguration;
import configuration.Permission;
import configuration.Permission.PermissionValue;

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
 * Executes the following tests: - Put a shared folder named folder1 on the
 * server - Put a public folder named folder2 on the server - Put a file named
 * file1.txt on the server - Put a file named file2.txt on the server - Modify
 * file1.txt in such a way that no diff is created - Rename file1.txt to
 * file3.txt - Delete file3.txt - Rename file2.txt to file1.txt - Put file2.txt
 * on the server - Modify file2.txt in such a way that a diff is created - Move
 * file1.txt in the sub-folder sub1 - Move file2.txt in the sub-folder sub1 -
 * Rename file2.txt to file3.txt - Modify file3.txt - Rename folder sub1 to sub2
 * - Delete file1.txt - Delete file3.txt - Delete sub2 - Add shared1 file1.txt -
 * Modify shared1 file1.txt - Rename shared1 file1.txt to file2.txt - Move
 * shared1 file2.txt to root directory as file1.txt - Add shared1 file1.txt -
 * Add public1 file1.txt - Add public1 fileÄ.txt - Move public1 fileÄ.txt to
 * fileÖ.txt - Modify public1 fileÖ.txt - Delete public1 fileÖ.txt
 * 
 * @author Fabian Foerg
 */
public final class TestExecutor implements ClientExecutor {
    /**
     * Time to wait between actions when <code>commit</code> is false in
     * milliseconds. With an increased waiting time, probably less test actions
     * are omitted, as there is more time to synchronize the states between
     * actions.
     */
    private static final long WAITING_TIME = 1000;
    /**
     * Time to wait between two consecutive action repetition attempts in
     * milliseconds.
     */
    private static final long REPEAT_TIME = 100;

    private final ClientConfiguration config;
    private final ClientConnectionHandler handler;
    private final boolean commit;

    /**
     * Creates a new instance with the given parameters.
     * 
     * @param handler
     *            the client connection handler.
     * @param config
     *            the client configuration file.
     * @param commit
     *            <code>true</code>, if the changes should be directly
     *            committed. Otherwise, <code>false</code>.
     */
    public TestExecutor(ClientConnectionHandler handler,
            ClientConfiguration config, boolean commit) {
        this.handler = handler;
        this.config = config;
        this.commit = commit;
    }

    /**
     * Executes the test scenario and stops.
     * 
     * @return <code>false</code>, as the client just executes the test scenario
     *         and stops.
     */
    @Override
    public boolean execute() {
        Integer versionRoot = 0;
        Integer versionShared = 0;
        Integer versionPublic = 0;
        Path fileFolder = Paths.get(config.getRootPath()).normalize();
        Path syncFolder = Paths.get(config.getSyncPath()).normalize();
        Permission[] permissionsSharer1 = new Permission[] { new Permission(
                "sharer1", PermissionValue.READ_HISTORY) };
        Permission[] permissionsPublic = new Permission[] { Permission.PUBLIC };

        try {
            /*
             * PUT folder tests.
             */

            // Create folder1
            boolean putFolderSuccess = handler.putFolder(new PutFolderData(
                    null, "folder1", permissionsSharer1, 1));
            assert (putFolderSuccess);

            // Create folder2
            putFolderSuccess = handler.putFolder(new PutFolderData(null,
                    "folder2", permissionsPublic,
                    DataContainers.PUBLIC_FILE_KEY_VERSION));
            assert (putFolderSuccess);

            /*
             * Private file tests.
             */

            // Put file1.txt on the server
            Path serverPathFile1 = Paths.get("file1.txt");
            Path localPathFile1 = serverPathFile1;
            Path completePathFile1 = Paths.get(config.getRootPath(),
                    localPathFile1.toString());

            write(completePathFile1, "asdf", false);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, completePathFile1);
                assert (versionRoot == 1);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Put file2.txt on the server
            Path serverPathFile2 = Paths.get("file2.txt");
            Path localPathFile2 = serverPathFile2;
            Path completePathFile2 = Paths.get(config.getRootPath(),
                    localPathFile2.toString());

            write(completePathFile2, "asdf2", false);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, completePathFile2);
                assert (versionRoot == 2);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Modify file1.txt (no diff should be created)
            write(completePathFile1, "fdsa", true);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, completePathFile1);
                assert (versionRoot == 3);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Rename file1.txt to file3.txt
            Path completePathFile3 = Paths.get(config.getRootPath(),
                    "file3.txt");
            Files.move(completePathFile1, completePathFile3);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, completePathFile1);
                assert (versionRoot == 4);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Delete file3.txt
            Files.delete(completePathFile3);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, completePathFile3);
                assert (versionRoot == 5);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Rename file2.txt to file1.txt
            Files.move(completePathFile2, completePathFile1);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, completePathFile2);
                assert (versionRoot == 6);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Create and put file2.txt on the server
            String txt = "";
            for (int i = 1; i <= 10; i++) {
                txt += "qwertz";
            }
            write(completePathFile2, txt, false);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, completePathFile2);
                assert (versionRoot == 7);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Modify file2.txt (a diff should be created)
            write(completePathFile2, "x", true);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, completePathFile2);
                assert (versionRoot == 8);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            /*
             * Private files in sub-folder tests.
             */

            // Move file1.txt in the sub-folder sub1
            Path completePathSub1 = Paths.get(config.getRootPath(), "sub1");
            Path sub1File1 = Paths.get(config.getRootPath(), "sub1",
                    "file1.txt");
            Files.createDirectory(completePathSub1);
            Files.move(completePathFile1, sub1File1);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, completePathFile1);
                assert (versionRoot == 9);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Move file2.txt in the sub-folder sub1
            Path sub1File2 = Paths.get(config.getRootPath(), "sub1",
                    "file2.txt");
            Files.move(completePathFile2, sub1File2);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, completePathFile2);
                assert (versionRoot == 10);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Rename file2.txt to file3.txt
            Path sub1File3 = Paths.get(config.getRootPath(), "sub1",
                    "file3.txt");
            Files.move(sub1File2, sub1File3);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, sub1File2);
                assert (versionRoot == 11);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Modify file3.txt
            write(sub1File3, "y", true);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, sub1File3);
                assert (versionRoot == 12);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Rename folder sub1 to sub2
            Path completePathSub2 = Paths.get(config.getRootPath(), "sub2");
            Files.move(completePathSub1, completePathSub2);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, sub1File3);
                // the two files in the sub-folder were renamed
                assert (versionRoot == 14);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Delete file1.txt
            Path sub2File1 = Paths.get(config.getRootPath(), "sub2",
                    "file1.txt");
            Files.delete(sub2File1);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, sub2File1);
                assert (versionRoot == 15);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Delete file3.txt
            Path sub2File3 = Paths.get(config.getRootPath(), "sub2",
                    "file3.txt");
            Files.delete(sub2File3);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, sub2File3);
                assert (versionRoot == 16);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Delete sub2 (must be empty)
            Files.delete(completePathSub2);

            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, sub2File3);
                // should not change the version
                assert (versionRoot == 16);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            /*
             * Shared folder tests.
             */

            // Add shared1 file1.txt
            Path shared1File1 = Paths.get(config.getRootPath(), "shared1",
                    "file1.txt");
            write(shared1File1, "yxcv", false);

            if (commit) {
                versionShared = sync(fileFolder, syncFolder, shared1File1);
                assert (versionShared == 1);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Modify shared1 file1.txt
            write(shared1File1, "a", true);

            if (commit) {
                versionShared = sync(fileFolder, syncFolder, shared1File1);
                assert (versionShared == 2);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Rename shared1 file1.txt to file2.txt
            Path shared1File2 = Paths.get(config.getRootPath(), "shared1",
                    "file2.txt");
            Files.move(shared1File1, shared1File2);

            if (commit) {
                versionShared = sync(fileFolder, syncFolder, shared1File1);
                assert (versionShared == 3);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Move shared1 file2.txt to root directory as file1.txt
            // Deletes shared1 file2.txt and adds owner-private file1.txt
            Files.move(shared1File2, completePathFile1);

            // Deletes shared1 file2.txt
            if (commit) {
                versionShared = sync(fileFolder, syncFolder, shared1File2);
                assert (versionShared == 4);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Adds file1.txt
            if (commit) {
                versionRoot = sync(fileFolder, syncFolder, completePathFile1);
                assert (versionRoot == 17);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Add shared1 file1.txt
            write(shared1File1, "shared1", false);

            if (commit) {
                versionShared = sync(fileFolder, syncFolder, shared1File1);
                assert (versionShared == 5);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            /*
             * Public folder tests.
             */

            // Add public1 file1.txt
            Path public1File1 = Paths.get(config.getRootPath(), "public1",
                    "file1.txt");
            write(public1File1, "public1", false);

            if (commit) {
                versionPublic = sync(fileFolder, syncFolder, public1File1);
                assert (versionPublic == 1);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Add public1 file2.txt (name with Umlaut)
            Path public1File2 = Paths.get(config.getRootPath(), "public1",
                    "fileÄ.txt");
            write(public1File2, "public1-file2", false);

            if (commit) {
                versionPublic = sync(fileFolder, syncFolder, public1File2);
                assert (versionPublic == 2);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Move public1 file2.txt to file3.txt (both names with Umlaut)
            Path public1File3 = Paths.get(config.getRootPath(), "public1",
                    "fileÖ.txt");
            Files.move(public1File2, public1File3);

            if (commit) {
                versionPublic = sync(fileFolder, syncFolder, public1File2);
                assert (versionPublic == 3);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Modify public1 file3.txt
            write(public1File3, "a", true);

            if (commit) {
                versionPublic = sync(fileFolder, syncFolder, public1File3);
                assert (versionPublic == 4);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Delete public1 file3.txt
            Files.delete(public1File3);

            if (commit) {
                versionPublic = sync(fileFolder, syncFolder, public1File3);
                assert (versionPublic == 5);
            } else {
                try {
                    Thread.sleep(WAITING_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            boolean success = commit ? ((versionRoot == 17)
                    && (versionShared == 5) && (versionPublic == 5)) : true;

            if (success && Files.exists(completePathFile1)
                    && !Files.exists(completePathFile2)
                    && !Files.exists(completePathFile3)
                    && !Files.exists(completePathSub2)
                    && Files.exists(shared1File1)
                    && !Files.exists(shared1File2)
                    && Files.exists(public1File1)
                    && !Files.exists(public1File2)
                    && !Files.exists(public1File3)) {
                System.out.println("\n\tSynchronization successful!\n");
            } else {
                System.err.println("\n\tSynchronization failed!\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // stop execution
        return false;
    }

    /**
     * Does nothing.
     */
    @Override
    public void stop() {
    }

    /**
     * Writes the given text to the given file in the given mode. The file is
     * locked.
     * 
     * @param path
     *            the path to the file to write.
     * @param text
     *            the text to write.
     * @param append
     *            <code>true</code>, if the text should be appended to the end
     *            of the file. Otherwise, <code>false</code>.
     */
    private void write(Path path, String text, boolean append) {
        assert (path != null) && (text != null);
        boolean repeat = true;

        while (repeat) {
            try (FileOutputStream out = new FileOutputStream(path.toFile(),
                    append);) {
                FileLock lock = out.getChannel().tryLock(0, Long.MAX_VALUE,
                        false);

                if (lock != null) {
                    out.write(text.getBytes(Coder.CHARSET));
                    repeat = false;
                }
            } catch (IOException | OverlappingFileLockException e) {
            }

            if (repeat) {
                System.out
                        .println(String
                                .format("REPEAT write %s due to present lock from other process.",
                                        path.toString()));

                try {
                    Thread.sleep(REPEAT_TIME);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Returns the synchronization version number.
     * 
     * @param fileFolder
     *            the client's root directory.
     * @param syncFolder
     *            the synchronization directory.
     * @param completeFileName
     *            the complete path to a file in the client's root directory.
     * @return the version number. Is <code>null</code> when an error occurred.
     * @throws IOException
     */
    private Integer sync(Path fileFolder, Path syncFolder, Path completeFileName)
            throws IOException {
        assert ((fileFolder != null) && (syncFolder != null) && (completeFileName != null));

        Path relativeFileName = fileFolder.normalize()
                .relativize(completeFileName).normalize();
        GetSyncData syncData = FileHandler.getSyncData(fileFolder, syncFolder,
                relativeFileName);
        Path localPath = FileHandler.getAccessBundleDirectory(fileFolder,
                relativeFileName);
        return handler.getSync(syncData, new ActionData[0], localPath, true);
    }
}
