package client.executors;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import misc.Coder;
import misc.FileHandler;
import protocol.DataContainers;
import protocol.DataContainers.ActionData;
import protocol.DataContainers.GetSyncData;
import protocol.DataContainers.PutFolderData;
import client.ClientConnectionHandler;
import configuration.ClientConfiguration;
import configuration.Permission;

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

public final class TestPerformanceCommitter implements ClientExecutor {
    /**
     * The test type for the test performance committer.
     * 
     * @author Fabian Foerg
     */
    public static enum CommitterType {
        NEW, NEW_AND_MODIFIED,
    }

    /**
     * Filename of the output CSV file with the test run times in milliseconds.
     */
    private static final String RESULT_FILENAME = ".test_commit.csv";
    /**
     * The name of the local shared folder without encryption.
     */
    private static final String PUBLIC_FOLDERNAME = "public1";
    /**
     * Filename of the test file.
     */
    private static final String FILENAME = "test_file_raw";
    /**
     * The buffer size in bytes of the file writer buffer.
     */
    private static final int BUFFER_SIZE = 256 * 1024;

    private final ClientConnectionHandler handler;
    private final ClientConfiguration config;
    private final CommitterType type;
    private final long fileSize;

    /**
     * Creates a new instance with the given parameters.
     * 
     * @param handler
     *            the client connection handler.
     * @param config
     *            the client configuration file.
     * @param fileSize
     *            the file size in bytes.
     */
    public TestPerformanceCommitter(ClientConnectionHandler handler,
            ClientConfiguration config, CommitterType type, Object fileSize) {
        if ((fileSize == null) || !(fileSize instanceof Long)
                || (((Long) fileSize) < 0)) {
            throw new IllegalArgumentException(
                    "fileSize must be a long greater or equal to zero!");
        }

        this.handler = handler;
        this.config = config;
        this.type = type;
        this.fileSize = (long) fileSize;
    }

    /**
     * Writes and modifies a large file. Commits the changes. Measures the time
     * and write it to <code>RESULT_FILENAME<code>: Result is written to
     * <code>RESULT_FILENAME<code>: the first column reflects the private
     * directory commit time; the second column reflects the public directory
     * commit time.
     */
    @Override
    public boolean execute() {
        Path privateFilename = Paths.get(config.getRootPath(), FILENAME);
        Path publicFilename = Paths.get(config.getRootPath(),
                PUBLIC_FOLDERNAME, FILENAME);
        Permission[] permissionsPublic = new Permission[] { Permission.PUBLIC };
        PutFolderData publicFolder = new PutFolderData(null, "folder2",
                permissionsPublic, DataContainers.PUBLIC_FILE_KEY_VERSION);

        /*
         * Create the public folder on the server. Its server name is folder2
         * (s. .access in public folder).
         */
        handler.putFolder(publicFolder);

        // Write the files, but do not measure the time.
        writeFile(privateFilename, fileSize);
        writeFile(publicFilename, fileSize);

        // Synchronize the private directory and measure the time.
        synchronize(true);
        // Synchronize the public directory and measure the time.
        synchronize(false);

        return false;
    }

    /**
     * Does nothing.
     */
    @Override
    public void stop() {
    }

    /**
     * Writes the test file.
     * 
     * @param file
     *            the path where the test file is to be written.
     * @param fileSize
     *            the size of the test file in bytes.
     * @return <code>true</code>, if the file was successfully written.
     *         <code>false</code>, otherwise.
     */
    private static boolean writeFile(Path file, long fileSize) {
        assert ((file != null) && (fileSize >= 0));
        boolean success = false;
        byte[] buffer = new byte[BUFFER_SIZE];
        byte b = 0;

        // fill buffer
        for (int i = 0; i < Math.min(BUFFER_SIZE, fileSize); i++) {
            buffer[i] = b;
            b++;
        }

        try (FileOutputStream writer = new FileOutputStream(file.toFile(),
                false)) {
            // use buffer for file content
            long written = 0;

            while (written < fileSize) {
                int toWrite = (int) Math.min(buffer.length, fileSize - written);
                writer.write(buffer, 0, toWrite);
                written += toWrite;
            }

            writer.close();
            success = true;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return success;
    }

    /**
     * Modifies the test file.
     * 
     * @param file
     *            the path of the test file.
     * @param fileSize
     *            the size of the test file in bytes.
     * @return <code>true</code>, if the file was successfully modified.
     *         <code>false</code>, otherwise.
     */
    private static boolean modifyFile(Path file, long fileSize) {
        assert ((file != null) && (fileSize >= 0));
        boolean success = false;

        try (FileChannel fc = FileChannel.open(file, StandardOpenOption.READ,
                StandardOpenOption.WRITE);) {
            long position = Files.size(file);
            ByteBuffer modification = ByteBuffer.wrap(new byte[] { 0 });
            assert ((position == fileSize) && (position == fc.size()));
            /*
             * Append to end of file. If you choose another position, bytes will
             * only be overwritten.
             */
            fc.position(position);
            while (modification.hasRemaining()) {
                fc.write(modification);
            }
            fc.close();
            assert (Files.size(file) == (fileSize + modification.capacity()));
            success = true;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return success;
    }

    /**
     * Synchronizes the private or public directory.
     * 
     * @param privateDirectory
     *            <code>true</code>, if the private directory is to be
     *            synchronized. <code>false</code>, if the public directory is
     *            to be synchronized.
     */
    private void synchronize(boolean privateDirectory) {
        Path rootPath = Paths.get(config.getRootPath());
        Path relativePath = privateDirectory ? Paths.get(".") : Paths
                .get(PUBLIC_FOLDERNAME);
        Path syncPath = Paths.get(config.getSyncPath());
        GetSyncData syncData = FileHandler.getSyncData(rootPath, syncPath,
                Paths.get(relativePath.toString(), FILENAME));
        String formatString = privateDirectory ? "%d;" : "%d\n";
        Integer version;
        boolean written;
        long timeStart, timeStop;

        // Synchronize the given directory and measure the time.
        timeStart = System.currentTimeMillis();
        version = handler.getSync(syncData, new ActionData[0], relativePath,
                true);
        timeStop = System.currentTimeMillis();
        assert (version == 1);

        if (CommitterType.NEW_AND_MODIFIED.equals(type)) {
            Path localFilename = Paths.get(config.getRootPath(),
                    relativePath.toString(), FILENAME);
            modifyFile(localFilename, fileSize);
            timeStart = System.currentTimeMillis() - (timeStop - timeStart);
            version = handler.getSync(syncData, new ActionData[0],
                    relativePath, true);
            timeStop = System.currentTimeMillis();
            assert (version == 2);
        }

        // Append the result to the file.
        written = append(String.format(formatString, timeStop - timeStart));
        assert (written);
    }

    /**
     * Appends the given string to file <code>RESULT_FILENAME</code>.
     * 
     * @param toAppend
     *            the string to append.
     * @return <code>true</code>, if the file was successfully written.
     *         <code>false</code>, otherwise.
     */
    private boolean append(String toAppend) {
        assert (toAppend != null);
        boolean success = false;

        try (BufferedWriter writer = Files.newBufferedWriter(
                Paths.get(config.getRootPath(), RESULT_FILENAME),
                Coder.CHARSET, StandardOpenOption.CREATE,
                StandardOpenOption.APPEND)) {
            writer.write(toAppend);
            writer.close();
            success = true;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return success;
    }
}
