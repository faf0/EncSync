package client.executors;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import misc.Coder;
import misc.FileHandler;
import protocol.DataContainers.ActionData;
import protocol.DataContainers.GetSyncData;
import client.ClientConnectionHandler;
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

public final class TestPerformanceSyncer implements ClientExecutor {
    /**
     * Filename of the output CSV file with the test run times in milliseconds.
     */
    private static final String RESULT_FILENAME = ".test_sync.csv";
    /**
     * The name of the local shared folder without encryption.
     */
    private static final String PUBLIC_FOLDERNAME = "public2";

    private final ClientConnectionHandler handler;
    private final ClientConfiguration config;

    /**
     * Creates a new instance with the given parameters.
     * 
     * @param handler
     *            the client connection handler.
     * @param config
     *            the client configuration file.
     */
    public TestPerformanceSyncer(ClientConnectionHandler handler,
            ClientConfiguration config) {
        this.handler = handler;
        this.config = config;
    }

    /**
     * Synchronizes the root directory and the public directory. Measures the
     * time it takes in milliseconds each time. Result is written to
     * <code>RESULT_FILENAME<code>: the first column reflects the private
     * directory sync time; the second column reflects the public directory
     * sync time.
     */
    @Override
    public boolean execute() {
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
                Paths.get(relativePath.toString(), "arbitrary"));
        String formatString = privateDirectory ? "%d;" : "%d\n";
        Integer version;
        boolean written;
        long timeStart, timeStop;

        // Synchronize the given directory and measure the time.
        timeStart = System.currentTimeMillis();
        version = handler.getSync(syncData, new ActionData[0], relativePath,
                false);
        timeStop = System.currentTimeMillis();
        assert ((version == 1) || (version == 2));

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
