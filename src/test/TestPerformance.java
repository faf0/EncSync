package test;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.json.simple.parser.ParseException;

import client.Client;
import client.executors.ClientExecutor.ClientExecutorType;

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
 * Initializes the client and server trees, although the server should not be
 * run on this machine. The server must be started manually (on another machine)
 * and its database and file hierarchy has to be initialized prior to each test
 * run. Starts a client which executes the test cases of the
 * <code>TestPerformanceExecutor</code>. One client creates and modifies large
 * files. The files are encrypted and transmitted as well as sent in plaintext.
 * Prints the time for multiple test runs to the CSV file
 * <code>.test_commit.csv</code>. Then another client using the same user name
 * and password is started which synchronizes the state of the first client to a
 * fresh directory tree. Prints the time for multiple test runs to the CSV file
 * <code>.test_sync.csv</code>.
 * 
 * @author Fabian Foerg
 */
public final class TestPerformance {
    /**
     * The size of the newly created test file in bytes.
     */
    private static final long FILE_SIZE = 100 * 1024 * 1024;

    /**
     * Hidden constructor.
     */
    private TestPerformance() {
    }

    /**
     * Starts the performance test.
     * 
     * @param args
     *            the size of the files to write in bytes.
     */
    public static void main(String[] args) {
        // delete old files, except hidden test results.
        Path serverConfig = Paths.get("files", "server", ".conf");
        InitClientAndServer.main(new String[] { serverConfig.toString() });

        // default values
        ClientExecutorType type = ClientExecutorType.TEST_PERFORMANCE_COMMITTER_NEW;
        long fileSize = FILE_SIZE;

        // parse size
        if (args.length == 2) {
            try {
                fileSize = Long.parseLong(args[1]);
            } catch (NumberFormatException e) {
                e.printStackTrace();
            }
        }
        // parse type
        if ((args.length == 1) || (args.length == 2)) {
            switch (args[0]) {
            case "c":
                type = ClientExecutorType.TEST_PERFORMANCE_COMMITTER_NEW;
                break;

            case "cm":
                type = ClientExecutorType.TEST_PERFORMANCE_COMMITTER_NEW_AND_MODIFIED;
                break;

            default:
                System.out.println("Unknown type");
                break;
            }
        }
        // print usage
        if ((args.length == 0) || (args.length > 2)) {
            System.out.println("Usage: program [type] [size]");
            System.out
                    .println("type: c for create only; cm for create and modify");
            System.out
                    .println("size: file size in bytes of the files to create\n");
        }
        // run the test
        runTest(type, fileSize);
    }

    private static void runTest(ClientExecutorType type, long fileSize) {
        assert ((ClientExecutorType.TEST_PERFORMANCE_COMMITTER_NEW.equals(type) || ClientExecutorType.TEST_PERFORMANCE_COMMITTER_NEW_AND_MODIFIED
                .equals(type)) && (fileSize >= 0));

        System.out.println("Starting performance test...");
        if (ClientExecutorType.TEST_PERFORMANCE_COMMITTER_NEW.equals(type)) {
            System.out.println("Type: create only");
        } else {
            System.out.println("Type: create and modify");
        }
        System.out.println(String.format("File size: %d bytes", fileSize));

        try {
            Client clientChangerAndCommitter, clientSyncer;

            /*
             * Make sure that a new client is constructed, when the server is
             * already running, as the constructor already creates the socket
             * and waits for the handshake to complete.
             */
            clientChangerAndCommitter = new Client("files/clients/joe1/.conf",
                    type, fileSize);
            clientChangerAndCommitter.start();
            clientChangerAndCommitter.join();

            clientSyncer = new Client("files/clients/joe2/.conf",
                    ClientExecutorType.TEST_PERFORMANCE_SYNCER, null);
            clientSyncer.start();
            clientSyncer.join();
        } catch (KeyManagementException | NoSuchAlgorithmException
                | CertificateException | KeyStoreException | IOException
                | ParseException e) {
            e.printStackTrace();
        }
    }
}
