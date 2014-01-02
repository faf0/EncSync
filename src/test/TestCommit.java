package test;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.sql.SQLException;

import org.json.simple.parser.ParseException;

import server.Server;
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
 * Initializes the client and server. Starts a server and and a client which
 * executes the test cases of the <code>TestExecutor</code>. Local detected
 * changes are committed. Then another client using the same user name and
 * password is started which synchronizes the state of the first client to a
 * fresh directory tree. Afterwards, another client with a different user name
 * and password synchronizes the public and shared directory.
 * 
 * @author Fabian Foerg
 */
public final class TestCommit {
    /**
     * Hidden constructor.
     */
    private TestCommit() {
    }

    /**
     * Starts the test.
     * 
     * @param args
     *            ignored.
     */
    public static void main(String[] args) {
        /*
         * Start server and client.
         */
        Path serverConfig = Paths.get("files", "server", ".conf");
        InitClientAndServer.main(new String[] { serverConfig.toString() });

        try {
            Server server = new Server(serverConfig.toString());
            Client clientChangerAndCommitter, clientSyncer, clientSharer;

            server.start();
            /*
             * Make sure that a new client is constructed, when the server is
             * already running, as the constructor already creates the socket
             * and waits for the handshake to complete.
             */
            clientChangerAndCommitter = new Client("files/clients/joe1/.conf",
                    ClientExecutorType.TEST_COMMIT, null);
            clientChangerAndCommitter.start();
            clientChangerAndCommitter.join();

            clientSyncer = new Client("files/clients/joe2/.conf",
                    ClientExecutorType.SYNCHRONIZATION_ONLY, null);
            clientSyncer.start();
            clientSyncer.stop();
            clientSyncer.join();

            clientSharer = new Client("files/clients/sharer1/.conf",
                    ClientExecutorType.SYNCHRONIZATION_ONLY, null);
            clientSharer.start();
            clientSharer.stop();
            clientSharer.join();

            server.stop();
            server.join();
        } catch (KeyManagementException | UnrecoverableKeyException
                | NoSuchAlgorithmException | CertificateException
                | KeyStoreException | IOException | ParseException
                | ClassNotFoundException | SQLException e) {
            e.printStackTrace();
        }
    }
}
