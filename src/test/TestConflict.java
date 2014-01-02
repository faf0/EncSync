package test;

import java.io.IOException;
import java.nio.file.Files;
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
import client.executors.SynchronizationExecutor;
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
 * This test examines the correct handling of conflicts. Successfully run
 * <code>TestCommit</code> prior to this test. Removes the version file from the
 * synchronization directory and adds the local files file2.txt and file3.txt.
 * The file file1.txt is already present, if <code>TestCommit</code> executed
 * successfully. Tests are done under the user joe2.
 * 
 * @author Fabian Foerg
 */
public final class TestConflict {
    /**
     * Hidden constructor.
     */
    private TestConflict() {
    }

    /**
     * Starts the test.
     * 
     * @param args
     *            ignored.
     */
    public static void main(String[] args) {
        Server server;
        Client clientSyncer;

        try {
            Files.createFile(Paths.get("files", "clients", "joe2", "file2.txt"));
            Files.createFile(Paths.get("files", "clients", "joe2", "file3.txt"));
            Files.delete(Paths.get("files", "clients", "joe2", ".sync",
                    SynchronizationExecutor.VERSION_FILE));

            server = new Server("files/server/.conf");
            server.start();

            clientSyncer = new Client("files/clients/joe2/.conf",
                    ClientExecutorType.SYNCHRONIZATION_ONLY, null);
            clientSyncer.start();
            clientSyncer.stop();
            clientSyncer.join();

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
