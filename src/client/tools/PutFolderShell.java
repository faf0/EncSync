package client.tools;

import java.io.IOException;
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
 * Allows the user to specify a folder name and permissions and send the
 * generated PUT folder request to the server which is started here.
 * 
 * @author Fabian Foerg
 */
public final class PutFolderShell {
    /**
     * Hidden constructor.
     */
    private PutFolderShell() {
    }

    /**
     * Prompts the user for the folder name and permissions. The PUT folder
     * request is finally sent to server which is started here.
     * 
     * @param args
     *            the path to the configuration file.
     */
    public static void main(String[] args) {
        String configPath;

        if (args.length != 1) {
            throw new IllegalArgumentException(
                    "Path to configuration file must be present!");
        }

        configPath = args[0];

        try {
            Client client = new Client(configPath,
                    ClientExecutorType.PUT_FOLDER, null);
            client.start();
            client.join();
        } catch (KeyManagementException | NoSuchAlgorithmException
                | KeyStoreException | CertificateException | IOException
                | ParseException e) {
            e.printStackTrace();
        }
    }
}
