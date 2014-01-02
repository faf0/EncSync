package client.executors;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import protocol.DataContainers.PutAuthData;
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

/**
 * Reads a user name, a password, and optionally a current password from
 * System.in. Registers or updates the respective user on the server.
 * 
 * @author Fabian Foerg
 */
public final class PutAuthExecutor implements ClientExecutor {
    private final ClientConnectionHandler handler;

    /**
     * Creates a new instance with the given parameters.
     * 
     * @param handler
     *            the client connection handler.
     */
    public PutAuthExecutor(ClientConnectionHandler handler) {
        this.handler = handler;
    }

    /**
     * Executes the PUT auth procedure and stops.
     */
    @Override
    public boolean execute() {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                System.in));) {
            String userName;
            String password;
            String currentPassword = null;
            boolean done;
            boolean success;

            System.out
                    .println("Enter the user name to create/update on the server:");

            do {
                userName = in.readLine();
                done = ClientConfiguration.isValidUserName(userName);

                if (!done) {
                    System.out.println("You did not enter a valid user name!");
                }
            } while (!done);

            System.out.println("Enter the password to set for the user:");

            done = false;

            do {
                password = in.readLine();
                done = ClientConfiguration.isValidPassword(password);

                if (!done) {
                    System.out.println("You did not enter a valid password!");
                }
            } while (!done);

            System.out
                    .println("Enter the current password for the user or ctrl-D:");

            done = false;

            do {
                currentPassword = in.readLine();

                if ((currentPassword != null) && (currentPassword.length() > 0)) {
                    done = ClientConfiguration.isValidPassword(currentPassword);
                } else {
                    currentPassword = null;
                    done = true;
                }

                if (!done) {
                    System.out.println("You did not enter a valid password!");
                }
            } while (!done);

            System.out.println("Sending request to server with");
            System.out.format(
                    "user name: %s\npassword: %s\ncurrent password: %s\n",
                    userName, password, currentPassword);

            success = handler.putAuth(new PutAuthData(userName, password,
                    currentPassword));

            if (success) {
                System.out.println("Request successfully executed by server!");
            } else {
                System.err
                        .println("Request was NOT successfully executed by server!");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Does nothing.
     */
    @Override
    public void stop() {
    }
}
