package client.executors;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Paths;

import client.ClientConnectionHandler;

import misc.FileHandler;
import protocol.DataContainers;
import protocol.DataContainers.PutFolderData;
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
 * Reads a folder name and permissions from System.in and tries to create the
 * folder on the server.
 * 
 * @author Fabian Foerg
 */
public final class PutFolderExecutor implements ClientExecutor {
    private final ClientConnectionHandler handler;

    /**
     * Creates a new instance with the given parameters.
     * 
     * @param handler
     *            the client connection handler.
     */
    public PutFolderExecutor(ClientConnectionHandler handler) {
        this.handler = handler;
    }

    /**
     * Executes the PUT folder procedure and stops.
     */
    @Override
    public boolean execute() {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                System.in));) {
            String folderName;
            Permission[] permissions;
            int keyVersion = 1;
            boolean done;
            boolean success;

            System.out
                    .println("Enter the folder name to create/update on the server:");

            do {
                folderName = in.readLine();
                done = (folderName != null)
                        && FileHandler
                                .isSharedFolderName(Paths.get(folderName));

                if (!done) {
                    System.out
                            .println("You did not enter a valid folder name!");
                }
            } while (!done);

            System.out
                    .format("Enter the minimum allowed key version on the server (at least 1 or %d for public files) [1]:%n",
                            DataContainers.PUBLIC_FILE_KEY_VERSION);

            do {
                String keyVersionString = in.readLine();

                if ((keyVersionString != null)
                        && !"".equals(keyVersionString.trim())) {
                    try {
                        keyVersion = Integer.parseInt(keyVersionString);
                        done = ((keyVersion >= 1) || (keyVersion == DataContainers.PUBLIC_FILE_KEY_VERSION));
                    } catch (NumberFormatException e) {
                        done = false;
                    }
                } else {
                    done = true;
                }

                if (!done) {
                    System.out
                            .println("You did not enter a valid minimum key version!");
                }
            } while (!done);

            System.out
                    .println("Enter the folder permissions in one of the following forms:");
            System.out.println(Permission.PUBLIC.getMember());
            System.out.println("Ctrl-D for private folders");
            System.out.format(
                    "member1%spermissionValue%smember2%spermissionValue\n",
                    Permission.MEMBER_PERMISSION_DELIMITER,
                    Permission.MEMBER_DELIMITER,
                    Permission.MEMBER_PERMISSION_DELIMITER);

            System.out.println("\nValid permission values are:");
            for (PermissionValue value : Permission.PermissionValue.values()) {
                System.out.println(value.toString());
            }

            do {
                String permissionString = in.readLine();
                if ((permissionString == null)
                        || "".equals(permissionString.trim())) {
                    permissions = null;
                    done = true;
                } else if (Permission.PUBLIC.getMember().equals(
                        permissionString)) {
                    permissions = new Permission[] { Permission.PUBLIC };
                    done = true;
                } else {
                    permissions = Permission.parsePermissions(permissionString);
                    done = (permissions != null);
                }

                if (!done) {
                    System.out.println("You did not enter valid permissions!");
                }
            } while (!done);

            System.out.println("Sending request to server with");
            System.out.format(
                    "folder name: %s\npermissions: %s\nkey version: %d\n",
                    folderName, Permission.toPermissionString(permissions),
                    keyVersion);

            success = handler.putFolder(new PutFolderData(null, folderName,
                    permissions, keyVersion));

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
