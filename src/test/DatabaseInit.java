package test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.json.simple.parser.ParseException;

import server.database.DatabaseCreation;
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
 * Removes an existing server database and initalizes the server database with
 * values for testing purposes. Test users are inserted into the database.
 * 
 * @author Fabian Foerg
 */
public final class DatabaseInit {
    /**
     * Removes the old server database, creates a new one and initializes it
     * with test values.
     * 
     * @param args
     *            the path to the server configuration file.
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            throw new IllegalArgumentException(
                    "Path to configuration file must be present!");
        }

        try {
            ServerConfiguration serverConfig = ServerConfiguration.parse(Paths
                    .get(args[0]));
            Files.deleteIfExists(Paths.get(serverConfig.getDatabasePath()));
            DatabaseCreation.main(args);
            DatabaseQueries.insertUser("joe1", "joe1-secret");
            DatabaseQueries.insertUser("sharer1", "sharer1-secret");
        } catch (IOException | ParseException e) {
            e.printStackTrace();
        }
    }
}
