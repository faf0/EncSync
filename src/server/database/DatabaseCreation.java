package server.database;

import java.io.IOException;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.json.simple.parser.ParseException;

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
 * Creates the tables for the server database.
 * 
 * @author Fabian Foerg
 */
public final class DatabaseCreation {
    /**
     * Hidden constructor.
     */
    private DatabaseCreation() {
    }

    /**
     * Creates the users table.
     * 
     * @param statement
     *            open database connection statement.
     * @throws SQLException
     */
    public static void createUsers(Statement statement) throws SQLException {
        if (statement == null) {
            throw new IllegalArgumentException("statement may not be null!");
        }

        String createTable = "CREATE TABLE users ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
                + "user VARCHAR NOT NULL, salted_hash VARBYTE NOT NULL, "
                + "salt VARBYTE NOT NULL, "
                + "CONSTRAINT user_unique UNIQUE (user));";
        statement.executeUpdate(createTable);
    }

    /**
     * Creates the folder table.
     * 
     * @param statement
     *            open database connection statement.
     * @throws SQLException
     */
    public static void createFolder(Statement statement) throws SQLException {
        if (statement == null) {
            throw new IllegalArgumentException("statement may not be null!");
        }

        String createTable = "CREATE TABLE folder ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
                + "owner INTEGER NOT NULL, path VARCHAR NOT NULL, "
                + "key_version INTEGER NOT NULL, group_no INTEGER, "
                + "CONSTRAINT owner_path_unique UNIQUE (owner, path), "
                + "CONSTRAINT path_constraint CHECK (path<>'' AND path<>'/'), "
                + "CONSTRAINT key_version_constraint CHECK (key_version>=1 OR key_version=-1), "
                + "FOREIGN KEY(owner) REFERENCES users(id));";
        statement.executeUpdate(createTable);
    }

    /**
     * Creates the file table.
     * 
     * @param statement
     *            open database connection statement.
     * @throws SQLException
     */
    public static void createFile(Statement statement) throws SQLException {
        if (statement == null) {
            throw new IllegalArgumentException("statement may not be null!");
        }

        String createTable = "CREATE TABLE file ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
                + "owner INTEGER NOT NULL, folder VARCHAR NOT NULL, "
                + "name VARCHAR NOT NULL, "
                + "modified TIMESTAMP NOT NULL, "
                + "key_version INTEGER NOT NULL, "
                + "is_diff BOOLEAN NOT NULL, "
                + "hash VARBYTE NOT NULL, version INTEGER NOT NULL, "
                + "size BIGINT NOT NULL, "
                + "extra VARBYTE, mac VARBYTE, "
                + "CONSTRAINT owner_folder_version_unique UNIQUE (owner, folder, version), "
                + "CONSTRAINT name_constraint CHECK (name<>'' AND name<>'/' AND name<>'.'), "
                + "CONSTRAINT version_constraint CHECK (version>=1), "
                + "CONSTRAINT key_version_constraint CHECK (key_version>=1 OR key_version=-1), "
                + "CONSTRAINT size CHECK (size>=0), "
                + "FOREIGN KEY(owner) REFERENCES users(id));";
        statement.executeUpdate(createTable);
    }

    /**
     * Creates the groups table.
     * 
     * @param statement
     *            open database connection statement.
     * @throws SQLException
     */
    public static void createGroups(Statement statement) throws SQLException {
        if (statement == null) {
            throw new IllegalArgumentException("statement may not be null!");
        }

        String createTable = "CREATE TABLE groups ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
                + "group_no INTEGER NOT NULL, "
                + "member INTEGER NOT NULL, "
                + "permission VARCHAR NOT NULL, "
                + "CONSTRAINT group_no_constraint CHECK (group_no>=1 OR group_no = -1), "
                + "CONSTRAINT permission_constraint CHECK (permission = 'r' OR permission = 'rw' "
                + "OR permission = 'rh' OR permission = 'rwh'), "
                + "FOREIGN KEY(member) REFERENCES users(id));";
        statement.executeUpdate(createTable);
    }

    /**
     * Creates the history table.
     * 
     * @param statement
     *            open database connection statement.
     * @throws SQLException
     */
    public static void createHistory(Statement statement) throws SQLException {
        if (statement == null) {
            throw new IllegalArgumentException("statement may not be null!");
        }

        String createTable = "CREATE TABLE history ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
                + "owner INTEGER NOT NULL, folder VARCHAR NOT NULL, "
                + "version INTEGER NOT NULL, time TIMESTAMP NOT NULL, "
                + "action CHAR NOT NULL, "
                + "object1 VARCHAR NOT NULL, object2 VARCHAR, "
                + "CONSTRAINT owner_path_version_unique UNIQUE (owner, folder, version), "
                + "CONSTRAINT version_constraint CHECK (version>=1), "
                + "CONSTRAINT folder_constraint CHECK (folder<>'' AND folder<>'/'), "
                + "CONSTRAINT action_constraint CHECK (action='A' OR action='M' OR action='D' OR action='R'), "
                + "CONSTRAINT objects_constraint CHECK (((action='A' OR action='M' OR action='D') AND object2 IS NULL) OR (action='R' AND object2 IS NOT NULL)), "
                + "FOREIGN KEY(owner) REFERENCES users(id));";
        statement.executeUpdate(createTable);
    }

    /**
     * Creates the server database tables.
     * 
     * @param args
     *            the path to the server configuration file.
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            throw new IllegalArgumentException(
                    "Path to configuration file must be present!");
        }

        ServerConfiguration serverConfig = null;

        try {
            serverConfig = ServerConfiguration.parse(Paths.get(args[0]));
        } catch (IOException | ParseException e) {
            e.printStackTrace();
        }

        if (serverConfig != null) {
            try {
                boolean initialized = DatabaseConnection.init(serverConfig
                        .getDatabasePath());

                if (initialized) {
                    try (Connection connection = DatabaseConnection
                            .getConnection();
                            Statement statement = connection.createStatement();) {
                        statement.setQueryTimeout(10);

                        // create tables
                        createUsers(statement);
                        createFolder(statement);
                        createFile(statement);
                        createGroups(statement);
                        createHistory(statement);
                    } catch (SQLException e) {
                        e.printStackTrace();
                    }
                }
            } catch (ClassNotFoundException | SQLException e) {
                e.printStackTrace();
            } finally {
                try {
                    DatabaseConnection.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
