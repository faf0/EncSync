package server.database;

import java.nio.file.Paths;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.LinkedList;
import java.util.List;

import misc.FileHandler;
import misc.Logger;
import protocol.DataContainers;
import protocol.DataContainers.ActionData;
import protocol.DataContainers.ActionType;
import protocol.ServerProtocol;
import server.crypto.Authentication;
import configuration.ClientConfiguration;
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
 * Contains methods for inserting into the server database.
 * 
 * @author Fabian Foerg
 */
public final class DatabaseQueries {
    private static final Object GROUP_LOCK = new Object();
    private static final Object HISTORY_LOCK = new Object();
    /**
     * The group number of the public group in the group table.
     */
    private static final int PUBLIC_GROUP_NUMBER = -1;

    /**
     * Represents an entry of the database table file.
     * 
     * @author Fabian Foerg
     */
    public static final class FileEntry {
        private final String owner;
        private final String folder;
        private final String fileName;
        private final Timestamp modified;
        private final boolean isDiff;
        private final int version;
        private final long size;
        private final byte[] hash;
        private final int keyVersion;
        private final byte[] extra;
        private final byte[] mac;

        public FileEntry(String owner, String folder, String fileName,
                Timestamp modified, boolean isDiff, int version, long size,
                byte[] hash, int keyVersion, byte[] extra, byte[] mac) {
            if (!ClientConfiguration.isValidUserName(owner)) {
                throw new IllegalArgumentException("owner is not a valid name!");
            }
            if (folder == null) {
                throw new NullPointerException("folder may not be null!");
            }
            if ((fileName == null)
                    || !FileHandler.isFileName(Paths.get(fileName))) {
                throw new IllegalArgumentException(
                        "fileName is not a valid file name!");
            }
            if (modified == null) {
                throw new NullPointerException("modified may not be null!");
            }
            if (version < 1) {
                throw new IllegalArgumentException(
                        "version must be at least one!");
            }
            if (size < 0) {
                throw new IllegalArgumentException(
                        "size must be at least zero!");
            }
            if (hash == null) {
                throw new NullPointerException("hash may not be null!");
            }
            if ((keyVersion < 1)
                    && (keyVersion != DataContainers.PUBLIC_FILE_KEY_VERSION)) {
                throw new IllegalArgumentException(
                        "keyVersion must be at least one or the public key version!");
            }
            if ((mac == null)
                    && (keyVersion != DataContainers.PUBLIC_FILE_KEY_VERSION)) {
                throw new IllegalArgumentException(
                        "mac must not be null, if the key version is non-public!");
            }

            this.owner = owner;
            this.folder = folder;
            this.fileName = fileName;
            this.modified = modified;
            this.isDiff = isDiff;
            this.version = version;
            this.size = size;
            this.hash = hash;
            this.keyVersion = keyVersion;
            this.extra = extra;
            this.mac = mac;
        }

        public byte[] getExtra() {
            return extra;
        }

        public String getFileName() {
            return fileName;
        }

        public String getFolder() {
            return folder;
        }

        public byte[] getHash() {
            return hash;
        }

        public int getKeyVersion() {
            return keyVersion;
        }

        public byte[] getMAC() {
            return mac;
        }

        public Timestamp getModified() {
            return modified;
        }

        public String getOwner() {
            return owner;
        }

        public long getSize() {
            return size;
        }

        public int getVersion() {
            return version;
        }

        public boolean isDiff() {
            return isDiff;
        }
    }

    /**
     * Represents an entry of the database table folder.
     * 
     * @author Fabian Foerg
     */
    public static final class FolderEntry {
        private final String owner;
        private final String path;
        private final int keyVersion;
        private final int groupNo;

        public FolderEntry(String owner, String path, int keyVersion,
                int groupNo) {
            if (!ClientConfiguration.isValidUserName(owner)) {
                throw new IllegalArgumentException("owner is not a valid name!");
            }
            if ((path == null) || !FileHandler.isFolderName(Paths.get(path))) {
                throw new IllegalArgumentException(
                        "path must be a valid folder name!");
            }
            if ((keyVersion < 1)
                    && (keyVersion != DataContainers.PUBLIC_FILE_KEY_VERSION)) {
                throw new IllegalArgumentException(
                        "keyVersion must be at least one or the public key version!");
            }
            if ((groupNo < 0) && (PUBLIC_GROUP_NUMBER != groupNo)) {
                throw new IllegalArgumentException(
                        "groupNo must be at least zero or the public group number!");
            }

            this.owner = owner;
            this.path = path;
            this.keyVersion = keyVersion;
            this.groupNo = groupNo;
        }

        public int getGroupNo() {
            return groupNo;
        }

        public int getKeyVersion() {
            return keyVersion;
        }

        public String getOwner() {
            return owner;
        }

        public String getPath() {
            return path;
        }
    }

    /**
     * Deletes the given entry from the database table file.
     * 
     * @param id
     *            the id in the database of the file to delete.
     * @return <code>true</code>, if the file was successfully deleted.
     *         Otherwise, <code>false</code> is returned.
     */
    public static boolean deleteFile(int id) {
        boolean success = false;

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("DELETE FROM file WHERE id=?;");) {
            statement.setInt(1, id);
            success = true;
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return success;
    }

    /**
     * Returns whether a file with the given parameters exists.
     * 
     * @param owner
     *            the owner column entry.
     * @param folder
     *            the folder containing the file.
     * @param version
     *            the version of the file. Must be at least one.
     * @return <code>true</code>, if the file exists. Otherwise,
     *         <code>false</code> is returned.
     */
    public static boolean existsFileEntry(String owner, String folder,
            int version) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }
        if (version < 1) {
            throw new IllegalArgumentException("version must be at least one!");
        }

        Integer ownerNo = getUserNo(owner);
        boolean exists = false;

        if (ownerNo == null) {
            return exists;
        }

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("SELECT 1 FROM file WHERE owner=? AND folder=? AND version=?;");) {
            statement.setInt(1, ownerNo);
            statement.setString(2, folder);
            statement.setInt(3, version);
            ResultSet rs = statement.executeQuery();
            exists = rs.next();
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return exists;
    }

    /**
     * Returns whether the maximum version number of the given file, if it
     * exists on the server. If the file was deleted or renamed, <code>0</code>
     * is returned. The similar method <code>getMaxFileVersion</code> returns
     * the maximum version of the latest existing version with the given name.
     * 
     * @param owner
     *            the owner column entry.
     * @param folder
     *            the folder containing the file.
     * @param name
     *            the path of the file name relative to <code>folder</code>.
     * @return the latest version number, if the file exists. Otherwise, <code>0
     *         </code> is returned.
     */
    public static int existsFileEntry(String owner, String folder, String name) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }
        if ((name == null) || !FileHandler.isFileName(Paths.get(name))) {
            throw new IllegalArgumentException("name is not a valid file name!");
        }

        Integer ownerNo = getUserNo(owner);
        int result = 0;

        if (ownerNo == null) {
            return result;
        }

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("SELECT MAX(version),action,object1 FROM history WHERE owner=? AND folder=? AND (object1=? OR (action=? AND object2=?));");) {
            statement.setInt(1, ownerNo);
            statement.setString(2, folder);
            statement.setString(3, name);
            statement.setString(4, ActionType.RENAME.toString());
            statement.setString(5, name);
            ResultSet rs = statement.executeQuery();
            if (rs.next()) {
                String action = rs.getString(2);
                String object = rs.getString(3);

                /*
                 * If the file was neither deleted nor renamed, it exists.
                 */
                if (!(ActionType.DELETE.toString().equals(action) || (ActionType.RENAME
                        .toString().equals(action) && name.equals(object)))) {
                    result = rs.getInt(1);
                }
            }
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return result;
    }

    /**
     * Returns whether the user exists in the database.
     * 
     * @param userName
     *            the name of the user to look for.
     * @return <code>true</code>, if the user exists or if an error occurred.
     *         <code>false</code>, otherwise.
     */
    public static boolean existsUser(String userName) {
        if (!ClientConfiguration.isValidUserName(userName)) {
            throw new IllegalArgumentException("userName must be valid!");
        }

        boolean exists = true;

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("SELECT 1 FROM users WHERE user=?;");) {
            statement.setString(1, userName);
            ResultSet rs = statement.executeQuery();
            exists = rs.next();
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return exists;
    }

    /**
     * Returns the entry identified by the given candidate key values of the
     * table file or <code>null</code>, if the entry does not exist.
     * 
     * @param owner
     *            the owner of the file.
     * @param folder
     *            the folder containing the file.
     * @param name
     *            the path of the file name relative to <code>folder</code>.
     * @param version
     *            the version of the file. Returns the file with version v =
     *            max{v : v <= version}.
     * @return the entry identified by the given primary key values or
     *         <code>null</code>, if the entry does not exist.
     */
    public static FileEntry getFileEntry(String owner, String folder,
            String name, int version) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }
        if ((name == null) || !FileHandler.isFileName(Paths.get(name))) {
            throw new IllegalArgumentException("name is not a valid file name!");
        }
        if (version < 1) {
            throw new IllegalArgumentException("version must be at least one!");
        }

        Integer ownerNo = getUserNo(owner);

        if (ownerNo == null) {
            return null;
        }

        FileEntry entry = null;

        try (Connection connection = DatabaseConnection.getConnection();
                /*
                 * LIMIT is not an SQL standard and be changed for databases
                 * which do not support it.
                 */
                PreparedStatement statement = connection
                        .prepareStatement("SELECT modified,is_diff,size,hash,key_version,extra,mac FROM file WHERE owner=? AND folder=? AND name=? AND version<=? ORDER BY version DESC LIMIT 1;");) {
            statement.setInt(1, ownerNo);
            statement.setString(2, folder);
            statement.setString(3, name);
            statement.setInt(4, version);
            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                Timestamp modified = rs.getTimestamp("modified");
                boolean isDiff = rs.getBoolean("is_diff");
                long size = rs.getLong("size");
                byte[] hash = rs.getBytes("hash");
                int keyVersion = rs.getInt("key_version");
                byte[] extra = rs.getBytes("extra");
                byte[] mac = rs.getBytes("mac");
                entry = new FileEntry(owner, folder, name, modified, isDiff,
                        version, size, hash, keyVersion, extra, mac);
            }
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return entry;
    }

    /**
     * Returns the entry identified by the given primary key values of the table
     * folder or <code>null</code>, if the entry does not exist.
     * 
     * @param owner
     *            the owner of the folder.
     * @param path
     *            the path of the folder relative to the owner's root directory.
     * @return the entry identified by the given primary key values or
     *         <code>null</code>, if the entry does not exist.
     */
    public static FolderEntry getFolderEntry(String owner, String path) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (path == null) {
            throw new NullPointerException("path may not be null!");
        }

        Integer ownerNo = getUserNo(owner);

        if (ownerNo == null) {
            return null;
        }

        FolderEntry entry = null;

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("SELECT key_version,group_no FROM folder WHERE owner=? AND path=?;");) {
            statement.setInt(1, ownerNo);
            statement.setString(2, path);
            ResultSet rs = statement.executeQuery();
            if (rs.next()) {
                int keyVersion = rs.getInt(1);
                int groupNo = rs.getInt(2);
                entry = new FolderEntry(owner, path, keyVersion, groupNo);
            }
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return entry;
    }

    /**
     * Retrieves the history entries for the (owner, folder) combination,
     * starting from <code>version</code>.
     * 
     * @param owner
     *            the name of the owner.
     * @param folder
     *            the path of the owner.
     * @param version
     *            the minimum version number. Must be at least one.
     * @return a possibly empty array of history entries or <code>null</code>,
     *         if an error occurred.
     */
    public static ActionData[] getHistory(String owner, String folder,
            int version) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (folder == null) {
            throw new NullPointerException("path may not be null!");
        }
        if (version < 1) {
            throw new IllegalArgumentException("version must be at least one!");
        }

        Integer ownerNo = getUserNo(owner);

        if (ownerNo == null) {
            return null;
        }

        List<ActionData> responses = new LinkedList<ActionData>();

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("SELECT version,action,object1,object2 FROM history WHERE owner=? AND folder=? AND version>=? ORDER BY version ASC;");) {
            statement.setInt(1, ownerNo);
            statement.setString(2, folder);
            statement.setInt(3, version);
            ResultSet rs = statement.executeQuery();

            while (rs.next()) {
                int responseVersion = rs.getInt("version");
                ActionType responseAction = ActionType.fromChar(rs.getString(
                        "action").charAt(0));
                String responseObject;
                if (ActionType.RENAME.equals(responseAction)) {
                    responseObject = String.format("%s%s%s",
                            rs.getString("object1"),
                            ServerProtocol.Messages.HISTORY_OBJECT_DELIMITER,
                            rs.getString("object2"));
                } else {
                    responseObject = rs.getString("object1");
                }

                responses.add(new ActionData(responseVersion, responseAction,
                        responseObject));
            }
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return responses.toArray(new ActionData[0]);
    }

    /**
     * Returns the maximum version in the database table file for the given file
     * or <code>0</code>, if the file has never existed. Note that if the file
     * existed, but was deleted or renamed, the version number of the latest
     * existing version with the same name is returned.
     * 
     * @param owner
     *            the owner of the file.
     * @param folder
     *            the folder containing the file.
     * @param name
     *            the path of the file name relative to <code>folder</code>.
     * @return the maximum version or <code>0</code>, if the file does not
     *         exist.
     */
    public static int getMaxFileVersion(String owner, String folder, String name) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }
        if ((name == null) || !FileHandler.isFileName(Paths.get(name))) {
            throw new IllegalArgumentException("name is not a valid file name!");
        }

        Integer ownerNo = getUserNo(owner);

        if (ownerNo == null) {
            return 0;
        }

        int maxVersion = 0;

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("SELECT MAX(version) FROM file WHERE owner=? AND folder=? AND name=?;");) {
            statement.setInt(1, ownerNo);
            statement.setString(2, folder);
            statement.setString(3, name);
            ResultSet rs = statement.executeQuery();
            if (rs.next()) {
                maxVersion = rs.getInt(1);
            }
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return maxVersion;
    }

    /**
     * Returns the maximum group_no in the database table groups.
     * 
     * @param connection
     *            the connection to use.
     * @return the maximum group_no in groups or <code>0</code>, if groups does
     *         not contain any entries.
     */
    private static int getMaxGroupNo(Connection connection) {
        if (connection == null) {
            throw new NullPointerException("connection may not be null!");
        }

        int maxNo = 0;

        try (Statement statement = connection.createStatement();) {
            ResultSet rs = statement
                    .executeQuery("SELECT MAX(group_no) FROM groups");
            if (rs.next()) {
                maxNo = rs.getInt(1);
            }
        } catch (SQLException e) {
            Logger.logError(e);
        }

        return maxNo;
    }

    /**
     * Returns the maximum version number for the given folder.
     * 
     * @param owner
     *            the owner of the folder.
     * @param folder
     *            an upper-most directory name in the owner's root directory or
     *            <code>.</code> for the owner's root itself.
     * @return the maximum history and general version number for the given
     *         folder or <code>0</code> , if no version number was found.
     */
    public static int getMaxHistoryVersion(String owner, String folder) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }

        int maxVersion = 0;
        Integer ownerNo = getUserNo(owner);

        if (ownerNo == null) {
            return maxVersion;
        }

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("SELECT MAX(version) FROM history WHERE owner=? AND folder=?;");) {
            statement.setInt(1, ownerNo);
            statement.setString(2, folder);
            ResultSet rs = statement.executeQuery();
            if (rs.next()) {
                maxVersion = rs.getInt(1);
            }
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return maxVersion;
    }

    /**
     * Returns the associated permissions of this folder from the permission
     * table.
     * 
     * @param owner
     *            the owner of the given <code>folderName</code>.
     * @param folderName
     *            must be an upper-level directory, that is just a single folder
     *            name.
     * @return the associated permissions or <code>null</code>, if permissions
     *         are not known for the given folder or are private. Can be an
     *         array containing <code>Permission.PUBLIC</code>.
     */
    public static Permission[] getPermissions(String owner, String folderName) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (folderName == null) {
            throw new NullPointerException("");
        }

        Permission[] result = null;
        Integer ownerNo = getUserNo(owner);

        if (ownerNo == null) {
            return result;
        }

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statementGroupNo = connection
                        .prepareStatement("SELECT group_no FROM folder WHERE owner=? AND path=?;");) {
            statementGroupNo.setInt(1, ownerNo);
            statementGroupNo.setString(2, folderName);
            ResultSet rsGroupNo = statementGroupNo.executeQuery();

            if (rsGroupNo.next()) {
                int groupNo = rsGroupNo.getInt(1);

                if (groupNo == PUBLIC_GROUP_NUMBER) {
                    result = new Permission[] { Permission.PUBLIC };
                } else if (groupNo != 0) {
                    List<Permission> permissionList = new LinkedList<Permission>();
                    try (PreparedStatement statementPermissions = connection
                            .prepareStatement("SELECT member,permission FROM groups WHERE group_no=?;");) {
                        statementPermissions.setInt(1, groupNo);
                        ResultSet rsPermissions = statementPermissions
                                .executeQuery();

                        while (rsPermissions.next()) {
                            String userName = getUser(connection,
                                    rsPermissions.getInt("member"));
                            String permission = rsPermissions
                                    .getString("permission");
                            permissionList.add(new Permission(userName,
                                    PermissionValue.fromString(permission)));
                        }

                        if (!permissionList.isEmpty()) {
                            result = permissionList.toArray(new Permission[0]);
                        }
                    } catch (SQLException e) {
                        Logger.logError(e);
                    }
                }
            }
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return result;
    }

    /**
     * Returns the user name of a given user number in the database table users.
     * 
     * @param connection
     *            the connection to use.
     * @param userNo
     *            the user number
     * @return <code>null</code>, if the user number does not exist. The user
     *         name otherwise.
     */
    private static String getUser(Connection connection, int userNo) {
        if (connection == null) {
            throw new NullPointerException("connection may not be null!");
        }

        String user = null;

        try (PreparedStatement statement = connection
                .prepareStatement("SELECT user FROM users WHERE id=?;");) {
            statement.setInt(1, userNo);
            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                user = rs.getString(1);
            }
        } catch (SQLException e) {
            Logger.logError(e);
        }

        return user;
    }

    /**
     * Returns the id of a user in the database table users.
     * 
     * @param user
     *            the user name.
     * @return <code>null</code>, if the user does not exist. The id otherwise.
     */
    private static Integer getUserNo(String user) {
        if (!ClientConfiguration.isValidUserName(user)) {
            throw new IllegalArgumentException("user may not be null!");
        }

        Integer userNo = null;

        try (Connection connection = DatabaseConnection.getConnection();) {
            userNo = getUserNo(connection, user);
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return userNo;
    }

    /**
     * Returns the id of a user in the database table users.
     * 
     * @param connection
     *            the connection to use.
     * @param user
     *            the user name.
     * @return <code>null</code>, if the user does not exist. The id otherwise.
     */
    private static Integer getUserNo(Connection connection, String user) {
        if (connection == null) {
            throw new NullPointerException("connection may not be null!");
        }
        if (!ClientConfiguration.isValidUserName(user)) {
            throw new IllegalArgumentException("user may not be null!");
        }

        Integer userNo = null;

        try (PreparedStatement statement = connection
                .prepareStatement("SELECT id FROM users WHERE user=?;");) {
            statement.setString(1, user);
            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                userNo = rs.getInt(1);
            }
        } catch (SQLException e) {
            Logger.logError(e);
        }

        return userNo;
    }

    /**
     * Inserts the given entry into the database tables file and history.
     * 
     * @param owner
     *            the owner to insert into file and history.
     * @param folder
     *            the folder containing the file.
     * @param name
     *            the path of the file name relative to <code>folder</code>.
     * @param modified
     *            the timestamp to insert into file.
     * @param keyVersion
     *            the key version to insert into file.
     * @param isDiff
     *            the is_diff to insert into file.
     * @param hash
     *            the hash to insert into file.
     * @param size
     *            the size to insert into file.
     * @param extra
     *            the extra protected data value to insert into file. May be
     *            <code>null</code>.
     * @param mac
     *            the mac to insert into file.
     * @param historyTime
     *            the timestamp to insert into history.
     * @param char the action to insert into history.
     * @param object1
     *            the first object of the action.
     * @param object2
     *            the second object of the action. Must be <code>null</code>, if
     *            the action is not R.
     * @param proposedVersion
     *            a proposal for the version number. The proposed version number
     *            is compared to the version number internally created by this
     *            method and the entries are only inserted, if the version
     *            numbers match. May be <code>null</code>, if the version should
     *            be computed internally in this method.
     * @return <code>true</code>, if the entries were successfully inserted.
     *         Otherwise, <code>false</code>.
     */
    public static boolean insertFileAndHistory(String owner, String folder,
            String name, Timestamp modified, int keyVersion, boolean isDiff,
            byte[] hash, long size, byte[] extra, byte[] mac,
            Timestamp historyTime, char action, String object1, String object2,
            Integer proposedVersion) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }
        if ((name == null) || !FileHandler.isFileName(Paths.get(name))) {
            throw new IllegalArgumentException("name is not a valid file name!");
        }
        if (modified == null) {
            throw new IllegalArgumentException("timestamp may not be null!");
        }
        if ((keyVersion < 1)
                && (keyVersion != DataContainers.PUBLIC_FILE_KEY_VERSION)) {
            throw new IllegalArgumentException(
                    "keyVersion must be at least one or the public key version!");
        }
        if (hash == null) {
            throw new IllegalArgumentException("hash may not be null!");
        }
        if ((mac == null)
                && (keyVersion != DataContainers.PUBLIC_FILE_KEY_VERSION)) {
            throw new IllegalArgumentException(
                    "mac must not be null, if the key version is non-public!");
        }
        if (historyTime == null) {
            throw new IllegalArgumentException("historyTime may not be null!");
        }
        if (ActionType.fromChar(action) == null) {
            throw new IllegalArgumentException("action is not valid!");
        }
        if ((object1 == null) || object1.isEmpty()) {
            throw new IllegalArgumentException(
                    "object1 may not be null or empty!");
        }
        if ((ActionType.fromChar(action).equals(ActionType.RENAME) && ((object2 == null) || object2
                .isEmpty()))
                || (!ActionType.fromChar(action).equals(ActionType.RENAME) && (object2 != null))) {
            throw new IllegalArgumentException(
                    "object2 is not appropriately combined with action!");
        }

        Integer ownerNo = getUserNo(owner);
        boolean success = false;

        if (ownerNo == null) {
            return success;
        }

        Connection connection = null;
        PreparedStatement statement = null;

        synchronized (HISTORY_LOCK) {
            int version = getMaxHistoryVersion(owner, folder) + 1;

            if ((proposedVersion != null) && (proposedVersion != version)) {
                return success;
            }

            try {
                connection = DatabaseConnection.getDedicatedConnection();
                connection.setAutoCommit(false);
                statement = connection
                        .prepareStatement("INSERT INTO file "
                                + "(id, owner, folder, name, modified, key_version, is_diff, hash, version, size, extra, mac) "
                                + "VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
                statement.setInt(1, ownerNo);
                statement.setString(2, folder);
                statement.setString(3, name);
                statement.setTimestamp(4, modified);
                statement.setInt(5, keyVersion);
                statement.setBoolean(6, isDiff);
                statement.setBytes(7, hash);
                statement.setInt(8, version);
                statement.setLong(9, size);
                if (extra != null) {
                    statement.setBytes(10, extra);
                } else {
                    statement.setNull(10, Types.VARBINARY);
                }
                if (mac != null) {
                    statement.setBytes(11, mac);
                } else {
                    statement.setNull(11, Types.VARBINARY);
                }
                statement.executeUpdate();
                boolean successInsertHistory = insertHistory(connection,
                        ownerNo, version, folder, historyTime, action, object1,
                        object2);

                if (successInsertHistory) {
                    connection.commit();
                    success = true;
                } else {
                    connection.rollback();
                }
            } catch (ClassNotFoundException | SQLException e) {
                Logger.logError(e);

                if (connection != null) {
                    try {
                        connection.rollback();
                    } catch (SQLException eInner) {
                        Logger.logError(eInner);
                    }
                }
            } finally {
                if (statement != null) {
                    try {
                        statement.close();
                    } catch (SQLException e) {
                        Logger.logError(e);
                    }
                }
                if (connection != null) {
                    try {
                        connection.close();
                    } catch (SQLException e) {
                        Logger.logError(e);
                    }
                }
            }
        }

        return success;
    }

    /**
     * Inserts the given entry into the database table folder.
     * 
     * @param owner
     *            the owner to insert.
     * @param path
     *            the path to insert.
     * @param permissions
     *            the permissions to insert. May be <code>null</code>.
     * @param keyVersion
     *            the minimum allowed key version number. Must be at least one
     *            or <code>DataContainers.PUBLIC_FILE_KEY_VERSION</code> for
     *            public files.
     * @return <code>true</code>, if the folder entry was successfully created.
     *         Otherwise, <code>false</code> is returned.
     */
    public static boolean insertFolder(String owner, String path,
            Permission[] permissions, int keyVersion) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (path == null) {
            throw new IllegalArgumentException("path may not be null!");
        }
        if ((keyVersion < 1)
                && (keyVersion != DataContainers.PUBLIC_FILE_KEY_VERSION)) {
            throw new IllegalArgumentException(
                    "keyVersion must be at least one or the public key version!");
        }

        boolean success = false;
        Integer ownerNo = getUserNo(owner);

        if (ownerNo == null) {
            return success;
        }

        Connection connection = null;
        PreparedStatement statement = null;

        try {
            boolean partialSuccess = false;
            connection = DatabaseConnection.getDedicatedConnection();
            connection.setAutoCommit(false);
            statement = connection.prepareStatement("INSERT INTO folder "
                    + "(id, owner, path, key_version, group_no) "
                    + "VALUES (NULL, ?, ?, ?, ?);");
            statement.setInt(1, ownerNo);
            statement.setString(2, path);
            statement.setInt(3, keyVersion);
            if ((permissions == null) || (permissions.length < 1)) {
                statement.setNull(4, Types.INTEGER);
                partialSuccess = true;
            } else if (Permission.PUBLIC.equals(permissions[0])) {
                // public has a default group number
                statement.setInt(4, PUBLIC_GROUP_NUMBER);
                partialSuccess = true;
            } else {
                Integer groupNo = insertGroup(connection, permissions);

                if (groupNo != null) {
                    statement.setInt(4, groupNo);
                    partialSuccess = true;
                }
            }

            if (partialSuccess) {
                statement.executeUpdate();
                connection.commit();
                success = true;
            } else {
                connection.rollback();
            }
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);

            if (connection != null) {
                try {
                    connection.rollback();
                } catch (SQLException eInner) {
                    Logger.logError(eInner);
                }
            }
        } finally {
            if (statement != null) {
                try {
                    statement.close();
                } catch (SQLException e) {
                    Logger.logError(e);
                }
            }
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException e) {
                    Logger.logError(e);
                }
            }
        }

        return success;
    }

    /**
     * Inserts the given member permissions into the database table group. Is
     * synchronized in order to ensure that the group numbers are unique.
     * 
     * @param connection
     *            the database connection to use. Must not be in auto-commit
     *            mode.
     * @param permissions
     *            the permissions to insert.
     * @return the group number of the inserted group or <code>null</code>, if
     *         not every member was successfully inserted.
     */
    private static Integer insertGroup(Connection connection,
            Permission[] permissions) {
        try {
            if ((connection == null) || connection.getAutoCommit()) {
                throw new IllegalArgumentException(
                        "connection may not be null!");
            }
        } catch (SQLException e) {
            Logger.logError(e);
            throw new IllegalArgumentException(
                    "connection must not be in auto-commit mode!");
        }
        if (permissions == null) {
            throw new IllegalArgumentException("permissions may not be null!");
        }
        if (permissions.length < 1) {
            throw new IllegalArgumentException(
                    "permissions must have at least length one!");
        }

        int inserted = 0;
        int groupNo;

        synchronized (GROUP_LOCK) {
            groupNo = getMaxGroupNo(connection) + 1;

            try (PreparedStatement statement = connection
                    .prepareStatement("INSERT INTO groups "
                            + "(id, group_no, member, permission) "
                            + "VALUES (NULL, ?, ?, ?);");) {
                statement.setInt(1, groupNo);

                for (Permission permission : permissions) {
                    Integer userNo = getUserNo(connection,
                            permission.getMember());

                    if (userNo != null) {
                        statement.setInt(2, userNo);
                        statement.setString(3, permission.getPermissions()
                                .toString());
                        statement.executeUpdate();
                        inserted++;
                    } else {
                        break;
                    }
                }
            } catch (SQLException e) {
                Logger.logError(e);
            }
        }

        return (inserted == permissions.length) ? groupNo : null;
    }

    /**
     * Inserts the given entry into the database table history.
     * 
     * @param connection
     *            the connection to use.
     * @param ownerNo
     *            the owner ID to insert.
     * @param historyVersion
     *            the history version to insert.
     * @param folder
     *            the corresponding folder of the owner.
     * @param time
     *            the timestamp of the action.
     * @param action
     *            the action type.
     * @param object1
     *            the first object of the action.
     * @param object2
     *            the second object of the action. Must be <code>null</code>, if
     *            the action is not R.
     * @return <code>true</code>, if the folder entry was successfully created.
     *         Otherwise, <code>false</code> is returned.
     */
    private static boolean insertHistory(Connection connection, int ownerNo,
            int historyVersion, String folder, Timestamp time, char action,
            String object1, String object2) {
        if (connection == null) {
            throw new IllegalArgumentException("connection may not be null!");
        }
        if (ownerNo < 1) {
            throw new IllegalArgumentException("ownerNo must be valid!");
        }
        if (historyVersion < 1) {
            throw new IllegalArgumentException("historyVersion must be valid!");
        }
        if (folder == null) {
            throw new IllegalArgumentException("folder may not be null!");
        }
        if (time == null) {
            throw new IllegalArgumentException("time may not be null!");
        }
        if (ActionType.fromChar(action) == null) {
            throw new IllegalArgumentException("action is not valid!");
        }
        if ((object1 == null) || object1.isEmpty()) {
            throw new IllegalArgumentException(
                    "object1 may not be null or empty!");
        }
        if ((ActionType.fromChar(action).equals(ActionType.RENAME) && ((object2 == null) || object2
                .isEmpty()))
                || (!ActionType.fromChar(action).equals(ActionType.RENAME) && (object2 != null))) {
            throw new IllegalArgumentException(
                    "object2 is not appropriately combined with action!");
        }

        boolean success = false;

        try (PreparedStatement statement = connection
                .prepareStatement("INSERT INTO history "
                        + "(id, owner, folder, version, time, action, object1, object2) "
                        + "VALUES (NULL, ?, ?, ?, ?, ?, ?, ?);");) {
            statement.setInt(1, ownerNo);
            statement.setString(2, folder);
            statement.setInt(3, historyVersion);
            statement.setTimestamp(4, time);
            statement.setString(5, String.valueOf(action));
            statement.setString(6, object1);
            if (object2 == null) {
                statement.setNull(7, Types.VARCHAR);
            } else {
                statement.setString(7, object2);
            }
            statement.executeUpdate();
            success = true;
        } catch (SQLException e) {
            Logger.logError(e);
        }

        return success;
    }

    /**
     * Inserts the given entry into the database table history.
     * 
     * @param owner
     *            the owner to insert.
     * @param folder
     *            the corresponding folder of the owner.
     * @param version
     *            the version of the action.
     * @param time
     *            the timestamp of the action.
     * @param action
     *            the action type.
     * @param object1
     *            the first object of the action.
     * @param object2
     *            the second object of the action. Must be <code>null</code>, if
     *            the action is not R.
     * @return <code>true</code>, if the folder entry was successfully created.
     *         Otherwise, <code>false</code> is returned.
     */
    public static boolean insertHistory(String owner, String folder,
            Timestamp time, char action, String object1, String object2) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (folder == null) {
            throw new IllegalArgumentException("folder may not be null!");
        }
        if (time == null) {
            throw new IllegalArgumentException("time may not be null!");
        }
        if (ActionType.fromChar(action) == null) {
            throw new IllegalArgumentException("action is not valid!");
        }
        if ((object1 == null) || object1.isEmpty()) {
            throw new IllegalArgumentException(
                    "object1 may not be null or empty!");
        }
        if ((ActionType.fromChar(action).equals(ActionType.RENAME) && ((object2 == null) || object2
                .isEmpty()))
                || (!ActionType.fromChar(action).equals(ActionType.RENAME) && (object2 != null))) {
            throw new IllegalArgumentException(
                    "object2 is not appropriately combined with action!");
        }

        Integer ownerNo = getUserNo(owner);

        if (ownerNo == null) {
            return false;
        }

        boolean success = false;

        synchronized (HISTORY_LOCK) {
            int historyVersion = getMaxHistoryVersion(owner, folder) + 1;

            try (Connection connection = DatabaseConnection.getConnection();) {
                success = insertHistory(connection, ownerNo, historyVersion,
                        folder, time, action, object1, object2);
            } catch (ClassNotFoundException | SQLException e) {
                Logger.logError(e);
            }
        }

        return success;
    }

    /**
     * Stores the given user name along with its password in the server
     * database. The password is salted with random bytes and hashed before the
     * it is persistently stored.
     * 
     * @param userName
     *            the name of the user to store.
     * @param plainTextPassword
     *            the plain text password.
     * @return <code>true</code>, if the user was successfully created.
     *         Otherwise, <code>false</code>.
     */
    public static boolean insertUser(String userName, String plainTextPassword) {
        if (!ClientConfiguration.isValidUserName(userName)) {
            throw new IllegalArgumentException("userName must be valid!");
        }
        if (!ClientConfiguration.isValidPassword(plainTextPassword)) {
            throw new IllegalArgumentException(
                    "plainTextPassword must be valid!");
        }

        boolean success = false;

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("INSERT INTO users (id, user, salted_hash, salt) "
                                + "VALUES (NULL, ?, ?, ?);");) {
            byte[] salt = new byte[8];
            new SecureRandom().nextBytes(salt);
            byte[] saltedHash = Authentication.createSaltedHash(
                    plainTextPassword, salt);
            statement.setString(1, userName);
            statement.setBytes(2, saltedHash);
            statement.setBytes(3, salt);
            statement.executeUpdate();
            success = true;
        } catch (Exception e) {
            Logger.logError(e);
        }

        return success;
    }

    /**
     * Returns whether the given folder is shared. A public folder is shared by
     * definition.
     * 
     * @param the
     *            owner of the folder
     * @param folderName
     *            an upper-most directory name in the owner's root directory.
     * @return <code>true</code>, if the given folder is shared. Otherwise, that
     *         is when the folder is private or unknown, <code>false</code> is
     *         returned.
     */
    public static boolean isSharedFolder(String owner, String folderName) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (folderName == null) {
            throw new NullPointerException("");
        }

        Integer ownerNo = getUserNo(owner);

        if (ownerNo == null) {
            return false;
        }

        boolean isShared = false;

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("SELECT group_no FROM folder WHERE owner=? AND path=?;");) {
            statement.setInt(1, ownerNo);
            statement.setString(2, folderName);
            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                int groupNo = rs.getInt(1);
                // groupNo equals NULL for private folders.
                isShared = (groupNo >= 1) || (PUBLIC_GROUP_NUMBER == groupNo);
            }
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);
        }

        return isShared;
    }

    /**
     * Updates the given folder entry.
     * 
     * @param owner
     *            the owner of the folder.
     * @param path
     *            the path of the folder.
     * @param keyVersion
     *            the minimum allowed key version for the folder.
     * @param permissions
     *            the new permissions. May be <code>null</code>.
     * @return <code>true</code>, if the folder entry was successfully created.
     *         Otherwise, <code>false</code> is returned.
     */
    public static boolean updateFolder(String owner, String path,
            int keyVersion, Permission[] permissions) {
        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if (path == null) {
            throw new IllegalArgumentException("path may not be null!");
        }
        if ((keyVersion < 1)
                && (keyVersion != DataContainers.PUBLIC_FILE_KEY_VERSION)) {
            throw new IllegalArgumentException(
                    "keyVersion must be at least one or the public key version!");
        }

        boolean success = false;
        Integer ownerNo = getUserNo(owner);

        if (ownerNo == null) {
            return success;
        }

        Connection connection = null;
        PreparedStatement statement = null;

        try {
            boolean partialSuccess = false;
            connection = DatabaseConnection.getDedicatedConnection();
            connection.setAutoCommit(false);
            statement = connection
                    .prepareStatement("UPDATE folder SET key_version=?, group_no=? WHERE owner=? AND path=?;");

            statement.setInt(1, keyVersion);
            statement.setInt(3, ownerNo);
            statement.setString(4, path);

            if ((permissions == null) || (permissions.length < 1)) {
                statement.setNull(2, Types.INTEGER);
                partialSuccess = true;
            } else if (Permission.PUBLIC.equals(permissions[0])) {
                // public has a default group number
                statement.setInt(2, PUBLIC_GROUP_NUMBER);
                partialSuccess = true;
            } else {
                Integer groupNo = insertGroup(connection, permissions);

                if (groupNo != null) {
                    statement.setInt(2, groupNo);
                    partialSuccess = true;
                }
            }

            if (partialSuccess) {
                statement.executeUpdate();
                connection.commit();
                success = true;
            } else {
                connection.rollback();
            }
        } catch (ClassNotFoundException | SQLException e) {
            Logger.logError(e);

            if (connection != null) {
                try {
                    connection.rollback();
                } catch (SQLException eInner) {
                    Logger.logError(eInner);
                }
            }
        } finally {
            if (statement != null) {
                try {
                    statement.close();
                } catch (SQLException e) {
                    Logger.logError(e);
                }
            }
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException e) {
                    Logger.logError(e);
                }
            }
        }

        return success;
    }

    /**
     * Updates the given user name along with its password in the server
     * database. The password is salted with random bytes and hashed before the
     * it is persistently stored.
     * 
     * @param userName
     *            the name of the user to store.
     * @param plainTextPassword
     *            the plain text password.
     * @return <code>true</code>, if the user was successfully updated.
     *         Otherwise, <code>false</code>.
     */
    public static boolean updatetUser(String userName, String plainTextPassword) {
        if (!ClientConfiguration.isValidUserName(userName)) {
            throw new IllegalArgumentException("userName must be valid!");
        }
        if (!ClientConfiguration.isValidPassword(plainTextPassword)) {
            throw new IllegalArgumentException(
                    "plainTextPassword must be valid!");
        }

        boolean success = false;
        Integer userNo = getUserNo(userName);

        if (userNo == null) {
            return success;
        }

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("UPDATE users SET user=?, salted_hash=?, salt=? "
                                + "WHERE id=?;");) {
            byte[] salt = new byte[8];
            new SecureRandom().nextBytes(salt);
            byte[] saltedHash = Authentication.createSaltedHash(
                    plainTextPassword, salt);
            statement.setString(1, userName);
            statement.setBytes(2, saltedHash);
            statement.setBytes(3, salt);
            statement.setInt(4, userNo);
            statement.executeUpdate();
            success = true;
        } catch (Exception e) {
            Logger.logError(e);
        }

        return success;
    }

    /**
     * Hidden constructor.
     */
    private DatabaseQueries() {
    }
}
