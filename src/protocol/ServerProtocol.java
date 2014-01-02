package protocol;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.StringTokenizer;

import misc.Coder;
import misc.FileHandler;
import misc.Logger;
import protocol.DataContainers.ActionData;
import protocol.DataContainers.DeleteFileData;
import protocol.DataContainers.GetFileData;
import protocol.DataContainers.GetMetadataData;
import protocol.DataContainers.GetMetadataResponseData;
import protocol.DataContainers.GetSyncData;
import protocol.DataContainers.Pair;
import protocol.DataContainers.PostMoveData;
import protocol.DataContainers.PutAuthData;
import protocol.DataContainers.PutFileData;
import protocol.DataContainers.PutFolderData;
import configuration.Permission;

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
 * Server protocol messages are created here. Additionally, client messages are
 * parsed in this class.
 * 
 * @author Fabian Foerg
 */
public final class ServerProtocol {
    /**
     * Interface and constants for server messages.
     * 
     * @author Fabian Foerg
     */
    public interface Messages {
        /**
         * Server message delimiter.
         */
        public static final byte[] DELIMITER = ClientProtocol.Messages.DELIMITER;

        /**
         * Parameter delimiter.
         */
        public static final String PARAMETER_DELIMITER = ClientProtocol.Messages.PARAMETER_DELIMITER;

        /**
         * Key/value delimiter.
         */
        public static final String KEY_VALUE_DELIMITER = ClientProtocol.Messages.KEY_VALUE_DELIMITER;
        /**
         * Delimiter for multiple arguments in the object field of history
         * messages.
         */
        public static final String HISTORY_OBJECT_DELIMITER = "\t";

        public String getKey();

        /**
         * Returns the delimited key.
         * 
         * @return the delimited key.
         */
        @Override
        public String toString();

        /**
         * Returns the length of the key plus the length of the key-value
         * delimiter.
         * 
         * @return the length of the key plus the length of the key-value
         *         delimiter.
         */
        public int length();
    }

    /**
     * All server message types.
     * 
     * @author Fabian Foerg
     */
    public static enum MessageType {
        UNKNOWN(ClientProtocol.MessageType.UNKNOWN, false),
        SUCCESS_POST_AUTH(ClientProtocol.MessageType.POST_AUTH),
        FAIL_POST_AUTH_PARSE(
                ClientProtocol.MessageType.POST_AUTH,
                "PARSE ERROR"),
        FAIL_POST_AUTH_VALIDITY(
                ClientProtocol.MessageType.POST_AUTH,
                "DATA INVALID"),
        FAIL_POST_AUTH_MISSING(ClientProtocol.MessageType.POST_AUTH, "MISSING"),
        SUCCESS_PUT_AUTH(ClientProtocol.MessageType.PUT_AUTH),
        FAIL_PUT_AUTH_PARSE(ClientProtocol.MessageType.PUT_AUTH, "PARSE ERROR"),
        FAIL_PUT_AUTH_VALIDITY(
                ClientProtocol.MessageType.PUT_AUTH,
                "DATA INVALID"),
        FAIL_PUT_AUTH_DB_ERROR(ClientProtocol.MessageType.PUT_AUTH, "DB ERROR"),
        SUCCESS_PUT_FOLDER(ClientProtocol.MessageType.PUT_FOLDER),
        FAIL_PUT_FOLDER_PARSE(
                ClientProtocol.MessageType.PUT_FOLDER,
                "PARSE ERROR"),
        FAIL_PUT_FOLDER_NAME(
                ClientProtocol.MessageType.PUT_FOLDER,
                "NAME FORMAT INVALID"),
        FAIL_PUT_FOLDER_DB_ERROR(
                ClientProtocol.MessageType.PUT_FOLDER,
                "DB ERROR"),
        FAIL_PUT_FOLDER_PERMISSION(
                ClientProtocol.MessageType.PUT_FOLDER,
                "PERMISSION DENIED"),
        SUCCESS_PUT_FILE(ClientProtocol.MessageType.PUT_FILE),
        /*
         * Proper identification requires that no message string is a substring
         * of another string.
         */
        SUCCESS_PUT_FILE_REQUEST(ClientProtocol.MessageType.PUT_FILE_REQUEST),
        FAIL_PUT_FILE_CONNECTION_LOCKED(
                ClientProtocol.MessageType.PUT_FILE,
                "CONNECTION LOCK PRESENT"),
        FAIL_PUT_FILE_PARSE(ClientProtocol.MessageType.PUT_FILE, "PARSE ERROR"),
        FAIL_PUT_FILE_HASH_INVALID(
                ClientProtocol.MessageType.PUT_FILE,
                "HASH INVALID"),
        FAIL_PUT_FILE_DB_ERROR(ClientProtocol.MessageType.PUT_FILE, "DB ERROR"),
        FAIL_PUT_FILE_PERMISSION(
                ClientProtocol.MessageType.PUT_FILE,
                "PERMISSION DENIED"),
        FAIL_PUT_FILE_INVALID_PATH(
                ClientProtocol.MessageType.PUT_FILE,
                "INVALID PATH"),
        FAIL_PUT_FILE_KEY_VERSION_TOO_LOW(
                ClientProtocol.MessageType.PUT_FILE,
                "KEY VERSION TOO LOW"),
        SUCCESS_GET_METADATA(ClientProtocol.MessageType.GET_METADATA),
        FAIL_GET_METADATA_PARSE(
                ClientProtocol.MessageType.GET_METADATA,
                "PARSE ERROR"),
        FAIL_GET_METADATA_PERMISSION(
                ClientProtocol.MessageType.GET_METADATA,
                "PERMISSION DENIED"),
        FAIL_GET_METADATA_NON_EXISTING(
                ClientProtocol.MessageType.GET_METADATA,
                "FILE DOES NOT EXIST"),
        SUCCESS_GET_FILE(ClientProtocol.MessageType.GET_FILE),
        FAIL_GET_FILE_PARSE(ClientProtocol.MessageType.GET_FILE, "PARSE ERROR"),
        FAIL_GET_FILE_PERMISSION(
                ClientProtocol.MessageType.GET_FILE,
                "PERMISSION DENIED"),
        FAIL_GET_FILE_NON_EXISTING(
                ClientProtocol.MessageType.GET_FILE,
                "FILE DOES NOT EXIST"),
        SUCCESS_GET_SYNC(ClientProtocol.MessageType.GET_SYNC),
        FAIL_GET_SYNC_PARSE(ClientProtocol.MessageType.GET_SYNC, "PARSE ERROR"),
        FAIL_GET_SYNC_PERMISSION(
                ClientProtocol.MessageType.GET_SYNC,
                "PERMISSION DENIED"),
        FAIL_GET_SYNC_NON_EXISTING(
                ClientProtocol.MessageType.GET_SYNC,
                "FOLDER DOES NOT EXIST"),
        FAIL_GET_SYNC_DB_ERROR(ClientProtocol.MessageType.GET_SYNC, "DB ERROR"),
        FAIL_GET_SYNC_SERVER_LOCKED(
                ClientProtocol.MessageType.GET_SYNC,
                "SERVER LOCK PRESENT"),
        FAIL_GET_SYNC_CONNECTION_LOCKED(
                ClientProtocol.MessageType.GET_SYNC,
                "CONNECTION LOCK PRESENT"),
        SUCCESS_POST_MOVE(ClientProtocol.MessageType.POST_MOVE),
        FAIL_POST_MOVE_CONNECTION_LOCKED(
                ClientProtocol.MessageType.POST_MOVE,
                "CONNECTION LOCK PRESENT"),
        FAIL_POST_MOVE_PARSE(
                ClientProtocol.MessageType.POST_MOVE,
                "PARSE ERROR"),
        FAIL_POST_MOVE_DB_ERROR(
                ClientProtocol.MessageType.POST_MOVE,
                "DB ERROR"),
        FAIL_POST_MOVE_PERMISSION(
                ClientProtocol.MessageType.POST_MOVE,
                "PERMISSION DENIED"),
        FAIL_POST_MOVE_NON_EXISTING(
                ClientProtocol.MessageType.POST_MOVE,
                "FILE/FOLDER DOES NOT EXIST"),
        SUCCESS_DELETE_FILE(ClientProtocol.MessageType.DELETE_FILE),
        FAIL_DELETE_FILE_CONNECTION_LOCKED(
                ClientProtocol.MessageType.DELETE_FILE,
                "CONNECTION LOCK PRESENT"),
        FAIL_DELETE_FILE_PARSE(
                ClientProtocol.MessageType.DELETE_FILE,
                "PARSE ERROR"),
        FAIL_DELETE_FILE_DB_ERROR(
                ClientProtocol.MessageType.DELETE_FILE,
                "DB ERROR"),
        FAIL_DELETE_FILE_PERMISSION(
                ClientProtocol.MessageType.DELETE_FILE,
                "PERMISSION DENIED"),
        FAIL_DELETE_FILE_NON_EXISTING(
                ClientProtocol.MessageType.DELETE_FILE,
                "FILE/FOLDER DOES NOT EXIST");

        public static final String SUCCESS_PREFIX = "SUCCESS";
        public static final String FAIL_PREFIX = "FAIL";

        private final ClientProtocol.MessageType messageType;
        private final boolean success;
        private final String failMessage;

        private MessageType(ClientProtocol.MessageType messageType) {
            assert (messageType != null);

            this.success = true;
            this.messageType = messageType;
            this.failMessage = "";
        }

        private MessageType(ClientProtocol.MessageType messageType,
                String failMessage) {
            assert (messageType != null) && (failMessage != null);

            this.success = false;
            this.messageType = messageType;
            this.failMessage = failMessage;
        }

        private MessageType(ClientProtocol.MessageType messageType,
                boolean success) {
            assert (messageType != null);

            this.success = success;
            this.messageType = messageType;
            this.failMessage = "";
        }

        public String getMessage() {
            return messageType.getMessage();
        }

        public String getAllAsString() {
            return success ? String.format("%s %s", SUCCESS_PREFIX,
                    messageType.getMessage()) : String.format("%s %s %s",
                    FAIL_PREFIX, messageType.getMessage(), failMessage);
        }

        public byte[] getAllAsBytes() {
            StringBuilder completeMessage = new StringBuilder(getAllAsString()
                    .length() + Messages.DELIMITER.length);
            completeMessage.append(getAllAsString());
            completeMessage.append(Coder.byteToString(Messages.DELIMITER));
            return Coder.stringToByte(completeMessage.toString());
        }

        public boolean equals(byte[] message) {
            if (message == null) {
                return false;
            }

            return Coder.startsWith(message, getAllAsString());
        }

        @Override
        public String toString() {
            return getAllAsString();
        }

        public static MessageType identify(String message) {
            if (message == null) {
                throw new NullPointerException("message may not be null!");
            }

            MessageType result = UNKNOWN;

            for (MessageType type : MessageType.values()) {
                if (message.startsWith(type.getAllAsString())) {
                    result = type;
                    break;
                }
            }

            return result;
        }
    }

    /**
     * Hidden constructor.
     */
    private ServerProtocol() {
    }

    /**
     * Parses the first bytes of the message and returns the identified message
     * type or <code>null</code>, if the message type is unknown.
     * 
     * @param message
     *            the message to parse.
     * @param length
     *            the length of the message in bytes.
     * @return the message type or <code>null</code>, if the message type is
     *         unknown.
     */
    public static ServerProtocol.MessageType identifyResponse(byte[] message,
            int length) {
        if (message == null) {
            throw new IllegalArgumentException("message may not be null!");
        }
        if (length < 1) {
            return MessageType.UNKNOWN;
        }

        return MessageType.identify(Coder.byteToString(message, 0, length));
    }

    /**
     * Parses a client POST auth request and returns a (user name, password)
     * pair or <code>null</code>, if the request is invalid.
     * 
     * @param message
     *            the client request.
     * @param length
     *            the length of the message in bytes.
     * @return <code>null</code>, if the request is invalid. Otherwise, a (user
     *         name, password) pair is returned.
     */
    public static Pair<String, String> postAuth(byte[] message, int length) {
        String messageString = Coder.byteToString(message, 0, length);
        StringTokenizer tokenizer = new StringTokenizer(messageString,
                ClientProtocol.Messages.PARAMETER_DELIMITER);
        String user = null;
        String password = null;

        if ((message == null) || (length < 0)) {
            return null;
        }

        if (!tokenizer.hasMoreTokens()
                || !ClientProtocol.MessageType.POST_AUTH.getMessage().equals(
                        tokenizer.nextToken())) {
            return null;
        }

        while (tokenizer.hasMoreElements()) {
            String nextToken = tokenizer.nextToken();
            ClientProtocol.Messages_PUT_auth parameter = ClientProtocol.Messages_PUT_auth
                    .identify(nextToken);

            if (parameter == null) {
                break;
            }

            switch (parameter) {
            case AUTH_USER:
                try {
                    user = Coder
                            .decodeBASE64asString(nextToken
                                    .substring(ClientProtocol.Messages_PUT_auth.AUTH_USER
                                            .length()));
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case AUTH_PASSWORD:
                try {
                    password = Coder
                            .decodeBASE64asString(nextToken
                                    .substring(ClientProtocol.Messages_PUT_auth.AUTH_PASSWORD
                                            .length()));
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            default:
                break;
            }
        }

        return ((user != null) && (password != null)) ? new Pair<String, String>(
                user, password) : null;
    }

    /**
     * Parses a client PUT auth request and returns a (user name, password,
     * currentPassword) combination or <code>null</code>, if the request is
     * invalid.
     * 
     * @param message
     *            the client request.
     * @param length
     *            the length of the message in bytes.
     * @return <code>null</code>, if the request is invalid. Otherwise, a (user
     *         name, password, currentPassword) combination is returned.
     */
    public static PutAuthData putAuth(byte[] message, int length) {
        String messageString = Coder.byteToString(message, 0, length);
        StringTokenizer tokenizer = new StringTokenizer(messageString,
                ClientProtocol.Messages.PARAMETER_DELIMITER);
        String user = null;
        String password = null;
        String currentPassword = null;

        if ((message == null) || (length < 0)) {
            return null;
        }

        if (!tokenizer.hasMoreTokens()
                || !ClientProtocol.MessageType.PUT_AUTH.getMessage().equals(
                        tokenizer.nextToken())) {
            return null;
        }

        while (tokenizer.hasMoreElements()) {
            String nextToken = tokenizer.nextToken();
            ClientProtocol.Messages_PUT_auth parameter = ClientProtocol.Messages_PUT_auth
                    .identify(nextToken);

            if (parameter == null) {
                break;
            }

            switch (parameter) {
            case AUTH_USER:
                try {
                    user = Coder
                            .decodeBASE64asString(nextToken
                                    .substring(ClientProtocol.Messages_PUT_auth.AUTH_USER
                                            .length()));
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case AUTH_PASSWORD:
                try {
                    password = Coder
                            .decodeBASE64asString(nextToken
                                    .substring(ClientProtocol.Messages_PUT_auth.AUTH_PASSWORD
                                            .length()));
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case AUTH_CURRENT_PASSWORD:
                try {
                    currentPassword = Coder
                            .decodeBASE64asString(nextToken
                                    .substring(ClientProtocol.Messages_PUT_auth.AUTH_CURRENT_PASSWORD
                                            .length()));
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            default:
                break;
            }
        }

        return ((user != null) && (password != null)) ? new PutAuthData(user,
                password, currentPassword) : null;
    }

    /**
     * Parses a client PUT folder request and returns a (folder name,
     * permissions) pair or <code>null</code>, if the request is invalid.
     * 
     * @param message
     *            the client request.
     * @param length
     *            the length of the message in bytes.
     * @return an object containing the parsed data, if successful. Otherwise,
     *         <code>null</code>.
     */
    public static PutFolderData putFolder(byte[] message, int length) {
        String messageString = Coder.byteToString(message, 0, length);
        StringTokenizer tokenizer = new StringTokenizer(messageString,
                ClientProtocol.Messages.PARAMETER_DELIMITER);
        String folder = null;
        Permission[] permissions = null;
        int keyVersion = 1;
        boolean permissionsValid = true;

        if ((message == null) || (length < 0)) {
            return null;
        }

        if (!tokenizer.hasMoreTokens()
                || !ClientProtocol.MessageType.PUT_FOLDER.getMessage().equals(
                        tokenizer.nextToken())) {
            return null;
        }

        while (tokenizer.hasMoreElements()) {
            String nextToken = tokenizer.nextToken();
            ClientProtocol.Messages_PUT_folder parameter = ClientProtocol.Messages_PUT_folder
                    .identify(nextToken);

            if (parameter == null) {
                break;
            }

            switch (parameter) {
            case PATH:
                try {
                    folder = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_PUT_folder.PATH
                                    .length()));
                    if ((folder != null) && "".equals(folder.trim())) {
                        folder = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case PERMISSIONS:
                try {
                    String permissionsString = Coder
                            .decodeBASE64asString(nextToken
                                    .substring(ClientProtocol.Messages_PUT_folder.PERMISSIONS
                                            .length()));
                    permissions = Permission
                            .parsePermissions(permissionsString);

                    if (permissions == null) {
                        permissionsValid = false;
                        break;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case KEY_VERSION:
                try {
                    keyVersion = Integer
                            .parseInt(nextToken
                                    .substring(ClientProtocol.Messages_PUT_folder.KEY_VERSION
                                            .length()));
                } catch (NumberFormatException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            default:
                break;
            }
        }

        return (FileHandler.isFolderName(Paths.get(folder)) && permissionsValid && ((keyVersion >= 1) || (keyVersion == DataContainers.PUBLIC_FILE_KEY_VERSION))) ? new PutFolderData(
                null, folder, permissions, keyVersion) : null;
    }

    /**
     * Parses a client PUT file request and returns an object containing the
     * parsed data or <code>null</code>, if the request is invalid.
     * 
     * @param message
     *            the client request.
     * @param length
     *            the length of the message in bytes.
     * @return an object containing the parsed data, if successful. Otherwise,
     *         <code>null</code>.
     */
    public static PutFileData putFile(byte[] message, int length) {
        String messageString = Coder.byteToString(message, 0, length);
        StringTokenizer tokenizer = new StringTokenizer(messageString,
                ClientProtocol.Messages.PARAMETER_DELIMITER);
        String owner = null;
        String folder = null;
        String fileName = null;
        boolean isDiff = false;
        Long size = null;
        byte[] hash = null;
        int keyVersion = 1; // default value
        byte[] extra = null;
        byte[] mac = null;

        if ((message == null) || (length < 0)) {
            return null;
        }

        if (!tokenizer.hasMoreTokens()
                || !ClientProtocol.MessageType.PUT_FILE.getMessage().equals(
                        tokenizer.nextToken())) {
            return null;
        }

        while (tokenizer.hasMoreElements()) {
            String nextToken = tokenizer.nextToken();
            ClientProtocol.Messages_PUT_file parameter = ClientProtocol.Messages_PUT_file
                    .identify(nextToken);

            if (parameter == null) {
                break;
            }

            switch (parameter) {
            case OWNER:
                try {
                    owner = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_PUT_file.OWNER
                                    .length()));
                    if ((owner != null) && "".equals(owner.trim())) {
                        owner = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case FOLDER:
                try {
                    folder = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_PUT_file.FOLDER
                                    .length()));
                    if ((folder != null) && "".equals(folder.trim())) {
                        folder = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case FILE:
                try {
                    fileName = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_PUT_file.FILE
                                    .length()));
                    if ((fileName != null) && "".equals(fileName.trim())) {
                        fileName = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case IS_DIFF:
                isDiff = Boolean.parseBoolean(nextToken
                        .substring(ClientProtocol.Messages_PUT_file.IS_DIFF
                                .length()));
                break;

            case SIZE:
                try {
                    size = Long.parseLong(nextToken.substring(
                            ClientProtocol.Messages_PUT_file.SIZE.length(),
                            nextToken.length()));
                } catch (NumberFormatException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case HASH:
                try {
                    hash = Coder.decodeBASE64(nextToken
                            .substring(ClientProtocol.Messages_PUT_file.HASH
                                    .length()));
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case KEY_VERSION:
                try {
                    keyVersion = Integer
                            .parseInt(nextToken
                                    .substring(ClientProtocol.Messages_PUT_file.KEY_VERSION
                                            .length()));
                } catch (NumberFormatException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case EXTRA:
                try {
                    extra = Coder.decodeBASE64(nextToken
                            .substring(ClientProtocol.Messages_PUT_file.EXTRA
                                    .length()));
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case MAC:
                try {
                    mac = Coder.decodeBASE64(nextToken
                            .substring(ClientProtocol.Messages_PUT_file.MAC
                                    .length()));
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            default:
                break;
            }
        }

        if (folder == null) {
            folder = FileHandler.ROOT_PATH.toString();
        }

        return ((folder != null)
                && (fileName != null)
                && (size != null)
                && (size >= 0)
                && (hash != null)
                && ((keyVersion >= 1) || (keyVersion == DataContainers.PUBLIC_FILE_KEY_VERSION)) && ((mac != null) || (keyVersion == DataContainers.PUBLIC_FILE_KEY_VERSION))) ? new PutFileData(
                owner, Paths.get(folder), Paths.get(fileName), isDiff, size,
                hash, keyVersion, extra, mac) : null;
    }

    /**
     * Parses a client GET metadata request and returns an object containing the
     * parsed data or <code>null</code>, if the request is invalid.
     * 
     * @param message
     *            the client request.
     * @param length
     *            the length of the message in bytes.
     * @return an object containing the parsed data, if successful. Otherwise,
     *         <code>null</code>.
     */
    public static GetMetadataData getMetadata(byte[] message, int length) {
        String messageString = Coder.byteToString(message, 0, length);
        StringTokenizer tokenizer = new StringTokenizer(messageString,
                ClientProtocol.Messages.PARAMETER_DELIMITER);
        String owner = null;
        String folder = null;
        String fileName = null;
        int version = 0;

        if ((message == null) || (length < 0)) {
            return null;
        }

        if (!tokenizer.hasMoreTokens()
                || !ClientProtocol.MessageType.GET_METADATA.getMessage()
                        .equals(tokenizer.nextToken())) {
            return null;
        }

        while (tokenizer.hasMoreElements()) {
            String nextToken = tokenizer.nextToken();
            ClientProtocol.Messages_GET_metadata parameter = ClientProtocol.Messages_GET_metadata
                    .identify(nextToken);

            if (parameter == null) {
                break;
            }

            switch (parameter) {
            case OWNER:
                try {
                    owner = Coder
                            .decodeBASE64asString(nextToken
                                    .substring(ClientProtocol.Messages_GET_metadata.OWNER
                                            .length()));
                    if ((owner != null) && "".equals(owner.trim())) {
                        owner = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case FOLDER:
                try {
                    folder = Coder
                            .decodeBASE64asString(nextToken
                                    .substring(ClientProtocol.Messages_GET_metadata.FOLDER
                                            .length()));
                    if ((folder != null) && "".equals(folder.trim())) {
                        folder = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case FILE:
                try {
                    fileName = Coder
                            .decodeBASE64asString(nextToken
                                    .substring(ClientProtocol.Messages_GET_metadata.FILE
                                            .length()));
                    if ((fileName != null) && "".equals(fileName.trim())) {
                        fileName = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case VERSION:
                try {
                    version = Integer
                            .parseInt(nextToken
                                    .substring(ClientProtocol.Messages_GET_metadata.VERSION
                                            .length()));
                } catch (NumberFormatException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            default:
                break;
            }
        }

        if (folder == null) {
            folder = FileHandler.ROOT_PATH.toString();
        }

        return ((folder != null) && (fileName != null) && (version >= 0)) ? new GetMetadataData(
                owner, Paths.get(folder), Paths.get(fileName), version) : null;
    }

    /**
     * Parses a client GET file request and returns an object containing the
     * parsed data or <code>null</code>, if the request is invalid.
     * 
     * @param message
     *            the client request.
     * @param length
     *            the length of the message in bytes.
     * @return an object containing the parsed data, if successful. Otherwise,
     *         <code>null</code>.
     */
    public static GetFileData getFile(byte[] message, int length) {
        String messageString = Coder.byteToString(message, 0, length);
        StringTokenizer tokenizer = new StringTokenizer(messageString,
                ClientProtocol.Messages.PARAMETER_DELIMITER);
        String owner = null;
        String folder = null;
        String fileName = null;
        int version = 0;
        Long byteFirst = null;
        Long byteLast = null;

        if ((message == null) || (length < 0)) {
            return null;
        }

        if (!tokenizer.hasMoreTokens()
                || !ClientProtocol.MessageType.GET_FILE.getMessage().equals(
                        tokenizer.nextToken())) {
            return null;
        }

        while (tokenizer.hasMoreElements()) {
            String nextToken = tokenizer.nextToken();
            ClientProtocol.Messages_GET_file parameter = ClientProtocol.Messages_GET_file
                    .identify(nextToken);

            if (parameter == null) {
                break;
            }

            switch (parameter) {
            case OWNER:
                try {
                    owner = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_GET_file.OWNER
                                    .length()));
                    if ((owner != null) && "".equals(owner.trim())) {
                        owner = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case FOLDER:
                try {
                    folder = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_GET_file.FOLDER
                                    .length()));
                    if ((folder != null) && "".equals(folder.trim())) {
                        folder = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case FILE:
                try {
                    fileName = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_GET_file.FILE
                                    .length()));
                    if ((fileName != null) && "".equals(fileName.trim())) {
                        fileName = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case VERSION:
                try {
                    version = Integer.parseInt(nextToken
                            .substring(ClientProtocol.Messages_GET_file.VERSION
                                    .length()));
                } catch (NumberFormatException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case BYTE_FIRST:
                try {
                    byteFirst = Long
                            .parseLong(nextToken
                                    .substring(ClientProtocol.Messages_GET_file.BYTE_FIRST
                                            .length()));
                } catch (NumberFormatException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case BYTE_LAST:
                try {
                    byteLast = Long
                            .parseLong(nextToken
                                    .substring(ClientProtocol.Messages_GET_file.BYTE_LAST
                                            .length()));
                } catch (NumberFormatException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            default:
                break;
            }
        }

        if (folder == null) {
            folder = FileHandler.ROOT_PATH.toString();
        }

        return ((folder != null) && (fileName != null) && (version >= 0)
                && ((byteFirst == null) || (byteFirst > 0)) && ((byteLast == null) || (byteLast > 0))) ? new GetFileData(
                owner, Paths.get(folder), Paths.get(fileName), version,
                byteFirst, byteLast) : null;
    }

    public static enum Messages_GET_metadata_RESPONSE implements Messages {
        IS_DIFF("is_diff"),
        VERSION("version"),
        SIZE("size"),
        HASH("hash"),
        KEY_VERSION("key_version"),
        EXTRA("extra"),
        MAC("mac");

        private final String key;

        private Messages_GET_metadata_RESPONSE(String key) {
            this.key = key;
        }

        @Override
        public String getKey() {
            return key;
        }

        @Override
        public String toString() {
            return Messages.PARAMETER_DELIMITER + key
                    + Messages.KEY_VALUE_DELIMITER;
        }

        public static Messages_GET_metadata_RESPONSE identify(String token) {
            if (token == null) {
                return null;
            }

            Messages_GET_metadata_RESPONSE result = null;

            for (Messages_GET_metadata_RESPONSE parameter : values()) {
                if (token.startsWith(parameter.key)) {
                    result = parameter;
                    break;
                }
            }

            return result;
        }

        @Override
        public int length() {
            return key.length() + Messages.KEY_VALUE_DELIMITER.length();
        }
    }

    /**
     * Returns a GET metadata server response with the given parameters.
     * 
     * @param data
     *            the parameters for the GET metadata server response.
     * @return a GET metadata server response message.
     */
    public static byte[] getMetadataResponse(GetMetadataResponseData data) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }

        StringBuilder builder = new StringBuilder(128);
        builder.append(MessageType.SUCCESS_GET_METADATA.getAllAsString());
        builder.append(Messages_GET_metadata_RESPONSE.VERSION);
        builder.append(String.valueOf(data.getVersion()));
        builder.append(Messages_GET_metadata_RESPONSE.IS_DIFF);
        builder.append(String.valueOf(data.isDiff()));
        builder.append(Messages_GET_metadata_RESPONSE.SIZE);
        builder.append(String.valueOf(data.getSize()));
        builder.append(Messages_GET_metadata_RESPONSE.HASH);
        builder.append(Coder.encodeBASE64(data.getHash()));
        builder.append(Messages_GET_metadata_RESPONSE.KEY_VERSION);
        builder.append(String.valueOf(data.getKeyVersion()));
        if (data.getExtra() != null) {
            builder.append(Messages_GET_metadata_RESPONSE.EXTRA);
            builder.append(Coder.encodeBASE64(data.getExtra()));
        }
        if (data.getMAC() != null) {
            builder.append(Messages_GET_metadata_RESPONSE.MAC);
            builder.append(Coder.encodeBASE64(data.getMAC()));
        }
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }

    /**
     * Parses a client GET sync request and returns an object containing the
     * parsed data or <code>null</code>, if the request is invalid.
     * 
     * @param message
     *            the client request.
     * @param length
     *            the length of the message in bytes.
     * @return an object containing the parsed data, if successful. Otherwise,
     *         <code>null</code>.
     */
    public static GetSyncData getSync(byte[] message, int length) {
        String messageString = Coder.byteToString(message, 0, length);
        StringTokenizer tokenizer = new StringTokenizer(messageString,
                ClientProtocol.Messages.PARAMETER_DELIMITER);
        String owner = null;
        String path = null;
        int version = 0;

        if ((message == null) || (length < 0)) {
            return null;
        }

        if (!tokenizer.hasMoreTokens()
                || !ClientProtocol.MessageType.GET_SYNC.getMessage().equals(
                        tokenizer.nextToken())) {
            return null;
        }

        while (tokenizer.hasMoreElements()) {
            String nextToken = tokenizer.nextToken();
            ClientProtocol.Messages_GET_sync parameter = ClientProtocol.Messages_GET_sync
                    .identify(nextToken);

            if (parameter == null) {
                break;
            }

            switch (parameter) {
            case OWNER:
                try {
                    owner = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_GET_sync.OWNER
                                    .length()));
                    if ((owner != null) && "".equals(owner.trim())) {
                        owner = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case PATH:
                try {
                    path = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_GET_sync.PATH
                                    .length()));
                    if ((path != null) && "".equals(path.trim())) {
                        path = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case VERSION:
                try {
                    version = Integer.parseInt(nextToken
                            .substring(ClientProtocol.Messages_GET_sync.VERSION
                                    .length()));
                } catch (NumberFormatException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            default:
                break;
            }
        }

        Path folderPath = (path != null) ? Paths.get(path)
                : FileHandler.ROOT_PATH;

        return (folderPath != null) && (version >= 0) ? new GetSyncData(owner,
                folderPath, version) : null;
    }

    public static enum Messages_GET_sync_RESPONSE implements Messages {
        VERSION("version"),
        ACTION("action"),
        OBJECT("object");

        public static final String TUPLE_DELIMITER = "\n";

        private final String key;

        private Messages_GET_sync_RESPONSE(String key) {
            this.key = key;
        }

        @Override
        public String getKey() {
            return key;
        }

        @Override
        public String toString() {
            return Messages.PARAMETER_DELIMITER + key
                    + Messages.KEY_VALUE_DELIMITER;
        }

        public static Messages_GET_sync_RESPONSE identify(String token) {
            if (token == null) {
                return null;
            }

            Messages_GET_sync_RESPONSE result = null;

            for (Messages_GET_sync_RESPONSE parameter : values()) {
                if (token.startsWith(parameter.key)) {
                    result = parameter;
                    break;
                }
            }

            return result;
        }

        @Override
        public int length() {
            return key.length() + Messages.KEY_VALUE_DELIMITER.length();
        }
    }

    /**
     * Returns a GET sync server response with the given parameters.
     * 
     * @param responses
     *            the parameters for the GET sync server response.
     * @return a GET sync server response message.
     */
    public static byte[] getSyncResponse(ActionData[] responses) {
        if (responses == null) {
            throw new NullPointerException("data may not be null!");
        }

        int i = 0;
        StringBuilder builder = new StringBuilder(128);
        builder.append(MessageType.SUCCESS_GET_SYNC.getAllAsString());

        for (ActionData response : responses) {
            builder.append(Messages_GET_sync_RESPONSE.VERSION);
            builder.append(String.valueOf(response.getVersion()));
            builder.append(Messages_GET_sync_RESPONSE.ACTION);
            builder.append(response.getAction().toChar());
            builder.append(Messages_GET_sync_RESPONSE.OBJECT);
            builder.append(response.getObject());

            i++;
            if (i < responses.length) {
                builder.append(Messages_GET_sync_RESPONSE.TUPLE_DELIMITER);
            }
        }
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }

    /**
     * Parses a client POST move request and returns an object containing the
     * parsed data or <code>null</code>, if the request is invalid.
     * 
     * @param message
     *            the client request.
     * @param length
     *            the length of the message in bytes.
     * @return an object containing the parsed data, if successful. Otherwise,
     *         <code>null</code>.
     */
    public static PostMoveData postMove(byte[] message, int length) {
        String messageString = Coder.byteToString(message, 0, length);
        StringTokenizer tokenizer = new StringTokenizer(messageString,
                ClientProtocol.Messages.PARAMETER_DELIMITER);
        String owner = null;
        String folder = null;
        String from = null;
        String to = null;

        if ((message == null) || (length < 0)) {
            return null;
        }

        if (!tokenizer.hasMoreTokens()
                || !ClientProtocol.MessageType.POST_MOVE.getMessage().equals(
                        tokenizer.nextToken())) {
            return null;
        }

        while (tokenizer.hasMoreElements()) {
            String nextToken = tokenizer.nextToken();
            ClientProtocol.Messages_POST_move parameter = ClientProtocol.Messages_POST_move
                    .identify(nextToken);

            if (parameter == null) {
                break;
            }

            switch (parameter) {
            case OWNER:
                try {
                    owner = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_POST_move.OWNER
                                    .length()));
                    if ((owner != null) && "".equals(owner.trim())) {
                        owner = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case FOLDER:
                try {
                    folder = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_POST_move.FOLDER
                                    .length()));
                    if ((folder != null) && "".equals(folder.trim())) {
                        folder = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case FROM:
                try {
                    from = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_POST_move.FROM
                                    .length()));
                    if ((from != null) && "".equals(from.trim())) {
                        from = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case TO:
                try {
                    to = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_POST_move.TO
                                    .length()));
                    if ((to != null) && "".equals(to.trim())) {
                        to = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            default:
                break;
            }
        }

        if (folder == null) {
            folder = FileHandler.ROOT_PATH.toString();
        }

        return ((folder != null) && (from != null) && (to != null)) ? new PostMoveData(
                owner, Paths.get(folder), Paths.get(from), Paths.get(to))
                : null;
    }

    /**
     * Parses a client DELETE file request and returns an object containing the
     * parsed data or <code>null</code>, if the request is invalid.
     * 
     * @param message
     *            the client request.
     * @param length
     *            the length of the message in bytes.
     * @return an object containing the parsed data, if successful. Otherwise,
     *         <code>null</code>.
     */
    public static DeleteFileData deleteFile(byte[] message, int length) {
        String messageString = Coder.byteToString(message, 0, length);
        StringTokenizer tokenizer = new StringTokenizer(messageString,
                ClientProtocol.Messages.PARAMETER_DELIMITER);
        String owner = null;
        String folder = null;
        String file = null;

        if ((message == null) || (length < 0)) {
            return null;
        }

        if (!tokenizer.hasMoreTokens()
                || !ClientProtocol.MessageType.DELETE_FILE.getMessage().equals(
                        tokenizer.nextToken())) {
            return null;
        }

        while (tokenizer.hasMoreElements()) {
            String nextToken = tokenizer.nextToken();
            ClientProtocol.Messages_DELETE_file parameter = ClientProtocol.Messages_DELETE_file
                    .identify(nextToken);

            if (parameter == null) {
                break;
            }

            switch (parameter) {
            case OWNER:
                try {
                    owner = Coder
                            .decodeBASE64asString(nextToken
                                    .substring(ClientProtocol.Messages_DELETE_file.OWNER
                                            .length()));
                    if ((owner != null) && "".equals(owner.trim())) {
                        owner = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case FOLDER:
                try {
                    folder = Coder
                            .decodeBASE64asString(nextToken
                                    .substring(ClientProtocol.Messages_DELETE_file.FOLDER
                                            .length()));
                    if ((folder != null) && "".equals(folder.trim())) {
                        folder = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case FILE:
                try {
                    file = Coder.decodeBASE64asString(nextToken
                            .substring(ClientProtocol.Messages_DELETE_file.FILE
                                    .length()));
                    if ((file != null) && "".equals(file.trim())) {
                        file = null;
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            default:
                break;
            }
        }

        if (folder == null) {
            folder = FileHandler.ROOT_PATH.toString();
        }

        return ((folder != null) && (file != null)) ? new DeleteFileData(owner,
                Paths.get(folder), Paths.get(file)) : null;
    }
}
