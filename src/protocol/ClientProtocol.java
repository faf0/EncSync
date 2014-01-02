package protocol;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import misc.Coder;
import misc.FileHandler;
import misc.Logger;
import protocol.DataContainers.ActionData;
import protocol.DataContainers.ActionType;
import protocol.DataContainers.DeleteFileData;
import protocol.DataContainers.GetFileData;
import protocol.DataContainers.GetMetadataData;
import protocol.DataContainers.GetMetadataResponseData;
import protocol.DataContainers.GetSyncData;
import protocol.DataContainers.PostMoveData;
import protocol.DataContainers.PutAuthData;
import protocol.DataContainers.PutFileData;
import protocol.DataContainers.PutFolderData;
import configuration.ClientConfiguration;
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
 * Client protocol messages are created by this class. Additionally, server
 * messages are parsed in this class.
 * 
 * @author Fabian Foerg
 */
public final class ClientProtocol {
    /**
     * Interface and constants for client messages.
     * 
     * @author Fabian Foerg
     */
    public interface Messages {
        /**
         * Client message delimiter.
         */
        public static final byte[] DELIMITER = new byte[] { 0 };

        /**
         * Parameter delimiter.
         */
        public static final String PARAMETER_DELIMITER = "?";

        /**
         * Key/value delimiter.
         */
        public static final String KEY_VALUE_DELIMITER = "=";

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
     * All client message types.
     * 
     * @author Fabian Foerg
     */
    public static enum MessageType {
        UNKNOWN("UNKNOWN MESSAGE TYPE"),
        POST_AUTH("POST auth"),
        PUT_AUTH("PUT auth"),
        PUT_FOLDER("PUT folder"),
        PUT_FILE_REQUEST("REQUEST PUT file"),
        PUT_FILE("PUT file"),
        GET_METADATA("GET metadata"),
        GET_FILE("GET file"),
        GET_SYNC("GET sync"),
        POST_MOVE("POST move"),
        DELETE_FILE("DELETE file"),
        POST_SYNC_DONE("POST sync DONE");

        private final String message;

        private MessageType(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }

        public boolean equals(byte[] message) {
            if (message == null) {
                return false;
            }

            return Coder.startsWith(message, getMessage());
        }

        @Override
        public String toString() {
            return message;
        }

        public static MessageType identify(String message) {
            if (message == null) {
                throw new NullPointerException("message may not be null!");
            }

            MessageType result = UNKNOWN;

            for (MessageType type : MessageType.values()) {
                if (message.startsWith(type.getMessage())) {
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
    private ClientProtocol() {
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
    public static ClientProtocol.MessageType identifyRequest(byte[] message,
            int length) {
        if (message == null) {
            throw new IllegalArgumentException("message may not be null!");
        }
        if (length < 1) {
            return MessageType.UNKNOWN;
        }

        return MessageType.identify(Coder.byteToString(message, 0, length));
    }

    public static enum Messages_POST_auth implements Messages {
        AUTH_USER("user"),
        AUTH_PASSWORD("password");

        private final String key;

        private Messages_POST_auth(String key) {
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

        public static Messages_POST_auth identify(String token) {
            if (token == null) {
                return null;
            }

            Messages_POST_auth result = null;

            for (Messages_POST_auth parameter : values()) {
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
     * Returns a POST auth request message.
     * 
     * @param user
     *            the user name.
     * @param password
     *            the cleartext password.
     * @return a POST auth request message.
     */
    public static byte[] postAuth(String user, String password) {
        if (!ClientConfiguration.isValidUserName(user)) {
            throw new IllegalArgumentException("user must be valid!");
        }
        if (password == null) {
            throw new NullPointerException("password may not be null!");
        }

        StringBuilder builder = new StringBuilder(128);
        builder.append(MessageType.POST_AUTH.getMessage());
        builder.append(Messages_POST_auth.AUTH_USER);
        builder.append(Coder.encodeBASE64(user));
        builder.append(Messages_POST_auth.AUTH_PASSWORD);
        builder.append(Coder.encodeBASE64(password));
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }

    public static enum Messages_PUT_auth implements Messages {
        AUTH_USER("user"),
        AUTH_PASSWORD("password"), AUTH_CURRENT_PASSWORD("current_password");

        private final String key;

        private Messages_PUT_auth(String key) {
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

        public static Messages_PUT_auth identify(String token) {
            if (token == null) {
                return null;
            }

            Messages_PUT_auth result = null;

            for (Messages_PUT_auth parameter : values()) {
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
     * Returns a POST auth request message.
     * 
     * @param user
     *            the user name.
     * @param password
     *            the cleartext password.
     * @return a POST auth request message.
     */
    public static byte[] putAuth(PutAuthData data) {
        if (data == null) {
            throw new IllegalArgumentException("data may not be null!");
        }

        StringBuilder builder = new StringBuilder(128);
        builder.append(MessageType.PUT_AUTH.getMessage());
        builder.append(Messages_PUT_auth.AUTH_USER);
        builder.append(Coder.encodeBASE64(data.getName()));
        builder.append(Messages_PUT_auth.AUTH_PASSWORD);
        builder.append(Coder.encodeBASE64(data.getPassword()));
        if (data.getCurrentPassword() != null) {
            builder.append(Messages_PUT_auth.AUTH_CURRENT_PASSWORD);
            builder.append(Coder.encodeBASE64(data.getCurrentPassword()));
        }
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }

    public static enum Messages_PUT_folder implements Messages {
        PATH("path"),
        PERMISSIONS("permissions"), KEY_VERSION("key_version");

        private final String key;

        private Messages_PUT_folder(String key) {
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

        public static Messages_PUT_folder identify(String token) {
            if (token == null) {
                return null;
            }

            Messages_PUT_folder result = null;

            for (Messages_PUT_folder parameter : values()) {
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
     * Returns a PUT folder message.
     * 
     * @param data
     *            the data for the message.
     * @return a PUT folder message.
     */
    public static byte[] putFolder(PutFolderData data) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }

        /*
         * Note that the owner is not part of the request, as only the current
         * authenticated user of the connection is allowed to create or modify a
         * folder.
         */
        StringBuilder builder = new StringBuilder(128);
        builder.append(MessageType.PUT_FOLDER.getMessage());
        builder.append(Messages_PUT_folder.PATH);
        builder.append(Coder.encodeBASE64(data.getFolder()));
        if (data.getPermissions() != null) {
            builder.append(Messages_PUT_folder.PERMISSIONS);
            builder.append(Coder.encodeBASE64(Permission
                    .toPermissionString(data.getPermissions())));
        }
        builder.append(Messages_PUT_folder.KEY_VERSION);
        builder.append(data.getKeyVersion());
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }

    public static enum Messages_PUT_file implements Messages {
        OWNER("owner"),
        FOLDER("folder"),
        FILE("file"),
        IS_DIFF("is_diff"),
        SIZE("size"),
        HASH("hash"),
        KEY_VERSION("key_version"),
        EXTRA("extra"),
        MAC("mac");

        private final String key;

        private Messages_PUT_file(String key) {
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

        public static Messages_PUT_file identify(String token) {
            if (token == null) {
                return null;
            }

            Messages_PUT_file result = null;

            for (Messages_PUT_file parameter : values()) {
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
     * Returns the header of a PUT file message. The file must be transmitted
     * directly afterwards over the same stream, if the server accepts the
     * request.
     * 
     * @param data
     *            the parameters for the request.
     * @return a PUT file message.
     */
    public static byte[] putFile(PutFileData data) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }

        StringBuilder builder = new StringBuilder(128);
        builder.append(MessageType.PUT_FILE.getMessage());
        if (data.getOwner() != null) {
            builder.append(Messages_PUT_file.OWNER);
            builder.append(Coder.encodeBASE64(data.getOwner()));
        }
        builder.append(Messages_PUT_file.FOLDER);
        builder.append(Coder.encodeBASE64(data.getFolder().toString()));
        builder.append(Messages_PUT_file.FILE);
        builder.append(Coder.encodeBASE64(FileHandler.toCanonicalPath(data
                .getFile())));
        builder.append(Messages_PUT_file.IS_DIFF);
        builder.append(Boolean.toString(data.isDiff()));
        builder.append(Messages_PUT_file.SIZE);
        builder.append(String.valueOf(data.getSize()));
        builder.append(Messages_PUT_file.HASH);
        builder.append(Coder.encodeBASE64(data.getHash()));
        builder.append(Messages_PUT_file.KEY_VERSION);
        builder.append(String.valueOf(data.getKeyVersion()));
        if (data.getExtra() != null) {
            builder.append(Messages_PUT_file.EXTRA);
            builder.append(Coder.encodeBASE64(data.getExtra()));
        }
        if (data.getMAC() != null) {
            builder.append(Messages_PUT_file.MAC);
            builder.append(Coder.encodeBASE64(data.getMAC()));
        }
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }

    public static enum Messages_GET_metadata implements Messages {
        OWNER("owner"),
        FOLDER("folder"),
        FILE("file"),
        VERSION("version");

        private final String key;

        private Messages_GET_metadata(String key) {
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

        public static Messages_GET_metadata identify(String token) {
            if (token == null) {
                return null;
            }

            Messages_GET_metadata result = null;

            for (Messages_GET_metadata parameter : values()) {
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
     * Returns a GET metadata request message.
     * 
     * @param data
     *            the data for the message.
     * @return a GET sync request message.
     */
    public static byte[] getMetadata(GetMetadataData data) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }

        StringBuilder builder = new StringBuilder(128);
        builder.append(MessageType.GET_METADATA.getMessage());
        if (data.getOwner() != null) {
            builder.append(Messages_GET_metadata.OWNER);
            builder.append(Coder.encodeBASE64(data.getOwner()));
        }
        builder.append(Messages_GET_metadata.FOLDER);
        builder.append(Coder.encodeBASE64(data.getFolder().toString()));
        builder.append(Messages_GET_metadata.FILE);
        builder.append(Coder.encodeBASE64(FileHandler.toCanonicalPath(data
                .getFile())));
        if (data.getVersion() > 0) {
            builder.append(Messages_GET_metadata.VERSION);
            builder.append(String.valueOf(data.getVersion()));
        }
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }

    public static enum Messages_GET_file implements Messages {
        OWNER("owner"),
        FOLDER("folder"),
        FILE("file"),
        VERSION("version"),
        BYTE_FIRST("byte_first"),
        BYTE_LAST("byte_last");

        private final String key;

        private Messages_GET_file(String key) {
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

        public static Messages_GET_file identify(String token) {
            if (token == null) {
                return null;
            }

            Messages_GET_file result = null;

            for (Messages_GET_file parameter : values()) {
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
     * Returns a GET file request message.
     * 
     * @param data
     *            the parameters for the request.
     * @return a GET file request message.
     */
    public static byte[] getFile(GetFileData data) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }

        StringBuilder builder = new StringBuilder(128);
        builder.append(MessageType.GET_FILE.getMessage());
        if (data.getOwner() != null) {
            builder.append(Messages_GET_file.OWNER);
            builder.append(Coder.encodeBASE64(data.getOwner()));
        }
        builder.append(Messages_GET_file.FOLDER);
        builder.append(Coder.encodeBASE64(data.getFolder().toString()));
        builder.append(Messages_GET_file.FILE);
        builder.append(Coder.encodeBASE64(FileHandler.toCanonicalPath(data
                .getFile())));
        if (data.getVersion() > 0) {
            builder.append(Messages_GET_file.VERSION);
            builder.append(String.valueOf(data.getVersion()));
        }
        if (data.getByteFirst() != null) {
            builder.append(Messages_GET_file.BYTE_FIRST);
            builder.append(String.valueOf(data.getByteFirst()));
        }
        if (data.getByteLast() != null) {
            builder.append(Messages_GET_file.BYTE_LAST);
            builder.append(String.valueOf(data.getByteLast()));
        }
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }

    /**
     * Parses a server GET metadata response and returns an object containing
     * the parsed data or <code>null</code>, if the response is invalid.
     * 
     * @param message
     *            the server response.
     * @param length
     *            the length of the message in bytes.
     * @return an object containing the parsed data, if successful. Otherwise,
     *         <code>null</code>.
     */
    public static GetMetadataResponseData getMetadataResponse(byte[] message,
            int length) {
        String messageString = Coder.byteToString(message, 0, length);
        StringTokenizer tokenizer = new StringTokenizer(messageString,
                ServerProtocol.Messages.PARAMETER_DELIMITER);
        boolean isDiff = false;
        Integer version = null;
        Long size = null;
        byte[] hash = null;
        int keyVersion = 1; // default value
        byte[] extra = null;
        byte[] mac = null;

        if ((message == null) || (length < 0)) {
            return null;
        }

        if (!tokenizer.hasMoreTokens()
                || !ServerProtocol.MessageType.SUCCESS_GET_METADATA
                        .getAllAsString().equals(tokenizer.nextToken())) {
            return null;
        }

        while (tokenizer.hasMoreElements()) {
            String nextToken = tokenizer.nextToken();
            ServerProtocol.Messages_GET_metadata_RESPONSE parameter = ServerProtocol.Messages_GET_metadata_RESPONSE
                    .identify(nextToken);

            if (parameter == null) {
                break;
            }

            switch (parameter) {
            case IS_DIFF:
                isDiff = Boolean
                        .parseBoolean(nextToken
                                .substring(ServerProtocol.Messages_GET_metadata_RESPONSE.IS_DIFF
                                        .length()));
                break;

            case VERSION:
                try {
                    version = Integer
                            .parseInt(nextToken
                                    .substring(ServerProtocol.Messages_GET_metadata_RESPONSE.VERSION
                                            .length()));
                } catch (NumberFormatException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case SIZE:
                try {
                    size = Long.parseLong(nextToken.substring(
                            ServerProtocol.Messages_GET_metadata_RESPONSE.SIZE
                                    .length(), nextToken.length()));
                } catch (NumberFormatException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case HASH:
                try {
                    hash = Coder
                            .decodeBASE64(nextToken
                                    .substring(ServerProtocol.Messages_GET_metadata_RESPONSE.HASH
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
                                    .substring(ServerProtocol.Messages_GET_metadata_RESPONSE.KEY_VERSION
                                            .length()));
                } catch (NumberFormatException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case EXTRA:
                try {
                    extra = Coder
                            .decodeBASE64(nextToken
                                    .substring(ServerProtocol.Messages_GET_metadata_RESPONSE.EXTRA
                                            .length()));
                } catch (IOException e) {
                    Logger.logError(e);
                    return null;
                }
                break;

            case MAC:
                try {
                    mac = Coder
                            .decodeBASE64(nextToken
                                    .substring(ServerProtocol.Messages_GET_metadata_RESPONSE.MAC
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

        return ((version != null)
                && (version > 0)
                && (size != null)
                && (size >= 0)
                && (hash != null)
                && ((keyVersion >= 1) || (keyVersion == DataContainers.PUBLIC_FILE_KEY_VERSION)) && ((mac != null) || (keyVersion == DataContainers.PUBLIC_FILE_KEY_VERSION))) ? new GetMetadataResponseData(
                isDiff, version, size, hash, keyVersion, extra, mac) : null;
    }

    public static enum Messages_GET_sync implements Messages {
        OWNER("owner"),
        PATH("path"),
        VERSION("version");

        private final String key;

        private Messages_GET_sync(String key) {
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

        public static Messages_GET_sync identify(String token) {
            if (token == null) {
                return null;
            }

            Messages_GET_sync result = null;

            for (Messages_GET_sync parameter : values()) {
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
     * Returns a GET sync request message.
     * 
     * @param data
     *            the data for the message.
     * @return a GET sync request message.
     */
    public static byte[] getSync(GetSyncData data) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }

        StringBuilder builder = new StringBuilder(128);
        builder.append(MessageType.GET_SYNC.getMessage());
        if (data.getOwner() != null) {
            builder.append(Messages_GET_sync.OWNER);
            builder.append(Coder.encodeBASE64(data.getOwner()));
        }
        if (data.getFolder() != null) {
            builder.append(Messages_GET_sync.PATH);
            builder.append(Coder.encodeBASE64(data.getFolder().toString()));
        }
        if (data.getVersion() > 0) {
            builder.append(Messages_GET_sync.VERSION);
            builder.append(String.valueOf(data.getVersion()));
        }
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }

    /**
     * Parses a server GET sync response and returns an object containing the
     * parsed synchronization data or an empty array. If the request failed,
     * <code>null</code> is returned.
     * 
     * @param message
     *            the server response.
     * @param length
     *            the length of the message in bytes.
     * @return an object containing the parsed synchronization data or an empty
     *         array, if successful. Otherwise, <code>null</code>.
     */
    public static ActionData[] getSyncResponse(byte[] message, int length) {
        String messageString = Coder.byteToString(message, 0, length);
        StringTokenizer tupleTokenizer = new StringTokenizer(messageString,
                ServerProtocol.Messages_GET_sync_RESPONSE.TUPLE_DELIMITER);
        String nextToken;
        List<ActionData> responses = new LinkedList<ActionData>();
        boolean done = false;
        boolean fine = true;

        if ((message == null) || (length < 0)) {
            return null;
        }

        if (!tupleTokenizer.hasMoreTokens()) {
            return null;
        }

        nextToken = tupleTokenizer.nextToken();

        if (nextToken.startsWith(ServerProtocol.MessageType.SUCCESS_GET_SYNC
                .getAllAsString())) {
            /*
             * First tuple contains the header. Skip the header.
             */
            nextToken = nextToken
                    .substring(ServerProtocol.MessageType.SUCCESS_GET_SYNC
                            .getAllAsString().length());
        } else {
            return null;
        }

        while (!done && fine) {
            StringTokenizer parameterTokenizer = new StringTokenizer(nextToken,
                    ServerProtocol.Messages.PARAMETER_DELIMITER);
            boolean empty = true;
            int version = 0;
            ActionType action = null;
            String object = null;

            /*
             * Parse a single response.
             */
            while (parameterTokenizer.hasMoreElements()) {
                String nextParameterToken = parameterTokenizer.nextToken();
                ServerProtocol.Messages_GET_sync_RESPONSE parameter = ServerProtocol.Messages_GET_sync_RESPONSE
                        .identify(nextParameterToken);
                empty = false;

                if (parameter == null) {
                    fine = false;
                    break;
                }

                switch (parameter) {
                case VERSION:
                    try {
                        version = Integer
                                .parseInt(nextParameterToken
                                        .substring(ServerProtocol.Messages_GET_sync_RESPONSE.VERSION
                                                .length()));
                    } catch (NumberFormatException e) {
                        Logger.logError(e);
                        return null;
                    }
                    break;

                case ACTION:
                    action = ActionType
                            .fromChar(nextParameterToken
                                    .charAt(ServerProtocol.Messages_GET_sync_RESPONSE.ACTION
                                            .length()));
                    break;

                case OBJECT:
                    object = nextParameterToken
                            .substring(ServerProtocol.Messages_GET_sync_RESPONSE.OBJECT
                                    .length());
                    break;

                default:
                    // unknown parameter
                    fine = false;
                    break;
                }
            }

            if (fine && (version >= 1) && (action != null) && (object != null)) {
                responses.add(new ActionData(version, action, object));

                if (tupleTokenizer.hasMoreElements()) {
                    nextToken = tupleTokenizer.nextToken();
                } else {
                    // no more elements
                    done = true;
                }
            } else if (!empty) {
                // response data was there, but could not be parsed
                fine = false;
            } else {
                // empty response
                done = true;
            }
        }

        return fine ? responses.toArray(new ActionData[0]) : null;
    }

    public static enum Messages_POST_move implements Messages {
        OWNER("owner"),
        FOLDER("folder"),
        FROM("from"),
        TO("to");

        private final String key;

        private Messages_POST_move(String key) {
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

        public static Messages_POST_move identify(String token) {
            if (token == null) {
                return null;
            }

            Messages_POST_move result = null;

            for (Messages_POST_move parameter : values()) {
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
     * Returns a POST move request message.
     * 
     * @param data
     *            the data for the message.
     * @return a POST move request message.
     */
    public static byte[] postMove(PostMoveData data) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }

        StringBuilder builder = new StringBuilder(128);
        builder.append(MessageType.POST_MOVE.getMessage());
        if (data.getOwner() != null) {
            builder.append(Messages_POST_move.OWNER);
            builder.append(Coder.encodeBASE64(data.getOwner()));
        }
        builder.append(Messages_POST_move.FOLDER);
        builder.append(Coder.encodeBASE64(data.getFolder().toString()));
        builder.append(Messages_POST_move.FROM);
        builder.append(Coder.encodeBASE64(FileHandler.toCanonicalPath(data
                .getFrom())));
        builder.append(Messages_POST_move.TO);
        builder.append(Coder.encodeBASE64(FileHandler.toCanonicalPath(data
                .getTo())));
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }

    public static enum Messages_DELETE_file implements Messages {
        OWNER("owner"),
        FOLDER("folder"),
        FILE("file");

        private final String key;

        private Messages_DELETE_file(String key) {
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

        public static Messages_DELETE_file identify(String token) {
            if (token == null) {
                return null;
            }

            Messages_DELETE_file result = null;

            for (Messages_DELETE_file parameter : values()) {
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
     * Returns a DELETE file request message.
     * 
     * @param owner
     *            the owner of the file.
     * @param folder
     *            the folder containing the file to delete. May not be
     *            <code>null</code>.
     * @param file
     *            the path relative to <code>folder</code> of the file to
     *            delete. Must not be <code>null</code>.
     * @return a DELETE file request message.
     */
    public static byte[] deleteFile(DeleteFileData data) {
        if (data == null) {
            throw new NullPointerException("data may not be null");
        }

        StringBuilder builder = new StringBuilder(128);
        builder.append(MessageType.DELETE_FILE.getMessage());
        if (data.getOwner() != null) {
            builder.append(Messages_DELETE_file.OWNER);
            builder.append(Coder.encodeBASE64(data.getOwner()));
        }
        builder.append(Messages_DELETE_file.FOLDER);
        builder.append(Coder.encodeBASE64(data.getFolder().toString()));
        builder.append(Messages_DELETE_file.FILE);
        builder.append(Coder.encodeBASE64(FileHandler.toCanonicalPath(data
                .getFile())));
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }

    /**
     * Returns a POST sync DONE message.
     * 
     * @return a POST sync DONE message.
     */
    public static byte[] postSyncDone() {
        StringBuilder builder = new StringBuilder(MessageType.POST_SYNC_DONE
                .getMessage().length() + Messages.DELIMITER.length);
        builder.append(MessageType.POST_SYNC_DONE.getMessage());
        builder.append(Coder.byteToString(Messages.DELIMITER));

        return Coder.stringToByte(builder.toString());
    }
}
