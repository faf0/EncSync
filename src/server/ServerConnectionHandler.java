package server;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.util.Date;

import misc.Coder;
import misc.FileHandler;
import misc.Logger;
import misc.network.ConnectionHandler;
import misc.network.SecureSocket;
import protocol.ClientProtocol;
import protocol.DataContainers.ActionData;
import protocol.DataContainers.ActionType;
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
import protocol.ServerProtocol;
import server.Server.ConnectionThread;
import server.Server.LockPair;
import server.crypto.Authentication;
import server.database.DatabaseQueries;
import server.database.DatabaseQueries.FileEntry;
import server.database.DatabaseQueries.FolderEntry;
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
 * Handles a single server-client connection. Implements the server protocol. Is
 * thread-safe, although instances of this class are not supposed to be accessed
 * by multiple threads concurrently.
 * 
 * @author Fabian Foerg
 */
public final class ServerConnectionHandler extends ConnectionHandler {
    /**
     * Name of the private folder containing an owner's private files.
     */
    public static final String PRIVATE_FOLDER = "private";

    private static final int BUFFER_SIZE = 1024 * 1024;
    private static final Object USER_LOCK = new Object();
    private static final Object FOLDER_LOCK = new Object();

    private boolean authenticated;
    private String userName;
    private long failedRequests;

    private final ConnectionThread connectionThread;
    private final Path clientDirectory;
    private final Path clientDirectoryAbsolute;
    private final long maxFailedRequests;

    /**
     * Creates a new server connection handler.
     * 
     * @param socket
     *            the associated socket.
     * @param connectionThread
     *            the connection thread managing this connection.
     * @param clientDirectory
     *            the directory where client data is stored. May not be
     *            <code>null</code>.
     * @param maxFailedRequests
     *            the maximum number of failed requests.
     * @throws IOException
     */
    public ServerConnectionHandler(SecureSocket socket,
            ConnectionThread connectionThread, Path clientDirectory,
            long maxFailedRequests) throws IOException {
        super(BUFFER_SIZE, socket, ClientProtocol.Messages.DELIMITER);

        if (connectionThread == null) {
            throw new NullPointerException("connectionThread may not be null!");
        }
        if (clientDirectory == null) {
            throw new IllegalArgumentException(
                    "clientDirectory may not be null!");
        }
        if (maxFailedRequests < 0) {
            throw new IllegalArgumentException(
                    "maxFailedRequests must be at least zero!");
        }

        authenticated = false;
        userName = null;
        failedRequests = 0;
        this.connectionThread = connectionThread;
        this.clientDirectory = clientDirectory.normalize();
        this.clientDirectoryAbsolute = this.clientDirectory.toAbsolutePath();
        this.maxFailedRequests = maxFailedRequests;
    }

    /**
     * Handles the next client request.
     * 
     * @return <code>true</code>, if we are done. Otherwise, <code>false</code>
     *         is returned.
     * @throws IOException
     */
    public synchronized boolean next() throws IOException {
        boolean done = false;
        int length = readNextMessage();

        if (length > 0) {
            Logger.log(String.format("%s -- %s",
                    Coder.byteToString(getBuffer(), 0, length),
                    super.toString()));
            ClientProtocol.MessageType messageType = ClientProtocol
                    .identifyRequest(getBuffer(), length);
            handleRequest(messageType, length);
        } else {
            done = true;
        }

        return done;
    }

    /**
     * Sends the given message to the connected client.
     * 
     * @param message
     *            the message to send.
     * @throws IOException
     */
    private void send(ServerProtocol.MessageType message) throws IOException {
        assert (message != null);

        super.send(message.getAllAsBytes());
    }

    /**
     * Handles the given request according to the identified client message
     * type. Blocks the connected client and closes the connection, if the
     * maximum number of failed requests was reached.
     * 
     * @param messageType
     *            the client protocol message type.
     * @param length
     *            the length of the message.
     * @throws IOException
     */
    private void handleRequest(ClientProtocol.MessageType messageType,
            int length) throws IOException {
        if (messageType == null) {
            throw new IllegalArgumentException("message type may not be null!");
        }

        boolean handledWell = false;

        switch (messageType) {
        case POST_AUTH:
            handledWell = handlePostAuth(length);
            break;

        case PUT_AUTH:
            handledWell = handlePutAuth(length);
            break;

        case PUT_FOLDER:
            handledWell = handlePutFolder(length);
            break;

        case PUT_FILE:
            handledWell = handlePutFile(length);
            break;

        case GET_METADATA:
            handledWell = handleGetMetadata(length);
            break;

        case GET_FILE:
            handledWell = handleGetFile(length);
            break;

        case GET_SYNC:
            handledWell = handleGetSync(length);
            break;

        case POST_MOVE:
            handledWell = handlePostMove(length);
            break;

        case DELETE_FILE:
            handledWell = handleDeleteFile(length);
            break;

        case POST_SYNC_DONE:
            handledWell = handlePostSyncDone();
            break;

        default:
        case UNKNOWN:
            handleUnknownMessageType(length);
            break;
        }

        /*
         * Check whether the client request was handled successfully. Block the
         * client and close the connection, if the maximum number of failed
         * requests was reached.
         */
        if (!handledWell || !isAuthenticated()) {
            failedRequests++;

            if (failedRequests >= maxFailedRequests) {
                connectionThread.block();
            }
        }
    }

    /**
     * Handles an unknown request from the client.
     * 
     * @param length
     *            the length of the message.
     * @throws IOException
     */
    private void handleUnknownMessageType(int length) throws IOException {
        send(ServerProtocol.MessageType.UNKNOWN);
    }

    /**
     * Handles an authentication request from the client.
     * 
     * @param length
     *            the length of the message.
     * @return <code>true</code>, if the request was handled successfully.
     *         Otherwise, <code>false</code>.
     * @throws IOException
     */
    private boolean handlePostAuth(int length) throws IOException {
        Pair<String, String> credentials = ServerProtocol.postAuth(getBuffer(),
                length);
        boolean success = false;

        if (credentials != null) {
            /*
             * User name and password were parsed successfully. Check the
             * validity.
             */
            authenticated = Authentication.isValidCredentials(
                    credentials.getFirst(), credentials.getSecond());

            if (authenticated) {
                userName = credentials.getFirst();
                send(ServerProtocol.MessageType.SUCCESS_POST_AUTH);
                success = true;
            } else {
                send(ServerProtocol.MessageType.FAIL_POST_AUTH_VALIDITY);
            }
        } else {
            send(ServerProtocol.MessageType.FAIL_POST_AUTH_PARSE);
        }

        return success;
    }

    /**
     * Handles a PUT auth request from the client. Registers or updates a user.
     * 
     * @param length
     *            the length of the message.
     * @return <code>true</code>, if the request was handled successfully.
     *         Otherwise, <code>false</code>.
     * @throws IOException
     */
    private boolean handlePutAuth(int length) throws IOException {
        PutAuthData data = ServerProtocol.putAuth(getBuffer(), length);
        boolean success = false;

        if (data != null) {
            /*
             * User name, password, and current password were parsed
             * successfully. Check the validity of the current password, if the
             * user existed.
             */
            boolean databaseSuccess = false;
            boolean invalidPassword = false;

            synchronized (USER_LOCK) {
                boolean existsUser = DatabaseQueries.existsUser(data.getName());

                if (existsUser) {
                    // check the current password and update the entry
                    if (Authentication.isValidCredentials(data.getName(),
                            data.getCurrentPassword())) {
                        databaseSuccess = DatabaseQueries.updatetUser(
                                data.getName(), data.getPassword());
                    } else {
                        invalidPassword = true;
                    }
                } else {
                    // insert the entry
                    databaseSuccess = DatabaseQueries.insertUser(
                            data.getName(), data.getPassword());
                }
            }

            if (databaseSuccess) {
                send(ServerProtocol.MessageType.SUCCESS_PUT_AUTH);
                success = true;
            } else {
                if (invalidPassword) {
                    send(ServerProtocol.MessageType.FAIL_PUT_AUTH_VALIDITY);
                } else {
                    send(ServerProtocol.MessageType.FAIL_PUT_AUTH_DB_ERROR);
                }
            }
        } else {
            send(ServerProtocol.MessageType.FAIL_PUT_AUTH_PARSE);
        }

        return success;
    }

    /**
     * Handles a PUT folder request from the client. A folder can also be
     * updated with this request. This request is not supposed to be sent in
     * order to create private folders, although it works.
     * 
     * @param length
     *            the length of the message.
     * @return <code>true</code>, if the request was handled successfully.
     *         Otherwise, <code>false</code>.
     * @throws IOException
     */
    private boolean handlePutFolder(int length) throws IOException {
        boolean success = false;

        if (isAuthenticated()) {
            PutFolderData data = ServerProtocol.putFolder(getBuffer(), length);

            if (data == null) {
                send(ServerProtocol.MessageType.FAIL_PUT_FOLDER_PARSE);
            } else if (!FileHandler.isSharedFolderName(Paths.get(data
                    .getFolder()))) {
                send(ServerProtocol.MessageType.FAIL_PUT_FOLDER_NAME);
            } else {
                /*
                 * Authentication validation is the only required permission
                 * check, as the owner is the only person who is allowed to
                 * create a folder in its root directory through "PUT folder".
                 * The folder name must not equal . nor PRIVATE_FOLDER, as these
                 * folders contain the private files of the owner on the
                 * server's file system.
                 */
                boolean databaseSuccess = false;
                boolean exists = FileHandler.ROOT_PATH.toString().equals(
                        data.getFolder())
                        || PRIVATE_FOLDER.equals(data.getFolder());

                synchronized (FOLDER_LOCK) {
                    exists = exists
                            || (DatabaseQueries.getFolderEntry(userName,
                                    data.getFolder()) != null);

                    if (exists) {
                        /*
                         * Update the existing folder entry.
                         */
                        databaseSuccess = DatabaseQueries.updateFolder(
                                userName, data.getFolder(),
                                data.getKeyVersion(), data.getPermissions());
                    } else {
                        /*
                         * Try to create the folder entry in the database.
                         */
                        databaseSuccess = DatabaseQueries.insertFolder(
                                userName, data.getFolder(),
                                data.getPermissions(), data.getKeyVersion());
                    }
                }

                if (databaseSuccess) {
                    /*
                     * It is not necessary to create the folder on the file
                     * system, as it will be created automatically when the
                     * first file from the folder is uploaded.
                     */
                    send(ServerProtocol.MessageType.SUCCESS_PUT_FOLDER);
                    success = true;
                } else {
                    send(ServerProtocol.MessageType.FAIL_PUT_FOLDER_DB_ERROR);
                }
            }
        } else {
            handleAuthMissing();
        }

        return success;
    }

    /**
     * Handles a PUT file request from the client.
     * 
     * @param length
     *            the length of the message.
     * @return <code>true</code>, if the request was handled successfully.
     *         Otherwise, <code>false</code>.
     * @throws IOException
     */
    private boolean handlePutFile(int length) throws IOException {
        boolean success = false;

        if (isAuthenticated()) {
            PutFileData parameters = ServerProtocol
                    .putFile(getBuffer(), length);

            if (parameters == null) {
                send(ServerProtocol.MessageType.FAIL_PUT_FILE_PARSE);
            } else {
                String owner = (parameters.getOwner() != null) ? parameters
                        .getOwner() : userName;

                if (!hasPermission(owner, parameters.getFolder(),
                        AccessRight.WRITE)) {
                    send(ServerProtocol.MessageType.FAIL_PUT_FILE_PERMISSION);
                } else if (!holdsLock(owner, parameters.getFolder())) {
                    send(ServerProtocol.MessageType.FAIL_PUT_FILE_CONNECTION_LOCKED);
                } else {
                    /*
                     * Client has access permissions and has locked the correct
                     * folder.
                     */
                    // check minimum allowed key version
                    FolderEntry entry = DatabaseQueries.getFolderEntry(owner,
                            parameters.getFolder().toString());

                    if ((entry != null)
                            && (parameters.getKeyVersion() < entry
                                    .getKeyVersion())) {
                        send(ServerProtocol.MessageType.FAIL_PUT_FILE_KEY_VERSION_TOO_LOW);
                    } else if (((entry == null) && !FileHandler.ROOT_PATH
                            .equals(parameters.getFolder()))) {
                        /*
                         * Client wants to write in non-existing, non-private
                         * folder.
                         */
                        send(ServerProtocol.MessageType.FAIL_PUT_FILE_INVALID_PATH);
                    } else {
                        /*
                         * Note that we rely on the fact that the connection is
                         * locked and therefore only one user can upload a file
                         * at a time. This fact ensures that our file version is
                         * identical to the one created internally by
                         * insertFileAndHistory. However, insertFileAndHistory
                         * only inserts the entry, if our and the internal
                         * version number match.
                         */
                        int version = DatabaseQueries.getMaxHistoryVersion(
                                owner, parameters.getFolder().toString()) + 1;
                        Path storagePath = toAbsoluteFilePath(owner, parameters
                                .getFolder().toString(), version);

                        /*
                         * Accept the request and download the file on the
                         * server.
                         */
                        if (isValidFilePath(storagePath)) {
                            send(ServerProtocol.MessageType.SUCCESS_PUT_FILE_REQUEST);
                            FileHandler.makeParentDirs(storagePath);
                            boolean receivedWell = FileHandler.receiveFile(
                                    getInputStream(),
                                    parameters.toProtectedData(), storagePath);

                            if (receivedWell) {
                                Timestamp time = new Timestamp(
                                        new Date().getTime());
                                boolean fileExists = (DatabaseQueries
                                        .existsFileEntry(owner, parameters
                                                .getFolder().toString(),
                                                parameters.getFile().toString()) >= 1);
                                char action = fileExists ? ActionType.MODIFY
                                        .toChar() : ActionType.ADD.toChar();
                                boolean databaseSuccess = DatabaseQueries
                                        .insertFileAndHistory(
                                                owner,
                                                parameters.getFolder()
                                                        .toString(),
                                                parameters.getFile().toString(),
                                                time, parameters
                                                        .getKeyVersion(),
                                                parameters.isDiff(), parameters
                                                        .getHash(), parameters
                                                        .getSize(), parameters
                                                        .getExtra(), parameters
                                                        .getMAC(), time,
                                                action, parameters.getFile()
                                                        .toString(), null,
                                                version);

                                if (databaseSuccess) {
                                    send(ServerProtocol.MessageType.SUCCESS_PUT_FILE);
                                    success = true;
                                } else {
                                    Files.delete(storagePath);
                                    send(ServerProtocol.MessageType.FAIL_PUT_FILE_DB_ERROR);
                                }
                            } else {
                                Files.deleteIfExists(storagePath);
                                send(ServerProtocol.MessageType.FAIL_PUT_FILE_HASH_INVALID);
                            }
                        } else {
                            send(ServerProtocol.MessageType.FAIL_PUT_FILE_INVALID_PATH);
                        }
                    }
                }
            }
        } else {
            handleAuthMissing();
        }

        return success;
    }

    /**
     * Handles a GET metadata request from the client by sending a response
     * message with the metadata, if the request is valid.
     * 
     * @param length
     *            the length of the message.
     * @return <code>true</code>, if the request was handled successfully.
     *         Otherwise, <code>false</code>.
     * @throws IOException
     */
    private boolean handleGetMetadata(int length) throws IOException {
        boolean success = false;

        if (isAuthenticated()) {
            GetMetadataData parameters = ServerProtocol.getMetadata(
                    getBuffer(), length);

            if (parameters == null) {
                send(ServerProtocol.MessageType.FAIL_GET_METADATA_PARSE);
            } else {
                String owner = (parameters.getOwner() != null) ? parameters
                        .getOwner() : userName;

                if (!hasPermission(owner, parameters.getFolder(),
                        AccessRight.READ)) {
                    send(ServerProtocol.MessageType.FAIL_GET_METADATA_PERMISSION);
                } else {
                    int version = (parameters.getVersion() != 0) ? parameters
                            .getVersion() : DatabaseQueries.getMaxFileVersion(
                            owner, parameters.getFolder().toString(),
                            parameters.getFile().toString());
                    FileEntry entry = null;
                    boolean exists = (version >= 1)
                            && ((entry = DatabaseQueries.getFileEntry(owner,
                                    parameters.getFolder().toString(),
                                    parameters.getFile().toString(), version)) != null);

                    if (!exists) {
                        send(ServerProtocol.MessageType.FAIL_GET_METADATA_NON_EXISTING);
                    } else {
                        /*
                         * Send a response message with the file metadata.
                         */
                        byte[] responseMessage = ServerProtocol
                                .getMetadataResponse(new GetMetadataResponseData(
                                        entry.isDiff(), entry.getVersion(),
                                        entry.getSize(), entry.getHash(), entry
                                                .getKeyVersion(), entry
                                                .getExtra(), entry.getMAC()));
                        send(responseMessage);
                        success = true;
                    }
                }
            }
        } else {
            handleAuthMissing();
        }

        return success;
    }

    /**
     * Handles a GET file request from the client by sending a response message
     * with the file, if the request is valid.
     * 
     * @param length
     *            the length of the message.
     * @return <code>true</code>, if the request was handled successfully.
     *         Otherwise, <code>false</code>.
     * @throws IOException
     */
    private boolean handleGetFile(int length) throws IOException {
        boolean success = false;

        if (isAuthenticated()) {
            GetFileData parameters = ServerProtocol
                    .getFile(getBuffer(), length);

            if (parameters == null) {
                send(ServerProtocol.MessageType.FAIL_GET_FILE_PARSE);
            } else {
                String owner = (parameters.getOwner() != null) ? parameters
                        .getOwner() : userName;

                if (!hasPermission(owner, parameters.getFolder(),
                        AccessRight.READ)) {
                    send(ServerProtocol.MessageType.FAIL_GET_FILE_PERMISSION);
                } else {
                    int version = (parameters.getVersion() != 0) ? parameters
                            .getVersion() : DatabaseQueries.getMaxFileVersion(
                            owner, parameters.getFolder().toString(),
                            parameters.getFile().toString());
                    Path fileToTransmit = toAbsoluteFilePath(owner, parameters
                            .getFolder().toString(), version);
                    boolean exists = (version >= 1)
                            && (DatabaseQueries.getFileEntry(owner, parameters
                                    .getFolder().toString(), parameters
                                    .getFile().toString(), version) != null)
                            && isValidFilePath(fileToTransmit);

                    if (!exists) {
                        send(ServerProtocol.MessageType.FAIL_GET_FILE_NON_EXISTING);
                    } else {
                        /*
                         * Check whether the file exists and send it, if it
                         * does.
                         */
                        send(ServerProtocol.MessageType.SUCCESS_GET_FILE);

                        success = FileHandler.transmitFile(fileToTransmit,
                                parameters.getByteFirst(),
                                parameters.getByteLast(), getOutputStream());
                    }
                }
            }
        } else {
            handleAuthMissing();
        }

        return success;
    }

    /**
     * Handles a GET sync request from the client by sending a response message
     * with an array of the changes since the given synchronization point
     * version from the client request.
     * 
     * @param length
     *            the length of the message.
     * @return <code>true</code>, if the request was handled successfully.
     *         Otherwise, <code>false</code>.
     * @throws IOException
     */
    private boolean handleGetSync(int length) throws IOException {
        boolean success = false;

        /*
         * If there is already a lock present for this connection, do not try to
         * acquire another lock. There may only be one lock per connection.
         */
        if (isAuthenticated() && !connectionThread.holdsLock()) {
            GetSyncData parameters = ServerProtocol
                    .getSync(getBuffer(), length);

            if (parameters == null) {
                send(ServerProtocol.MessageType.FAIL_GET_SYNC_PARSE);
            } else {
                String owner = (parameters.getOwner() != null) ? parameters
                        .getOwner() : userName;

                if (!hasPermission(owner, parameters.getFolder(),
                        AccessRight.HISTORY)) {
                    send(ServerProtocol.MessageType.FAIL_GET_SYNC_PERMISSION);
                } else if (!FileHandler.ROOT_PATH
                        .equals(parameters.getFolder())
                        && (DatabaseQueries.getFolderEntry(owner, parameters
                                .getFolder().toString()) == null)) {
                    send(ServerProtocol.MessageType.FAIL_GET_SYNC_NON_EXISTING);
                } else {
                    /*
                     * The client-supplied folder exists and the client has
                     * access permissions. Release any previous lock, if
                     * present. Try to acquire the (owner, path) pair lock.
                     */
                    connectionThread.releaseLock();
                    Path path = parameters.getFolder();
                    LockPair lock = connectionThread.acquireLock(new LockPair(
                            owner, path));

                    if (lock != null) {
                        int version = parameters.getVersion();
                        /*
                         * Increment the version, as the sent version denotes
                         * the last handled synchronization point version.
                         */
                        version++;

                        /*
                         * Retrieve the history list for the (owner, path)
                         * combination.
                         */
                        ActionData[] responses = DatabaseQueries.getHistory(
                                owner, path.toString(), version);

                        if (responses != null) {
                            send(ServerProtocol.getSyncResponse(responses));
                            success = true;
                        } else {
                            send(ServerProtocol.MessageType.FAIL_GET_SYNC_DB_ERROR);
                        }
                    } else {
                        send(ServerProtocol.MessageType.FAIL_GET_SYNC_SERVER_LOCKED);
                    }
                }
            }
        } else if (!isAuthenticated()) {
            handleAuthMissing();
        } else {
            send(ServerProtocol.MessageType.FAIL_GET_SYNC_CONNECTION_LOCKED);
        }

        return success;
    }

    /**
     * Handles a POST sync DONE request from the client by releasing the
     * associated (owner, path) pair lock, if this lock exists.
     * 
     * @return <code>true</code>, if the request was handled successfully.
     *         Otherwise, <code>false</code>.
     * 
     * @throws IOException
     */
    private boolean handlePostSyncDone() throws IOException {
        boolean success = false;

        if (isAuthenticated() && connectionThread.holdsLock()) {
            boolean removed = connectionThread.releaseLock();

            if (removed) {
                success = true;
            } else {
                Logger.log(String.format("No lock was present."));
            }
        } else if (!isAuthenticated()) {
            handleAuthMissing();
        }

        return success;
    }

    /**
     * Handles a POST move request from the client by carrying out the move and
     * putting this event in the history and telling the client whether this was
     * done successfully.
     * 
     * @param length
     *            the length of the message.
     * @return <code>true</code>, if the request was handled successfully.
     *         Otherwise, <code>false</code>.
     * @throws IOException
     */
    private boolean handlePostMove(int length) throws IOException {
        boolean success = false;

        if (isAuthenticated()) {
            PostMoveData parameters = ServerProtocol.postMove(getBuffer(),
                    length);

            if (parameters != null) {
                String owner = (parameters.getOwner() != null) ? parameters
                        .getOwner() : userName;

                if (!hasPermission(owner, parameters.getFolder(),
                        AccessRight.WRITE)) {
                    send(ServerProtocol.MessageType.FAIL_POST_MOVE_PERMISSION);
                } else if (!holdsLock(owner, parameters.getFolder())) {
                    send(ServerProtocol.MessageType.FAIL_POST_MOVE_CONNECTION_LOCKED);
                } else {
                    /*
                     * Do not rename folders. Do not rename files on the server,
                     * as the history must stay consistent. But verify that the
                     * source file exists, while the destination file does NOT
                     * exist. Add a history entry for a file rename.
                     */
                    int srcVersion = DatabaseQueries.existsFileEntry(owner,
                            parameters.getFolder().toString(), parameters
                                    .getFrom().toString());

                    /*
                     * The source file must exist, while the destination file
                     * must not.
                     */
                    if ((srcVersion >= 1)
                            && (DatabaseQueries.existsFileEntry(owner,
                                    parameters.getFolder().toString(),
                                    parameters.getTo().toString()) < 1)) {
                        FileEntry fromEntry = DatabaseQueries.getFileEntry(
                                owner, parameters.getFolder().toString(),
                                parameters.getFrom().toString(), srcVersion);
                        Timestamp historyTime = new Timestamp(
                                new Date().getTime());
                        boolean databaseSuccess = DatabaseQueries
                                .insertFileAndHistory(owner, parameters
                                        .getFolder().toString(), parameters
                                        .getTo().toString(), fromEntry
                                        .getModified(), fromEntry
                                        .getKeyVersion(), fromEntry.isDiff(),
                                        fromEntry.getHash(), fromEntry
                                                .getSize(), fromEntry
                                                .getExtra(),
                                        fromEntry.getMAC(), historyTime,
                                        ActionType.RENAME.toChar(), parameters
                                                .getFrom().toString(),
                                        parameters.getTo().toString(), null);

                        if (databaseSuccess) {
                            send(ServerProtocol.MessageType.SUCCESS_POST_MOVE);
                            success = true;
                        } else {
                            send(ServerProtocol.MessageType.FAIL_POST_MOVE_DB_ERROR);
                        }
                    } else {
                        send(ServerProtocol.MessageType.FAIL_POST_MOVE_NON_EXISTING);
                    }
                }
            } else {
                send(ServerProtocol.MessageType.FAIL_POST_MOVE_PARSE);
            }
        } else {
            handleAuthMissing();
        }

        return success;
    }

    /**
     * Handles a DELETE file request from the client by putting this event in
     * the history and telling the client whether this was done successfully.
     * 
     * @param length
     *            the length of the message.
     * @return <code>true</code>, if the request was handled successfully.
     *         Otherwise, <code>false</code>.
     * @throws IOException
     */
    private boolean handleDeleteFile(int length) throws IOException {
        boolean success = false;

        if (isAuthenticated()) {
            DeleteFileData data = ServerProtocol
                    .deleteFile(getBuffer(), length);

            if (data != null) {
                String owner = (data.getOwner() != null) ? data.getOwner()
                        : userName;

                if (!hasPermission(owner, data.getFolder(), AccessRight.WRITE)) {
                    send(ServerProtocol.MessageType.FAIL_DELETE_FILE_PERMISSION);
                } else if (!holdsLock(owner, data.getFolder())) {
                    send(ServerProtocol.MessageType.FAIL_DELETE_FILE_CONNECTION_LOCKED);
                } else {
                    int fileVersion = DatabaseQueries.existsFileEntry(owner,
                            data.getFolder().toString(), data.getFile()
                                    .toString());

                    if (fileVersion > 0) {
                        boolean databaseSuccess = DatabaseQueries
                                .insertHistory(owner, data.getFolder()
                                        .toString(),
                                        new Timestamp(new Date().getTime()),
                                        ActionType.DELETE.toChar(), data
                                                .getFile().toString(), null);

                        if (databaseSuccess) {
                            send(ServerProtocol.MessageType.SUCCESS_DELETE_FILE);
                            success = true;
                        } else {
                            send(ServerProtocol.MessageType.FAIL_DELETE_FILE_DB_ERROR);
                        }
                    } else {
                        send(ServerProtocol.MessageType.FAIL_DELETE_FILE_NON_EXISTING);
                    }
                }
            } else {
                send(ServerProtocol.MessageType.FAIL_DELETE_FILE_PARSE);
            }
        } else {
            handleAuthMissing();
        }

        return success;
    }

    /**
     * Returns the path under the owner's directory on the server of the given
     * relative file path.
     * 
     * @param owner
     *            the owner of the file.
     * @param folder
     *            the server folder sent by the client relative to the owner's
     *            root directory.
     * @param version
     *            the version of the file.
     * @return the path under the owner's directory on the server of the given
     *         relative server path.
     */
    private Path toAbsoluteFilePath(String owner, String folder, int version) {
        assert ((owner != null) && (folder != null) && (version >= 1));
        String upperMostDirectory = FileHandler.ROOT_PATH.toString().equals(
                folder) ? PRIVATE_FOLDER : folder;
        return Paths.get(clientDirectory.toString(), owner, upperMostDirectory,
                Integer.toString(version));
    }

    /**
     * Returns whether the given path is a valid file path pointing to a user
     * file. Must be called to prevent directory traversal attacks.
     * 
     * @param path
     *            the path to check. May be absolute or relative to the current
     *            directory.
     * @return <code>true</code>, if the path is valid. Otherwise,
     *         <code>false</code>.
     */
    private boolean isValidFilePath(Path path) {
        if (path == null) {
            return false;
        }

        Path absolutePath = path.normalize().toAbsolutePath();
        boolean isSubPath = absolutePath.startsWith(clientDirectoryAbsolute);
        // name count must equal three: owner/folder/fileVersion
        return isSubPath
                && (absolutePath.relativize(clientDirectoryAbsolute)
                        .getNameCount() == 3);
    }

    /**
     * Handles requests from unauthenticated clients. The client is informed
     * that it has not successfully authenticated towards the server.
     * 
     * @throws IOException
     */
    private void handleAuthMissing() throws IOException {
        send(ServerProtocol.MessageType.FAIL_POST_AUTH_MISSING);
    }

    /**
     * Returns whether the client already authenticated itself towards the
     * server.
     * 
     * @return <code>true</code>, if the client is authenticated. Otherwise,
     *         <code>false</code> is returned.
     */
    private boolean isAuthenticated() {
        return authenticated;
    }

    /**
     * Represents an access right.
     * 
     * @author Fabian Foerg
     */
    private static enum AccessRight {
        READ,
        WRITE,
        HISTORY;
    }

    /**
     * Returns <code>true</code>, if and only if the connected user has the
     * given access rights.
     * 
     * @param owner
     *            the owner of the resource to access.
     * @param folder
     *            the owner's folder of the resource to access.
     * @param right
     *            the access right to look for.
     * @return <code>true</code>, if the connected user has the permission to
     *         access the file. <code>false</code>, otherwise.
     */
    private boolean hasPermission(String owner, Path folder, AccessRight right) {
        assert ((folder != null) && (right != null));

        boolean permitted = false;

        if (userName != null) {
            if (userName.equals(owner)) {
                // the owner has all access rights for its files
                permitted = true;
            } else {
                // We deal with a shared folder or a private folder of the owner
                Permission[] permissions = DatabaseQueries.getPermissions(
                        owner, folder.toString());

                if (permissions != null) {
                    for (Permission permission : permissions) {
                        if (!permitted) {
                            switch (right) {
                            case READ:
                                if (Permission.PUBLIC.equals(permission)
                                        || userName.equals(permission
                                                .getMember())) {
                                    permitted = true;
                                }
                                break;

                            case WRITE:
                                if (userName.equals(permission.getMember())
                                        && permission.mayWrite()) {
                                    permitted = true;
                                }
                                break;

                            case HISTORY:
                                if (Permission.PUBLIC.equals(permission)
                                        || (userName.equals(permission
                                                .getMember()) && permission
                                                .mayReadHistory())) {
                                    permitted = true;
                                }
                                break;

                            default:
                                break;
                            }
                        } else {
                            /*
                             * We have the given access rights and stop
                             * searching.
                             */
                            break;
                        }
                    }
                }
            }
        }

        return permitted;
    }

    /**
     * Returns whether this connection holds a lock on the given (owner, folder)
     * pair.
     * 
     * @param owner
     *            the owner of the folder.
     * @param folder
     *            the server folder.
     * @return <code>true</code>, if the lock is held. Otherwise,
     *         <code>false</code>.
     */
    private boolean holdsLock(String owner, Path folder) {
        return ((owner != null) && (folder != null)) ? connectionThread
                .holdsLock(new LockPair(owner, folder)) : false;
    }
}
