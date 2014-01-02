package client;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import misc.Coder;
import misc.FileHandler;
import misc.Logger;
import misc.diff.DifferFactory;
import misc.diff.DifferFactory.DifferImplementation;
import misc.network.ConnectionHandler;
import misc.network.SecureSelfHealSocket;
import protocol.ClientProtocol;
import protocol.DataContainers;
import protocol.DataContainers.ActionData;
import protocol.DataContainers.DeleteFileData;
import protocol.DataContainers.GetFileData;
import protocol.DataContainers.GetMetadataData;
import protocol.DataContainers.GetMetadataResponseData;
import protocol.DataContainers.GetSyncData;
import protocol.DataContainers.Pair;
import protocol.DataContainers.PostMoveData;
import protocol.DataContainers.ProtectedData;
import protocol.DataContainers.PutAuthData;
import protocol.DataContainers.PutFileData;
import protocol.DataContainers.PutFolderData;
import protocol.DataContainers.Triple;
import protocol.ServerProtocol;
import client.executors.SynchronizationExecutor;
import configuration.AccessBundle;
import configuration.ClientConfiguration;
import configuration.GroupAccessBundle;
import configuration.Key;

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
 * Handles client connections. Implements the client protocol. Is thread-safe,
 * although instances of this class are not supposed to be accessed by multiple
 * threads concurrently. Only one folder may be synchronized at a time.
 * 
 * @author Fabian Foerg
 */
public final class ClientConnectionHandler extends ConnectionHandler {
    /**
     * Name of the synchronization lock file. If placed in the root directory,
     * no folder is synchronized. Can be put into a shared folder in order to
     * lock only the shared folder.
     */
    public static final String LOCK_FILE = ".lock";

    /**
     * The buffer size in bytes of the message buffer.
     */
    private static final int BUFFER_SIZE = 1024 * 1024;
    /**
     * The date format for the conflicted file suffix.
     */
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat(
            "yyyy-MM-dd HH.mm.ss");

    private final SecureSelfHealSocket socket;
    private final ClientConfiguration config;
    private final Path fileFolder;
    private final Path syncFolder;

    /**
     * Set when getSync is called. Used for re-syncing in this.send when the
     * connection fails.
     */
    private GetSyncData syncData;
    /**
     * Set when getSync is called. Used for re-syncing in this.send when the
     * connection fails.
     */
    private Path pathLocal;

    /**
     * Creates a new client connection handler.
     * 
     * @param socket
     *            the associated socket.
     * @param config
     *            the client configuration. May not be <code>null</code>.
     */
    public ClientConnectionHandler(SecureSelfHealSocket socket,
            ClientConfiguration config) {
        super(BUFFER_SIZE, socket, ServerProtocol.Messages.DELIMITER);

        if (config == null) {
            throw new NullPointerException("config may not be null!");
        }

        this.socket = socket;
        this.config = config;
        this.fileFolder = Paths.get(config.getRootPath()).normalize();
        this.syncFolder = Paths.get(config.getSyncPath()).normalize();
        syncData = null;
        pathLocal = null;
    }

    /**
     * Attempts to send the given message. If the socket is closed, otherwise
     * unusable or when an <code>IOException</code> occurs while sending, the
     * connection is re-established, re-authenticated, re-synchronized if
     * applicable. Then the message is sent again.
     * 
     * @param message
     *            the message to send.
     * @param syncData
     *            the syncData to send to the server in order to synchronize the
     *            client before the message is sent again after a failed send
     *            attempt. A lost connection results in a lost lock on a folder
     *            and therefore possible changes from other clients need to be
     *            synchronized when a connection is re-established. May be
     *            <code>null</code> , if and only if the folder does not need to
     *            be synchronized.
     * @param pathLocal
     *            the local path to sync. May be <code>null</code>, if and only
     *            if <code>syncData</code> is <code>null</code>.
     * @return <code>true</code>, if the message was successfully sent to the
     *         server. Otherwise, <code>false</code>.
     */
    private boolean send(byte[] message, GetSyncData syncData, Path pathLocal) {
        assert (message != null)
                && !((syncData != null) && (pathLocal == null));
        boolean success = false;
        boolean needsRebuild = socket.needsRebuild();

        if (needsRebuild) {
            success = reconnectAndSend(message);
        } else {
            try {
                send(message);
                success = true;
            } catch (IOException e) {
                Logger.logError(e);
                success = reconnectAndSend(message);
            }
        }

        return success;
    }

    /**
     * Connects to the server, authenticates itself to the server, and
     * synchronizes the current folder if necessary. Then the given message is
     * sent to the server.
     * 
     * @param message
     *            the message to send.
     * @return <code>true</code>, if the message was successfully sent to the
     *         server. Otherwise, <code>false</code>.
     */
    private boolean reconnectAndSend(byte[] message) {
        boolean success = false;
        boolean connected = socket.rebuild(true);

        if (connected) {
            Logger.log("Re-connected! Authenticating.");
            /*
             * We need to re-authenticate, as the socket connection was closed.
             * Additionally, we need to synchronize again and obtain locks, if
             * applicable.
             */
            boolean authenticated = postAuth(config.getUser(),
                    config.getPassword());

            try {
                if (authenticated) {
                    boolean synced = true;

                    Logger.log("Authenticated!");

                    if (syncData != null) {
                        Logger.log("Syncing data.");
                        synced = (getSync(syncData, new ActionData[0],
                                pathLocal, false) != null);
                        if (synced) {
                            Logger.log("Synced!");
                        }
                    }

                    if (synced) {
                        Logger.log(String.format("Sending message %s again.",
                                Coder.byteToString(message)));
                        send(message);
                        success = true;
                    }
                }
            } catch (IOException eInner) {
                Logger.logError(eInner);
            }
        } else {
            Logger.logError("Cannot re-establish connection to server!");
        }

        return success;
    }

    /**
     * Sends a POST auth request to the server and waits for the response of the
     * server. Returns whether the authentication request was accepted by the
     * server.
     * 
     * @param userName
     *            the user name.
     * @param password
     *            the plain text password.
     * @return <code>true</code>, if the server accepted our request. Otherwise,
     *         <code>false</code> is returned.
     */
    public synchronized boolean postAuth(String userName, String password) {
        boolean success = false;
        byte[] message = ClientProtocol.postAuth(userName, password);

        try {
            /*
             * Do not use this.send, as doing so could result in an infinite
             * connection re-establishment loop.
             */
            send(message);
            /*
             * Check whether our authentication attempt succeeded.
             */
            int length = readNextMessage();
            ServerProtocol.MessageType messageType = ServerProtocol
                    .identifyResponse(getBuffer(), length);
            String reply = String.format("%s user=%s", messageType.toString(),
                    userName);

            if (ServerProtocol.MessageType.SUCCESS_POST_AUTH
                    .equals(messageType)) {
                success = true;
                Logger.log(reply);
            } else {
                Logger.logError(reply);
            }
        } catch (IOException e) {
            Logger.logError(e);
        }

        return success;
    }

    /**
     * Sends a POST auth request to the server and waits for the response of the
     * server. Returns whether the authentication request was accepted by the
     * server.
     * 
     * @param data
     *            the data to send to the server.
     * @return <code>true</code>, if the server accepted our request. Otherwise,
     *         <code>false</code> is returned.
     */
    public synchronized boolean putAuth(PutAuthData data) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }

        boolean success = false;
        byte[] message = ClientProtocol.putAuth(data);
        send(message, null, null);

        /*
         * Check whether our PUT auth request succeeded.
         */
        int length = readNextMessage();
        ServerProtocol.MessageType messageType = ServerProtocol
                .identifyResponse(getBuffer(), length);
        String reply = String.format("%s user=%s", messageType.toString(),
                data.getName());

        if (ServerProtocol.MessageType.SUCCESS_PUT_AUTH.equals(messageType)) {
            success = true;
            Logger.log(reply);
        } else {
            Logger.logError(reply);
        }

        return success;
    }

    /**
     * Sends a PUT folder request to the server and waits for the response of
     * the server. Returns whether the create folder request was accepted by the
     * server.
     * 
     * @param data
     *            the data to send to the server.
     * @return <code>true</code>, if the server accepted our request. Otherwise,
     *         <code>false</code> is returned.
     */
    public synchronized boolean putFolder(PutFolderData data) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }

        boolean success = false;
        byte[] message = ClientProtocol.putFolder(data);
        send(message, null, null);

        /*
         * Check whether our PUT folder request was successful.
         */
        int length = readNextMessage();
        ServerProtocol.MessageType messageType = ServerProtocol
                .identifyResponse(getBuffer(), length);
        String reply = String.format("%s folder=%s", messageType.toString(),
                data.getFolder());

        if (ServerProtocol.MessageType.SUCCESS_PUT_FOLDER.equals(messageType)) {
            success = true;
            Logger.log(reply);
        } else {
            Logger.logError(reply);
        }

        return success;
    }

    /**
     * Sends a PUT file request to the server and waits for the response of the
     * server. If the server accepts the file, the file is encrypted if desired
     * and eventually transmitted. Puts a plaintext copy of the complete sent
     * file in the synchronization folder.
     * 
     * @param owner
     *            the owner of the file. May be <code>null</code>.
     * @param serverFolder
     *            the relative path to the owner's root directory containing the
     *            file.
     * @param serverFile
     *            the relative path to <code>serverFolder</code> of the file on
     *            the server. May not be <code>null</code>.
     * @param localFile
     *            the relative path to the client's root directory of the
     *            original file.
     * @param isDiff
     *            <code>true</code>, if the local file is a diff.
     *            <code>false</code>, otherwise.
     * @param diff
     *            the complete path to the diff file. If <code>isDiff</code> is
     *            <code>true</code>, this parameter may not be <code>null</code>
     *            .
     * @return <code>true</code>, if the file was successfully transmitted.
     *         Otherwise, <code>false</code> is returned.
     */
    private boolean putFile(String owner, Path serverFolder, Path serverFile,
            Path localFile, boolean isDiff, Path diff) {
        if (!FileHandler.isFolderName(serverFolder)) {
            throw new IllegalArgumentException(
                    "serverFolder must be a valid folder name!");
        }
        if (!FileHandler.isFileName(serverFile)) {
            throw new IllegalArgumentException(
                    "serverFile must be a valid file name!");
        }
        if (localFile == null) {
            throw new NullPointerException("localFile may not be null!");
        }
        if (isDiff && (diff == null)) {
            throw new IllegalArgumentException(
                    "if isDiff is true, diff must not be null!");
        }

        boolean success = false;

        /*
         * Encrypt the file if desired and compute the hash and MAC of the
         * encrypted data.
         */
        PutFileData dataToSend = null;
        Triple<Path, ProtectedData, byte[]> result = FileHandler.getData(
                fileFolder, localFile, isDiff, diff);

        if (result != null) {
            dataToSend = PutFileData.from(result.getSecond(), owner,
                    serverFolder, serverFile, result.getThird());
        }

        if (dataToSend == null) {
            Logger.logError(String.format("Cannot PUT file %s",
                    localFile.toString()));
            return success;
        }

        Path plaintextFile = Paths.get(fileFolder.toString(),
                localFile.toString()).normalize();
        Path toTransmit = result.getFirst().normalize(); // can be encrypted

        if (!Files.isReadable(plaintextFile) || !Files.isReadable(toTransmit)) {
            Logger.logError(String.format(
                    "File %s or file %s are not readable!",
                    plaintextFile.toString(), toTransmit.toString()));
        } else {
            byte[] message = ClientProtocol.putFile(dataToSend);
            assert ((syncData != null) && (pathLocal != null));
            send(message, syncData, pathLocal);

            /*
             * Check whether our PUT file request was successful.
             */
            int length = readNextMessage();
            ServerProtocol.MessageType messageType = ServerProtocol
                    .identifyResponse(getBuffer(), length);
            String requestMessage = String.format("%s file=%s",
                    messageType.toString(), localFile.toString());

            if (ServerProtocol.MessageType.SUCCESS_PUT_FILE_REQUEST
                    .equals(messageType)) {
                Logger.log(requestMessage);

                // upload the possibly encrypted file to the server.
                FileHandler.transmitFile(toTransmit, null, null,
                        getOutputStream());
                length = readNextMessage();
                messageType = ServerProtocol.identifyResponse(getBuffer(),
                        length);
                String putFileMessage = String.format("%s file=%s",
                        messageType.toString(), localFile.toString());

                if (ServerProtocol.MessageType.SUCCESS_PUT_FILE
                        .equals(messageType)) {
                    // put a local copy of the plaintext file in the sync folder
                    Path syncFile = Paths.get(syncFolder.toString(),
                            localFile.toString());
                    FileHandler.makeParentDirs(syncFile);
                    success = FileHandler.copyFile(plaintextFile, syncFile,
                            true);

                    if (success) {
                        Logger.log(putFileMessage);
                    } else {
                        /*
                         * Do not accept partially written synchronization
                         * files.
                         */
                        Logger.logError(String
                                .format("Error copying local file %s in synchronization directory.",
                                        plaintextFile.toString()));

                        try {
                            Files.deleteIfExists(syncFile);
                        } catch (IOException e) {
                            Logger.logError(e);
                        }
                    }
                } else {
                    Logger.logError(putFileMessage);
                }
            } else {
                Logger.logError(requestMessage);
            }
        }

        // delete the possibly encrypted file, if one was created.
        if (!plaintextFile.equals(toTransmit)) {
            try {
                Files.delete(toTransmit);
            } catch (IOException e) {
                Logger.logError(e);
            }
        }

        return success;
    }

    /**
     * Moves a file or a folder on the server by sending a POST move request.
     * Checks whether the rename is valid according to the synchronization tree
     * structure first.
     * 
     * @param data
     *            the data for the move.
     * @param relativeSyncFileName
     *            the name of the synchronization file which has to be renamed,
     *            relative to the root directory.
     * @param relativeRealFileName
     *            the name of the existing real file in the file folder relative
     *            to the root directory.
     * @return <code>true</code>, if the request was carried out successfully.
     *         Otherwise, <code>false</code> is returned.
     */
    private boolean postMove(PostMoveData data, Path relativeSyncFileName,
            Path relativeRealFileName) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }
        if (relativeSyncFileName == null) {
            throw new NullPointerException(
                    "relativeSyncFileName may not be null!");
        }
        if (relativeRealFileName == null) {
            throw new NullPointerException(
                    "relativeRealFileName may not be null!");
        }

        boolean success = false;
        // try to rename the sync file
        Path syncFile = Paths.get(syncFolder.toString(),
                relativeSyncFileName.toString()).normalize();
        Path renamedSyncFile = Paths.get(syncFolder.toString(),
                relativeRealFileName.toString()).normalize();

        if (Files.exists(syncFile) && !Files.exists(renamedSyncFile)) {
            byte[] message = ClientProtocol.postMove(data);
            assert ((syncData != null) && (pathLocal != null));
            send(message, syncData, pathLocal);

            /*
             * Check whether our POST move request was successful.
             */
            int length = readNextMessage();
            ServerProtocol.MessageType messageType = ServerProtocol
                    .identifyResponse(getBuffer(), length);
            String reply = String.format("%s owner=%s from=%s to=%s",
                    messageType.toString(), data.getOwner(), data.getFrom()
                            .toString(), data.getTo().toString());

            if (ServerProtocol.MessageType.SUCCESS_POST_MOVE
                    .equals(messageType)) {
                FileHandler.makeParentDirs(renamedSyncFile);
                try {
                    Files.move(syncFile, renamedSyncFile);
                    success = true;
                    Logger.log(reply);
                } catch (IOException e) {
                    Logger.logError(e);
                }
            } else {
                Logger.logError(reply);
            }
        } else {
            Logger.logError(String
                    .format("POST MOVE owner=%s from=%s to=%s failed, as this move is inconsistent with the history!",
                            data.getOwner(), data.getFrom().toString(), data
                                    .getTo().toString()));
        }

        return success;
    }

    /**
     * Delete a file on the server by sending a DELETE file request. The file is
     * not really deleted on the server side in order to keep the history
     * consistent. Instead an entry is added to the history table. The
     * synchronization file of the deleted file is deleted on the client. If the
     * synchronization file does not exist, no request is sent and
     * <code>false</code> is returned.
     * 
     * @param owner
     *            the owner of the file to delete. May be <code>null</code>.
     * @param serverFolder
     *            the relative path to the owner's root directory containing the
     *            file.
     * @param serverFile
     *            the relative path to <code>serverFolder</code> of the file on
     *            the server. May not be <code>null</code>.
     * @param syncFile
     *            the file to delete locally, if the request was carried out
     *            successfully on the server.
     * @return <code>true</code>, if the request was carried out successfully.
     *         Otherwise, <code>false</code> is returned.
     */
    private boolean deleteFile(String owner, Path serverFolder,
            Path serverFile, Path syncFile) {
        if (!FileHandler.isFolderName(serverFolder)) {
            throw new IllegalArgumentException(
                    "serverFolder must be a valid folder name!");
        }
        if (!FileHandler.isFileName(serverFile)) {
            throw new IllegalArgumentException(
                    "serverFile must be a valid file name!");
        }
        if (syncFile == null) {
            throw new NullPointerException("syncFile may not be null!");
        }

        boolean success = false;

        if (Files.exists(syncFile)) {
            byte[] message = ClientProtocol.deleteFile(new DeleteFileData(
                    owner, serverFolder, serverFile));
            assert ((syncData != null) && (pathLocal != null));
            send(message, syncData, pathLocal);

            /*
             * Check whether our DELETE file request was successful.
             */
            int length = readNextMessage();
            ServerProtocol.MessageType messageType = ServerProtocol
                    .identifyResponse(getBuffer(), length);
            String reply = String.format("%s owner=%s file=%s",
                    messageType.toString(), owner, serverFile.toString());

            if (ServerProtocol.MessageType.SUCCESS_DELETE_FILE
                    .equals(messageType)) {
                try {
                    Files.delete(syncFile);
                    success = true;
                    Logger.log(reply);
                } catch (IOException e) {
                    Logger.logError(e);
                }
            } else {
                Logger.logError(reply);
            }
        } else {
            Logger.logError(String.format(
                    "DELETE failed, as sync file %s does not exist!",
                    syncFile.toString()));
        }

        return success;
    }

    /**
     * Get file metadata from the server by sending a GET metadata request,
     * parsing the server's response. Checks the metadata, if an integrity key
     * is provided.
     * 
     * @param data
     *            the data values sent to the server.
     * @param prefix
     *            the path to the client's root directory. May not be
     *            <code>null</code>.
     * @param folder
     *            a folder path relative to prefix which contains an access
     *            bundle. May not be <code>null</code>.
     * @return the parsed metadata or <code>null</code>, if the metadata is not
     *         available, cannot be parsed or if its possibly present MAC cannot
     *         be verified.
     */
    public synchronized GetMetadataResponseData getMetadata(
            GetMetadataData data, Path prefix, Path folder) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }
        if (prefix == null) {
            throw new NullPointerException("prefix may not be null!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }

        GetMetadataResponseData result = null;
        byte[] message = ClientProtocol.getMetadata(data);
        send(message, null, null);

        /*
         * Check whether our GET metadata request was successful.
         */
        int length = readNextMessage();
        ServerProtocol.MessageType messageType = ServerProtocol
                .identifyResponse(getBuffer(), length);

        if (ServerProtocol.MessageType.SUCCESS_GET_METADATA.equals(messageType)) {
            /*
             * Parse the metadata of the file from the server response message.
             */
            result = ClientProtocol.getMetadataResponse(getBuffer(), length);

            if (result != null) {
                if (result.getMAC() != null) {
                    AccessBundle bundle = FileHandler.getAccessBundle(prefix,
                            folder);

                    if (bundle != null) {
                        if (result.getKeyVersion() != DataContainers.PUBLIC_FILE_KEY_VERSION) {
                            // check integrity
                            ProtectedData protectedData = new ProtectedData(
                                    result.isDiff(), result.getSize(),
                                    result.getHash(), result.getKeyVersion(),
                                    result.getExtra());
                            Key integrityKey = bundle.getIntegrityKey(result
                                    .getKeyVersion());

                            if (integrityKey != null) {
                                boolean valid = MessageDigest.isEqual(
                                        protectedData.getMAC(integrityKey),
                                        result.getMAC());

                                if (!valid) {
                                    result = null;
                                    Logger.logError(String.format(
                                            "Cannot verify MAC for file %s",
                                            data.getFile().toString()));
                                }
                            } else {
                                /*
                                 * There is not an integrity key, although there
                                 * is supposed to be one.
                                 */
                                result = null;
                                Logger.logError(String.format(
                                        "Integrity key missing for %s", data
                                                .getFile().toString()));
                            }
                        }
                        /*
                         * else: the file is public; thus, there is no MAC to
                         * verify.
                         */
                    } else {
                        result = null;
                        Logger.logError(String.format(
                                "Cannot parse bundle for file %s", data
                                        .getFile().toString()));
                    }
                }
            } else {
                Logger.logError(String
                        .format("Parse error for server's GET metadata response for file %s",
                                data.getFile().toString()));
            }
        } else {
            Logger.logError(String.format("%s file=%s", messageType.toString(),
                    data.getFile().toString()));
        }

        return result;
    }

    /**
     * Get a file from the server by sending a GET metadata request, checking
     * the metadata, sending a GET file request and downloading the file. Does
     * not patch the received file. Puts a copy of the received file in the
     * synchronization folder, if the copy is not a diff.
     * 
     * @param data
     *            the data values sent to the server.
     * @param pathLocal
     *            the local folder path relative to the client's root directory.
     *            May not be <code>null</code>.
     * @param fileName
     *            the name of the file relative to <code>pathLocal</code>. May
     *            not be <code>null</code>.
     * @param toStore
     *            the complete path where the received file is supposed to be
     *            stored. May not be <code>null</code>.
     * @return the first part of the pair is <code>true</code>, if the file was
     *         received successfully. Otherwise, the first part is
     *         <code>false</code>. The second part comprises the file metadata
     *         from the server of <code>null</code>, if the metadata could not
     *         be retrieved.
     */
    public synchronized Pair<Boolean, GetMetadataResponseData> getFile(
            GetFileData data, Path pathLocal, Path fileName, Path toStore) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }
        if (pathLocal == null) {
            throw new NullPointerException("pathLocal may not be null!");
        }
        if (fileName == null) {
            throw new NullPointerException("fileName may not be null!");
        }
        if (toStore == null) {
            throw new NullPointerException("toStore may not be null!");
        }

        boolean success = false;
        Path relativeFileName = Paths.get(pathLocal.toString(),
                fileName.toString());
        Path accessBundleDirectory = FileHandler.getAccessBundleDirectory(
                fileFolder, relativeFileName);
        GetMetadataResponseData responseData = getMetadata(
                data.toMetadataData(), fileFolder, accessBundleDirectory);

        if (responseData == null) {
            return new Pair<Boolean, GetMetadataResponseData>(false, null);
        }

        /*
         * Metadata received and verified successfully. Get the file.
         */
        byte[] message = ClientProtocol.getFile(data);
        send(message, null, null);

        /*
         * Check whether our GET file request was successful.
         */
        int length = readNextMessage();
        ServerProtocol.MessageType messageType = ServerProtocol
                .identifyResponse(getBuffer(), length);
        String reply = String.format("%s file=%s", messageType.toString(),
                toStore.toString());

        if (ServerProtocol.MessageType.SUCCESS_GET_FILE.equals(messageType)) {
            boolean receivedWell = false;
            Path plaintextFile = toStore;

            // create parent directories for the file to get, if required.
            FileHandler.makeParentDirs(plaintextFile);

            // receive and possibly convert the file to plaintext
            receivedWell = FileHandler.receiveAndConvert(getInputStream(),
                    responseData.toProtectedData(), fileFolder,
                    accessBundleDirectory, plaintextFile);

            if (receivedWell) {
                boolean exception = false;
                Path syncFile = Paths.get(syncFolder.toString(),
                        pathLocal.toString(), fileName.toString());

                if (!responseData.isDiff()) {
                    // put a local copy in the sync folder
                    FileHandler.makeParentDirs(syncFile);
                    exception = !FileHandler.copyFile(plaintextFile, syncFile,
                            true);
                }

                if (!exception) {
                    success = true;
                    Logger.log(reply);
                } else {
                    /*
                     * Do not accept partially written synchronization files.
                     */
                    Logger.logError(String
                            .format("Error copying local file %s in synchronization directory.",
                                    plaintextFile.toString()));

                    try {
                        Files.deleteIfExists(syncFile);
                    } catch (IOException e) {
                        Logger.logError(e);
                    }
                }
            } else {
                try {
                    Files.deleteIfExists(plaintextFile);
                } catch (IOException e) {
                    Logger.logError(e);
                }
            }
        } else {
            Logger.logError(reply);
        }

        return new Pair<Boolean, GetMetadataResponseData>(success, responseData);
    }

    /**
     * Synchronize the client's directory by sending a GET sync request to the
     * server, parsing the result and carrying out the parsed actions. If all
     * parsed actions were carried out successfully, the given actions are
     * carried out. Finally, local changes are synchronized with the server, if
     * desired. Local changes are committed, even if the execution of the given
     * local actions failed. During synchronization a lock is held on the
     * server.
     * 
     * @param data
     *            the GET sync data to send to the server.
     * @param actions
     *            actions to be taken after synchronizing with the server and
     *            before committing local changes. May be empty, but not
     *            <code>null</code>.
     * @param pathLocal
     *            the local path to synchronize containing an access bundle.
     *            Must be relative to the client root directory. May not be
     *            <code>null</code>.
     * @param commitLocalChanges
     *            <code>true</code>, if local changes are to be committed.
     *            Otherwise, <code>false</code>.
     * @return the new version number up to which we executed all
     *         synchronization actions or <code>null</code>, if the given folder
     *         is currently locked or if an error occurred.
     */
    public synchronized Integer getSync(GetSyncData data, ActionData[] actions,
            Path pathLocal, boolean commitLocalChanges) {
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }
        if (actions == null) {
            throw new NullPointerException("actions may not be null!");
        }
        if (pathLocal == null) {
            throw new NullPointerException("pathLocal may not be null!");
        }

        /*
         * syncVersion is the synchronization version of the already handled
         * responses.
         */
        int syncVersion = data.getVersion();
        /*
         * increments counts the additional version increments due to conflict
         * resolving
         */
        int increments = 0;

        /*
         * Check for lock file in the file root directory and the directory to
         * synchronize.
         */
        if (Files.exists(Paths.get(fileFolder.toString(), LOCK_FILE))
                || Files.exists(Paths.get(fileFolder.toString(),
                        pathLocal.toString(), LOCK_FILE))) {
            Logger.logError(String.format(
                    "Lock file is present. We do not synchronize folder %s",
                    pathLocal.toString()));
            return null;
        }

        byte[] message = ClientProtocol.getSync(data);
        send(message, null, null);

        this.syncData = data;
        this.pathLocal = pathLocal;

        /*
         * Check whether our GET sync request was successful.
         */
        int length = readNextMessage();
        ServerProtocol.MessageType messageType = ServerProtocol
                .identifyResponse(getBuffer(), length);

        if (ServerProtocol.MessageType.SUCCESS_GET_SYNC.equals(messageType)) {
            /*
             * Parse the synchronization actions from the server response
             * message.
             */
            ActionData[] serverResponses = ClientProtocol.getSyncResponse(
                    getBuffer(), length);

            if (serverResponses != null) {
                for (ActionData response : serverResponses) {
                    Integer success = executeAction(response, data.getOwner(),
                            data.getFolder(), pathLocal);
                    String prefix = (success != null) ? "SUCCESS" : "FAIL";
                    String logMessage = String
                            .format("%s server action %s, version %s, path %s, object %s",
                                    prefix, response.getAction(),
                                    response.getVersion(),
                                    pathLocal.toString(), response.getObject());

                    if (success != null) {
                        syncVersion = response.getVersion();
                        increments += success;
                        Logger.log(logMessage);
                    } else {
                        Logger.logError(logMessage);

                        /*
                         * If increments > 0, there is a gap containing undone
                         * actions between executed action numbers on this
                         * client.
                         */
                        if (increments > 0) {
                            Logger.logError("There is a is a gap containing undone "
                                    + "actions between executed action numbers "
                                    + "on this client");
                        }

                        increments = 0;
                        break;
                    }
                }

                /*
                 * Check whether all responses were carried out successfully. If
                 * this is the case, try to commit the given actions and commit
                 * all other local changes.
                 */
                if (syncVersion == (data.getVersion() + serverResponses.length)) {
                    Integer actionsTaken = 0;
                    Pair<Integer, Boolean> localChanges;

                    // commit local actions
                    for (ActionData action : actions) {
                        boolean success = commitAction(action, data.getOwner(),
                                data.getFolder(), pathLocal);
                        String prefix = success ? "SUCCESS" : "FAIL";
                        String logMessage = String
                                .format("%s local action %s, version %s, path %s, object %s",
                                        prefix, action.getAction(),
                                        action.getVersion(),
                                        pathLocal.toString(),
                                        action.getObject());

                        if (success) {
                            actionsTaken++;
                            Logger.log(logMessage);
                        } else {
                            Logger.logError(logMessage);
                        }

                        /*
                         * Ignore failed local actions. The local change
                         * detector should take care of all remaining
                         * uncommitted changes.
                         */
                    }
                    increments += actionsTaken;

                    // commit local changes
                    if (commitLocalChanges) {
                        localChanges = getSyncLocal(data.getOwner(),
                                data.getFolder(), pathLocal);
                        increments += localChanges.getFirst();
                    }
                }
            } else {
                Logger.logError("Unparsable GET sync response.");
            }
        } else {
            Logger.logError(String.format(
                    "GET sync FAILED for folder %s and version %d: %s",
                    data.getFolder(), data.getVersion(), messageType.toString()));
        }

        /*
         * Release the synchronization lock on the server for this connection,
         * if it is present.
         */
        try {
            send(ClientProtocol.postSyncDone());
        } catch (IOException e) {
            /*
             * Exception can be ignored, as the server releases the lock
             * automatically when the socket connection fails.
             */
            Logger.logError(e);
        }

        /*
         * Write the version file.
         */
        boolean success = FileHandler.writeVersion(syncVersion + increments,
                fileFolder, syncFolder, pathLocal);

        return success ? (syncVersion + increments) : null;
    }

    /**
     * Executes the given action which might originate from the server history.
     * 
     * @param action
     *            the action to execute.
     * @param owner
     *            the owner of the data on the server.
     * @param pathServer
     *            the relative path to the owner's root directory on the server.
     * @param pathLocal
     *            the storage path relative to the client's root directory.
     * @return the number of version increments of the server. Is <code>0</code>
     *         , if no conflict occurred. Is <code>null</code>, if an error
     *         occurred.
     */
    private Integer executeAction(ActionData action, String owner,
            Path pathServer, Path pathLocal) {
        assert ((action != null) && (pathServer != null) && (pathLocal != null));

        Integer success = null;

        switch (action.getAction()) {
        case ADD:
            success = getSyncAdd(owner, pathServer, pathLocal, action);
            break;

        case MODIFY:
            success = getSyncModify(owner, pathServer, pathLocal, action);
            break;

        case DELETE:
            success = getSyncDelete(owner, pathServer, pathLocal, action);
            break;

        case RENAME:
            success = getSyncRename(owner, pathServer, pathLocal, action);
            break;

        default:
            break;
        }

        return success;
    }

    /**
     * Commits the already locally executed given action to the server. The
     * action might originate from a local change carried out by the user and
     * detected by a watcher.
     * 
     * @param action
     *            the action to execute.
     * @param owner
     *            the owner of the data on the server.
     * @param pathServer
     *            the relative path to the owner's root directory on the server.
     * @param pathLocal
     *            the storage path relative to the client's root directory.
     * @return <code>true</code>, if the action was committed successfully.
     *         Otherwise, <code>false</code>.
     */
    private boolean commitAction(ActionData action, String owner,
            Path pathServer, Path pathLocal) {
        assert ((action != null) && (pathServer != null) && (pathLocal != null));

        boolean success = false;
        Path serverFile;
        Path localFile;
        String[] split;
        Path serverSrc;
        Path serverDst;
        Path localSrc;
        Path localDst;

        switch (action.getAction()) {
        case ADD:
            serverFile = Paths.get(action.getObject().toString()).normalize();
            localFile = Paths.get(pathLocal.toString(),
                    action.getObject().toString()).normalize();
            localSrc = Paths.get(fileFolder.toString(), localFile.toString());
            if (Files.isReadable(localSrc)) {
                try (FileInputStream in = new FileInputStream(localSrc.toFile())) {
                    // The local file is still present and readable
                    FileLock lock = in.getChannel().tryLock(0, Long.MAX_VALUE,
                            true);
                    success = (lock != null)
                            && putFile(owner, pathServer, serverFile,
                                    localFile, false, null);
                } catch (IOException | OverlappingFileLockException e) {
                    Logger.logError(e);
                }
            }
            break;

        case MODIFY:
            serverFile = Paths.get(action.getObject().toString()).normalize();
            localFile = Paths.get(pathLocal.toString(),
                    action.getObject().toString()).normalize();
            localSrc = Paths.get(syncFolder.toString(), localFile.toString());
            localDst = Paths.get(fileFolder.toString(), localFile.toString());
            if (Files.isReadable(localDst)) {
                try (FileInputStream dst = new FileInputStream(
                        localDst.toFile())) {
                    // The local file is still present and readable
                    FileLock lock = dst.getChannel().tryLock(0, Long.MAX_VALUE,
                            true);

                    if (lock != null) {
                        if (Files.isReadable(localSrc)) {
                            /*
                             * The synchronization file is present. We deal with
                             * a modification indeed. There is no need to lock
                             * the synchronization file.
                             */
                            success = handleModification(owner, pathServer,
                                    serverFile, localFile, localSrc, localDst);
                        } else {
                            /*
                             * The synchronization file is not there. The file
                             * is new.
                             */
                            success = putFile(owner, pathServer, serverFile,
                                    localFile, false, null);
                        }
                    }
                } catch (IOException | OverlappingFileLockException e) {
                    Logger.logError(e);
                }
            }
            break;

        case DELETE:
            serverFile = Paths.get(action.getObject().toString()).normalize();
            localFile = Paths.get(syncFolder.toString(), pathLocal.toString(),
                    action.getObject().toString()).normalize();
            success = deleteFile(owner, pathServer, serverFile, localFile);
            break;

        case RENAME:
            split = action.getObject().split(
                    ServerProtocol.Messages.HISTORY_OBJECT_DELIMITER);
            assert (split.length == 2);
            serverSrc = Paths.get(split[0]).normalize();
            serverDst = Paths.get(split[1]).normalize();
            localSrc = Paths.get(pathLocal.toString(), split[0]);
            localDst = Paths.get(pathLocal.toString(), split[1]);
            success = postMove(new PostMoveData(owner, pathServer, serverSrc,
                    serverDst), localSrc, localDst);
            break;

        default:
            break;
        }

        return success;
    }

    /**
     * Handles a GET sync ADD response from the server.
     * 
     * @param owner
     *            the owner of the data on the server.
     * @param pathServer
     *            the folder path relative to the owner's root directory on the
     *            server. May not be <code>null</code>.
     * @param pathLocal
     *            the local folder path relative to the client's root directory.
     *            May not be <code>null</code>.
     * @param response
     *            the ADD response from the server containing the file name.
     * @return the number of version increments of the server. Is <code>0</code>
     *         , if no conflict occurred. Is <code>null</code>, if an error
     *         occurred.
     */
    private Integer getSyncAdd(String owner, Path pathServer, Path pathLocal,
            ActionData response) {
        assert ((pathServer != null) && (pathLocal != null) && (response != null));

        /*
         * A new file was added. The version of the file is equal to the version
         * of the response.
         */
        Integer result = null;
        String fileName = FileHandler.fromCanonicalPath(response.getObject());
        Path localFile = Paths.get(fileFolder.toString(), pathLocal.toString(),
                fileName);
        Path syncFile = Paths.get(syncFolder.toString(), pathLocal.toString(),
                fileName);
        boolean existsLocalFile = Files.exists(localFile)
                && !Files.isDirectory(localFile);
        boolean existsSyncFile = Files.exists(syncFile)
                && !Files.isDirectory(syncFile);

        if (!existsSyncFile) {
            if (existsLocalFile) {
                try (RandomAccessFile file = new RandomAccessFile(
                        localFile.toFile(), "r");) {
                    FileLock lock = file.getChannel().tryLock(0,
                            Long.MAX_VALUE, true);

                    if (lock != null) {
                        /*
                         * The same file already exists. In this case there is a
                         * conflict. Rename the local file, upload it to the
                         * server and download the added file. Note that we
                         * cannot generally check whether the local and the
                         * server file are different according to the metadata
                         * hashes, as the server file can be a diff, while local
                         * files are complete. Moreover, the hash on the
                         * server-side refers to the encrypted file, if the file
                         * is encrypted.
                         */
                        boolean success = getSyncResolveConflict(owner,
                                pathServer, pathLocal, fileName,
                                response.getVersion(), null, true, file);

                        if (success) {
                            result = 1;
                        }
                    }
                } catch (IOException | OverlappingFileLockException e) {
                    Logger.logError(e);
                }
            } else {
                /*
                 * The file does not exist locally. Just get it from the server.
                 */
                Path fileOnServer = Paths.get(fileName);
                FileHandler.makeParentDirs(localFile);
                boolean success = getFile(
                        new GetFileData(owner, pathServer, fileOnServer,
                                response.getVersion(), null, null), pathLocal,
                        Paths.get(fileName), localFile).getFirst();

                if (success) {
                    result = 0;
                }
            }
        } else {
            /*
             * The synchronization file already exists, do not get the file. The
             * reason might be that the file to be added is a conflicted file
             * and the client did not finish synchronization due to an error.
             */
            result = 0;
        }

        return result;
    }

    /**
     * Diffs the local modified file, if it is configured and uploads the diff
     * to the server, if it does not exceed the threshold size. Lock on the
     * target should be held, as this method does not lock files itself.
     * 
     * @param owner
     *            the owner of the file on the server.
     * @param pathServer
     *            the relative path to the owner's root directory on the server.
     *            May not be <code>null</code.
     * @param fileOnServer
     *            the path relative to <code>pathServer</code> of the file on
     *            the server. May not be <code>null</code>.
     * @param fileRelativeLocal
     *            the path of the local file relative to the client's root
     *            directory. May not be <code>null</code>.
     * @param source
     *            the complete path of the diff source. May not be
     *            <code>null</code>.
     * @param target
     *            the complete path of the diff target. May not be
     *            <code>null</code>.
     * @return <code>true</code>, if the diff or complete file was successfully
     *         uploaded. Otherwise, <code>false</code> is returned.
     */
    private boolean handleModification(String owner, Path pathServer,
            Path fileOnServer, Path fileRelativeLocal, Path source, Path target) {
        assert ((pathServer != null) && (fileOnServer != null)
                && (fileRelativeLocal != null) && (source != null) && (target != null));

        boolean successAction = false;
        boolean diffed = false;

        /*
         * If diffing is activated in the configuration, try to diff the file
         * and check whether the patch size does not exceed the patch threshold
         * (configured percentage of original file size).
         */
        try {
            if (config.isDiff()) {
                Path diff = DifferFactory.getInstance(
                        DifferImplementation.XDELTA).diff(source, target);

                // We do not lock the diff file, as it is stored in a
                // temporary directory.
                if ((diff != null)
                        && (Files.size(diff) <= (config.getDiffThreshold() * Files
                                .size(target)))) {
                    diffed = true;
                    successAction = putFile(owner, pathServer, fileOnServer,
                            fileRelativeLocal, true, diff);
                    Files.deleteIfExists(diff);
                }
            }

            if (!diffed) {
                // The target file is already locked by the caller of this
                // method.
                successAction = putFile(owner, pathServer, fileOnServer,
                        fileRelativeLocal, false, null);
            }
        } catch (IOException e) {
            Logger.logError(e);
        }

        return successAction;
    }

    /**
     * Handles a GET sync MODIFY response from the server.
     * 
     * @param owner
     *            the owner of the data on the server.
     * @param pathServer
     *            the folder path relative to the owner's root directory on the
     *            server. May not be <code>null</code>.
     * @param pathLocal
     *            the local folder path relative to the client's root directory.
     *            May not be <code>null</code>.
     * @param response
     *            the MODIFY response from the server containing the file name.
     * @return the number of version increments of the server. Is <code>0</code>
     *         , if no conflict occurred. Is <code>null</code>, if an error
     *         occurred.
     */
    private Integer getSyncModify(String owner, Path pathServer,
            Path pathLocal, ActionData response) {
        assert ((pathServer != null) && (pathLocal != null) && (response != null));

        Integer result = null;
        String fileName = FileHandler.fromCanonicalPath(response.getObject());
        Path localFile = Paths.get(fileFolder.toString(), pathLocal.toString(),
                fileName);
        Path syncFile = Paths.get(syncFolder.toString(), pathLocal.toString(),
                fileName);
        byte[] localFileChecksum = null;

        /*
         * The response says that the file was modified. Thus, we must have a
         * synchronization copy, as "modified" implies that the file exists
         * since at least the previous synchronization point.
         */
        assert (Files.exists(syncFile));

        if (Files.exists(localFile) && !Files.isDirectory(localFile)) {
            try (RandomAccessFile file = new RandomAccessFile(
                    localFile.toFile(), "rw");) {
                FileLock lock = file.getChannel().tryLock(0, Long.MAX_VALUE,
                        false);

                if (lock != null) {
                    long localFileSize = Files.size(localFile);
                    boolean modified = ((Files.size(syncFile) != localFileSize) || !MessageDigest
                            .isEqual(
                                    FileHandler.getChecksum(syncFile),
                                    localFileChecksum = FileHandler
                                            .getChecksum(new FileInputStream(
                                                    file.getFD()),
                                                    localFileSize)));

                    if (modified) {
                        /*
                         * Local file was definitely modified. There might be a
                         * conflict with the server file (if the modifications
                         * differ). Rename the local file, transmit it to the
                         * server and download the server version. Note that we
                         * cannot check whether the local changes are identical
                         * to the server changes without the overhead of
                         * creating a local diff (if the server file is a diff),
                         * encrypting it with the respective access bundle key
                         * (if the server file is encrypted) and comparing the
                         * hash of the local encrypted file to the server file.
                         */
                        boolean success = getSyncResolveConflict(owner,
                                pathServer, pathLocal, fileName,
                                response.getVersion(), localFileChecksum, true,
                                file);

                        if (success) {
                            result = applyModification(owner, pathServer,
                                    pathLocal, response, file);

                            if (result == 0) {
                                result = 1;
                            }
                        }
                    } else {
                        result = applyModification(owner, pathServer,
                                pathLocal, response, file);
                    }
                }
            } catch (IOException | OverlappingFileLockException
                    | NoSuchAlgorithmException e) {
                Logger.logError(e);
            }
        } else {
            /*
             * File was not modified locally or does not exist. Just apply the
             * patch, or overwrite the file, if it exists and copy it to the
             * synchronization directory (getFile does the latter). Lock the
             * local file, as it will be written.
             */
            FileHandler.makeParentDirs(localFile);

            try (RandomAccessFile file = new RandomAccessFile(
                    localFile.toFile(), "rw");) {
                FileLock lock = file.getChannel().tryLock(0, Long.MAX_VALUE,
                        false);

                if (lock != null) {
                    result = applyModification(owner, pathServer, pathLocal,
                            response, file);
                }
            } catch (IOException | OverlappingFileLockException e) {
                Logger.logError(e);
            }
        }

        return result;
    }

    /**
     * Gets the modified file from the server. Applies the diff, if the modified
     * file is a diff and stores the file. If the file is not a diff, the file
     * is only stored. Does not hold any file locks itself and releases the
     * given file lock when necessary by closing the given file.
     * 
     * @param owner
     *            the owner of the data on the server.
     * @param pathServer
     *            the folder path relative to the owner's root directory on the
     *            server. May not be <code>null</code>.
     * @param pathLocal
     *            the local folder path relative to the client's root directory.
     *            May not be <code>null</code>.
     * @param response
     *            the MODIFY response from the server containing the file name.
     * @param file
     *            the locked local file.
     * @return the number of version increments of the server. Is <code>0</code>
     *         , if no conflict occurred. Is <code>null</code>, if an error
     *         occurred.
     */
    private Integer applyModification(String owner, Path pathServer,
            Path pathLocal, ActionData response, RandomAccessFile file) {
        assert ((pathServer != null) && (pathLocal != null)
                && (response != null) && (file != null));

        Integer result = null;
        String fileName = FileHandler.fromCanonicalPath(response.getObject());
        Path localFile = Paths.get(fileFolder.toString(), pathLocal.toString(),
                fileName);
        Path syncFile = Paths.get(syncFolder.toString(), pathLocal.toString(),
                fileName);
        Path tempFile = null;
        Path tempTarget = null;

        try {
            tempFile = FileHandler.getTempFile(localFile);

            if (tempFile != null) {
                Path fileOnServer = Paths.get(fileName.toString()).normalize();
                Pair<Boolean, GetMetadataResponseData> getResponse = getFile(
                        new GetFileData(owner, pathServer, fileOnServer,
                                response.getVersion(), null, null), pathLocal,
                        Paths.get(fileName).normalize(), tempFile);

                if (getResponse.getFirst()) {
                    /*
                     * Successfully received the file. Apply diff, if the
                     * received file was a diff. Otherwise, just move the file
                     * to the target file.
                     */
                    if (!getResponse.getSecond().isDiff()) {
                        file.close();
                        Files.move(tempFile, localFile,
                                StandardCopyOption.REPLACE_EXISTING);
                        result = 0;
                    } else {
                        /*
                         * tempFile is a diff. We apply it. As we deal only with
                         * temporary and synchronization files, there is no need
                         * to lock any file.
                         */
                        tempTarget = FileHandler.getTempFile(syncFile);
                        boolean patched = (tempTarget != null)
                                && DifferFactory.getInstance(
                                        DifferImplementation.XDELTA).patch(
                                        syncFile, tempFile, tempTarget);

                        if (patched) {
                            file.close();
                            boolean copied = FileHandler.copyFile(tempTarget,
                                    localFile, true);
                            if (copied) {
                                Files.move(tempTarget, syncFile,
                                        StandardCopyOption.REPLACE_EXISTING);
                                result = 0;
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            Logger.logError(e);
        } finally {
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException innerE) {
                    Logger.logError(innerE);
                }
            }
            if (tempTarget != null) {
                try {
                    Files.deleteIfExists(tempTarget);
                } catch (IOException innerE) {
                    Logger.logError(innerE);
                }
            }

        }

        return result;
    }

    /**
     * Handles a GET sync DELETE response from the server.
     * 
     * @param owner
     *            the owner of the data on the server.
     * @param pathServer
     *            the folder path relative to the owner's root directory on the
     *            server. May not be <code>null</code>.
     * @param pathLocal
     *            the local folder path relative to the client's root directory.
     *            May not be <code>null</code>.
     * @param response
     *            the DELETE response from the server containing the file name.
     * @return the number of version increments of the server. Is <code>0</code>
     *         , if no conflict occurred. Is <code>null</code>, if an error
     *         occurred.
     */
    private Integer getSyncDelete(String owner, Path pathServer,
            Path pathLocal, ActionData response) {
        assert ((pathServer != null) && (pathLocal != null) && (response != null));

        /*
         * A file was removed. Check whether the respective existing localFile
         * was changed. If this is the case, a conflict occurred.
         */
        Integer result = null;
        String fileName = FileHandler.fromCanonicalPath(response.getObject());
        Path localFile = Paths.get(fileFolder.toString(), pathLocal.toString(),
                fileName);
        Path syncFile = Paths.get(syncFolder.toString(), pathLocal.toString(),
                fileName);
        byte[] localFileChecksum = null;

        assert (Files.exists(syncFile));

        if (Files.exists(localFile) && !Files.isDirectory(localFile)) {
            try (RandomAccessFile file = new RandomAccessFile(
                    localFile.toFile(), "r");) {
                FileLock lock = file.getChannel().tryLock(0, Long.MAX_VALUE,
                        true);

                if (lock != null) {
                    long localFileSize = Files.size(localFile);
                    boolean modified = (lock != null)
                            && ((Files.size(syncFile) != localFileSize) || !MessageDigest
                                    .isEqual(
                                            FileHandler.getChecksum(syncFile),
                                            localFileChecksum = FileHandler
                                                    .getChecksum(
                                                            new FileInputStream(
                                                                    file.getFD()),
                                                            localFileSize)));

                    if (modified) {
                        /*
                         * Local file exists and was definitely modified. In
                         * order not to loose the data we have, we upload the
                         * file to the server.
                         */
                        boolean success = getSyncResolveConflict(owner,
                                pathServer, pathLocal, fileName,
                                response.getVersion(), localFileChecksum,
                                false, file);

                        if (success) {
                            result = 1;
                        }
                    } else {
                        /*
                         * File was not modified locally. Just delete the file
                         * and also try to delete the copy in the sync
                         * directory.
                         */
                        try {
                            file.close();
                            Files.delete(localFile);
                            Files.delete(syncFile);
                            result = 0;
                        } catch (IOException e) {
                            Logger.logError(e);
                        }
                    }
                }
            } catch (IOException | OverlappingFileLockException
                    | NoSuchAlgorithmException e) {
                Logger.logError(e);
            }
        } // do not delete directories

        return result;
    }

    /**
     * Handles a GET sync RENAME response from the server and tries to handle
     * potential conflicts.
     * 
     * @param owner
     *            the owner of the data on the server.
     * @param pathServer
     *            the folder path relative to the owner's root directory on the
     *            server. May not be <code>null</code>.
     * @param pathLocal
     *            the local folder path relative to the client's root directory.
     *            May not be <code>null</code>.
     * @param response
     *            the RENAME response from the server containing the file names.
     * @return the number of version increments of the server. Is <code>0</code>
     *         , if no conflict occurred. Is <code>null</code>, if an error
     *         occurred.
     */
    private Integer getSyncRename(String owner, Path pathServer,
            Path pathLocal, ActionData response) {
        assert ((pathServer != null) && (pathLocal != null) && (response != null));

        /*
         * A file was renamed, as we do not support shared directory renames.
         */
        Integer result = null;
        String[] split = response.getObject().split(
                ServerProtocol.Messages.HISTORY_OBJECT_DELIMITER);

        if ((split != null) && (split.length == 2)) {
            String fileNameSrc = FileHandler.fromCanonicalPath(split[0]);
            String fileNameTarget = FileHandler.fromCanonicalPath(split[1]);
            Path sourceFile = Paths.get(fileFolder.toString(),
                    pathLocal.toString(), fileNameSrc);
            Path targetFile = Paths.get(fileFolder.toString(),
                    pathLocal.toString(), fileNameTarget);
            Path sourceSyncFile = Paths.get(syncFolder.toString(),
                    pathLocal.toString(), fileNameSrc);
            Path targetSyncFile = Paths.get(syncFolder.toString(),
                    pathLocal.toString(), fileNameTarget);

            if (Files.exists(sourceSyncFile) && !Files.exists(targetSyncFile)) {
                if (Files.exists(sourceFile) && !Files.exists(targetFile)) {
                    /*
                     * The owner has not made any local, conflicting changes.
                     */
                    try {
                        FileHandler.makeParentDirs(targetFile);
                        Files.move(sourceFile, targetFile);
                        FileHandler.makeParentDirs(targetSyncFile);
                        Files.move(sourceSyncFile, targetSyncFile);
                        result = 0;
                    } catch (IOException e) {
                        Logger.logError(e);
                    }
                } else {
                    if (!Files.exists(sourceFile)) {
                        /*
                         * getFile must get the source file with file version <=
                         * given version. This is done so, indeed.
                         */
                        Path sourceFileName = Paths.get(fileNameSrc)
                                .normalize();
                        Path fileOnServer = sourceFileName;
                        getFile(new GetFileData(owner, pathServer,
                                fileOnServer, response.getVersion(), null, null),
                                pathLocal, sourceFileName, sourceFile);
                    }

                    if (Files.exists(sourceFile) && Files.exists(targetFile)) {
                        /*
                         * Rename the target file and upload it to the server.
                         * Note that the given version number is ignored, as we
                         * do not download a file from the server.
                         */
                        try (FileOutputStream outSource = new FileOutputStream(
                                sourceFile.toFile(), true);
                                RandomAccessFile fileTarget = new RandomAccessFile(
                                        targetFile.toFile(), "rw")) {
                            FileLock lockSource = outSource.getChannel()
                                    .tryLock(0, Long.MAX_VALUE, false);
                            FileLock lockTarget = fileTarget.getChannel()
                                    .tryLock(0, Long.MAX_VALUE, false);

                            if ((lockSource != null) && (lockTarget != null)) {
                                // the target file is renamed and uploaded
                                boolean success = getSyncResolveConflict(owner,
                                        pathServer, pathLocal, fileNameTarget,
                                        1, null, false, fileTarget);

                                if (success) {
                                    outSource.close();
                                    Files.move(sourceFile, targetFile);
                                    Files.move(sourceSyncFile, targetSyncFile);
                                    result = 1;
                                }
                            }
                        } catch (IOException | OverlappingFileLockException e) {
                            Logger.logError(e);
                        }
                    } else {
                        /*
                         * Target file might not exist, while the source file
                         * might exist. Try again.
                         */
                        return getSyncRename(owner, pathServer, pathLocal,
                                response);
                    }
                }
            } else {
                Logger.logError(String
                        .format("Cannot MOVE from=%s to=%s, as from does not exist in the synchronization directory or to exists in the synchronization directory.",
                                sourceFile.toString(), targetFile.toString()));
            }
        }

        return result;
    }

    /**
     * Resolves a file conflict by renaming the given local file, uploading the
     * renamed local file to the server and downloading the conflicted server
     * file with the original local file name (if desired). The synchronization
     * directory is updated according to the changes in the working tree. As
     * this method does not lock the conflicted file, the calling method must
     * lock the file. The file lock is released in this method before the file
     * is renamed.
     * 
     * @param owner
     *            the owner of the data on the server.
     * @param pathServer
     *            the folder path relative to the owner's root directory on the
     *            server. May not be <code>null</code>.
     * @param pathLocal
     *            the local folder path relative to the client's root directory.
     *            Must exist. A respective synchronization file may exist.
     * @param fileName
     *            the name of the conflicting file. Must be an existing file.
     * @param version
     *            the version to download from the server. Must be at least one.
     * @param localFileChecksum
     *            checksum of the local file. May be <code>null</code>.
     * @param download
     *            <code>true</code>, if the file <code>fileName</code> should be
     *            downloaded from the server. <code>false</code>, if
     *            <code>fileName</code> should not be downloaded.
     * @param file
     *            the locked conflicting file. Must not be <code>null</code>.
     * @return <code>true</code>, if the conflict was handled successfully.
     *         Otherwise, <code>false</code>.
     */
    private boolean getSyncResolveConflict(String owner, Path pathServer,
            Path pathLocal, String fileName, int version,
            byte[] localFileChecksum, boolean download, RandomAccessFile file) {
        assert ((pathServer != null) && (pathLocal != null)
                && (fileName != null) && (version >= 1) && (file != null));

        boolean success = false;
        Path localFile = Paths.get(fileFolder.toString(), pathLocal.toString(),
                fileName).normalize();
        assert (Files.exists(localFile));
        String conflictedCopySuffix = String.format(" (conflicted copy %s)",
                DATE_FORMAT.format(new Date()));
        Path localConflictedCopy = Paths.get(String.format("%s%s",
                localFile.toString(), conflictedCopySuffix));

        /*
         * Local file exists, though it should not exist or has a different
         * version. In order not to loose the data we have, we rename the file
         * and upload it to the server. Additionally, we download the version
         * from the server, if desired.
         */
        // count up to get an inexistent suffix, if necessary
        for (int i = 2; Files.exists(localConflictedCopy); i++) {
            localConflictedCopy = Paths.get(String.format("%s%s (%d)",
                    localFile.toString(), conflictedCopySuffix, i));
        }
        localConflictedCopy = localConflictedCopy.normalize();

        try {
            file.close();
            // rename
            Files.move(localFile, localConflictedCopy);

            // upload
            Path conflictedCopyFileName = Paths
                    .get(fileFolder.toString(), pathLocal.toString())
                    .normalize().relativize(localConflictedCopy).normalize();
            Path serverConflictedCopy = Paths.get(
                    conflictedCopyFileName.toString()).normalize();
            Path localConflictedCopyRelative = Paths.get(pathLocal.toString(),
                    conflictedCopyFileName.toString()).normalize();

            try (RandomAccessFile fileConflicted = new RandomAccessFile(
                    localConflictedCopy.toFile(), "r");) {
                FileLock lockFileConflicted = fileConflicted.getChannel()
                        .tryLock(0, Long.MAX_VALUE, true);

                if (lockFileConflicted != null) {
                    boolean uploaded = putFile(owner, pathServer,
                            serverConflictedCopy, localConflictedCopyRelative,
                            false, null);
                    fileConflicted.close();

                    if (uploaded) {
                        if (download) {
                            // download
                            Path fileOnServer = Paths.get(fileName).normalize();
                            success = getFile(
                                    new GetFileData(owner, pathServer,
                                            fileOnServer, version, null, null),
                                    pathLocal, Paths.get(fileName), localFile)
                                    .getFirst();
                        } else {
                            success = true;
                        }
                    } else {
                        Logger.logError(String.format(
                                "Uploading conflicted file %s FAILED.",
                                localConflictedCopyRelative.toString()));
                    }
                }
            } catch (IOException | OverlappingFileLockException e) {
                Logger.logError(e);
            }
        } catch (IOException e) {
            Logger.logError(e);
        }

        return success;
    }

    /**
     * Tries to find changes made in <code>pathLocal</code> and sends detected
     * changes to the server. <code>pathLocal</code> must have been synchronized
     * successfully, before this method is called.
     * 
     * @param owner
     *            the owner of the data on the server.
     * @param pathServer
     *            the folder path relative to the owner's root directory on the
     *            server. May not be <code>null</code>.
     * @param pathLocal
     *            the local folder path relative to the client's root directory.
     *            Must exist.
     * @return the number of commits and a boolean denoting whether everything
     *         was carried out successfully.
     */
    private Pair<Integer, Boolean> getSyncLocal(String owner, Path pathServer,
            Path pathLocal) {
        assert ((pathServer != null) && (pathLocal != null));

        SetAndMap<Path, Long, byte[]> syncCollection = new SyncCollector(
                fileFolder, syncFolder, pathLocal).execute();

        if (syncCollection != null) {
            // find local file changes and commit them.
            return new ChangeDetector(this, owner, fileFolder, syncFolder,
                    pathServer, pathLocal, syncCollection, Paths.get(config
                            .getLogFile()), Paths.get(config.getLogErrorFile()))
                    .execute();
        } else {
            return new Pair<Integer, Boolean>(0, false);
        }
    }

    /**
     * Collects files in the synchronization folder except hidden sub-folders,
     * hidden files and version files.
     * 
     * @author Fabian Foerg
     */
    private static final class SyncCollector {
        private final SetAndMap<Path, Long, byte[]> syncCollection;
        private final Path fileFolder;
        private final Path syncDir;
        private boolean success;

        /**
         * Constructor.
         * 
         * @param fileFolder
         *            the complete path of the client's root directory.
         * @param syncFolder
         *            the complete path of the synchronization directory.
         * @param pathLocal
         *            the storage folder path relative to the client's root
         *            directory. Must exist. A respective synchronization folder
         *            may exist.
         */
        public SyncCollector(Path fileFolder, Path syncFolder, Path pathLocal) {
            if (fileFolder == null) {
                throw new NullPointerException("fileFolder may not be null!");
            }
            if (syncFolder == null) {
                throw new NullPointerException("syncFolder may not be null!");
            }
            if (pathLocal == null) {
                throw new NullPointerException("pathLocal may not be null!");
            }

            syncCollection = new SetAndMap<>();
            this.fileFolder = fileFolder;
            syncDir = Paths.get(syncFolder.toString(), pathLocal.toString())
                    .normalize();
            success = true;
        }

        /**
         * Starts to collect information about the synchronization folder tree.
         * May be called multiple times.
         * 
         * @return the collected data or <code>null</code>, if an error
         *         occurred.
         */
        public SetAndMap<Path, Long, byte[]> execute() {
            syncCollection.clear();

            try {
                if (Files.isDirectory(syncDir)) {
                    Files.walkFileTree(syncDir, new SyncVisitor());
                }
            } catch (IOException e) {
                success = false;
                Logger.logError(e);
            }

            return success ? syncCollection : null;
        }

        private final class SyncVisitor extends SimpleFileVisitor<Path> {
            public SyncVisitor() {
            }

            @Override
            public FileVisitResult visitFile(Path file,
                    BasicFileAttributes attrs) {
                try {
                    if (!Files.isHidden(file)
                            && !file.getFileName().toString().startsWith(".")
                            && !SynchronizationExecutor.VERSION_FILE
                                    .equals(file.getFileName().toString())) {
                        long size = Files.size(file);
                        syncCollection.addB(file, size);
                    }
                } catch (IOException e) {
                    success = false;
                    Logger.logError(e);
                    return FileVisitResult.TERMINATE;
                }

                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult preVisitDirectory(Path dir,
                    BasicFileAttributes attrs) {
                try {
                    Path dirName = syncDir.normalize().relativize(dir);

                    /*
                     * Ignore hidden directories except the synchronization
                     * directory. Ignore directories which contain access
                     * bundles. An exception is the file root directory to
                     * crawl.
                     */
                    if (((Files.isHidden(dir) || dir.getFileName().toString()
                            .startsWith(".")) && !syncDir.equals(dir))
                            || (Files.exists(Paths.get(fileFolder.toString(),
                                    dirName.toString(),
                                    GroupAccessBundle.ACCESS_BUNDLE_FILENAME)) && !""
                                    .equals(dirName.toString().trim()))) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                } catch (IOException e) {
                    success = false;
                    Logger.logError(e);
                    return FileVisitResult.TERMINATE;
                }

                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                success = false;
                Logger.logError(exc);
                return FileVisitResult.TERMINATE;
            }
        }
    }

    /**
     * Compares each file in the given local directory to the respective file in
     * the synchronization directory and commits detected changes. A change can
     * be either a modification, a rename, an addition or a deletion. Hidden and
     * shared folders as well as hidden files are ignored.
     * 
     * @author Fabian Foerg
     */
    private static final class ChangeDetector {
        private final ClientConnectionHandler handler;
        private final String owner;
        private final Path fileFolder;
        private final Path syncFolder;
        private final Path pathServer;
        private final Path pathLocal;
        private final Path toCrawl;
        private final SetAndMap<Path, Long, byte[]> syncCollection;
        private final Path logFile;
        private final Path logErrorFile;
        private boolean success;
        private int changes;
        private boolean executed;

        /**
         * Constructor.
         * 
         * @param handler
         *            the client connection handler to use for committing the
         *            changes.
         * @param owner
         *            the owner of the data on the server.
         * @param fileFolder
         *            the complete path of the client's root directory.
         * @param syncFolder
         *            the complete path of the synchronization directory.
         * @param pathServer
         *            the relative path to the owner's root directory on the
         *            server.
         * @param pathLocal
         *            the storage path relative to the client's root directory.
         *            Must exist. A respective synchronization file may exist.
         * @param syncCollection
         *            the collection of synchronization files along with their
         *            sizes in bytes and known checksums.
         * @param logFile
         *            the log file. We do not synchronize this file.
         * @param logErrorFile
         *            the error log file. We do not synchronize this file.
         */
        public ChangeDetector(ClientConnectionHandler handler, String owner,
                Path fileFolder, Path syncFolder, Path pathServer,
                Path pathLocal, SetAndMap<Path, Long, byte[]> syncCollection,
                Path logFile, Path logErrorFile) {
            if (handler == null) {
                throw new NullPointerException("handler may not be null!");
            }
            if (fileFolder == null) {
                throw new NullPointerException("fileFolder may not be null!");
            }
            if (syncFolder == null) {
                throw new NullPointerException("syncFolder may not be null!");
            }
            if (pathServer == null) {
                throw new NullPointerException("pathServer may not be null!");
            }
            if (pathLocal == null) {
                throw new NullPointerException("pathLocal may not be null!");
            }
            if (syncCollection == null) {
                throw new NullPointerException(
                        "syncCollection may not be null!");
            }

            this.handler = handler;
            this.owner = owner;
            this.fileFolder = fileFolder;
            this.syncFolder = syncFolder;
            this.pathServer = pathServer;
            this.pathLocal = pathLocal;
            this.syncCollection = syncCollection;
            toCrawl = Paths.get(fileFolder.toString(), pathLocal.toString())
                    .normalize();
            this.logFile = logFile.normalize().toAbsolutePath();
            this.logErrorFile = logErrorFile.normalize().toAbsolutePath();
            success = true;
            changes = 0;
            executed = false;
        }

        /**
         * Detects changes between the local and the synchronization directory
         * and commits them. Returns the number of commits and a boolean
         * denoting whether everything was carried out successfully. Must not be
         * called more than once!
         * 
         * @return the number of commits and a boolean denoting whether
         *         everything was carried out successfully.
         */
        public Pair<Integer, Boolean> execute() {
            if (executed) {
                return new Pair<Integer, Boolean>(0, false);
            } else {
                try {
                    Files.walkFileTree(toCrawl, new ChangeVisitor());

                    if (success) {
                        /* Detect deleted files. */
                        for (Path syncFile : syncCollection.getSet()) {
                            Path fileName = Paths
                                    .get(syncFolder.toString(),
                                            pathLocal.toString()).normalize()
                                    .relativize(syncFile).normalize();
                            boolean success = handler.deleteFile(owner,
                                    pathServer, fileName, syncFile);

                            if (success) {
                                changes++;
                            } else {
                                success = false;
                                break;
                            }
                        }
                    }
                } catch (IOException e) {
                    success = false;
                    Logger.logError(e);
                } finally {
                    syncCollection.clear();
                    executed = true;
                }

                return new Pair<Integer, Boolean>(changes, success);
            }
        }

        private final class ChangeVisitor extends SimpleFileVisitor<Path> {
            @Override
            public FileVisitResult visitFile(Path file,
                    BasicFileAttributes attrs) {
                // ignore hidden files, access bundles and log files
                try {
                    Path fileAbsolute = file.toAbsolutePath();

                    if (Files.isHidden(file)
                            || file.getFileName().toString().startsWith(".")
                            || AccessBundle.ACCESS_BUNDLE_FILENAME.equals(file
                                    .getFileName().toString())
                            || logFile.equals(fileAbsolute)
                            || logErrorFile.equals(fileAbsolute)) {
                        return FileVisitResult.CONTINUE;
                    }
                } catch (IOException e) {
                    success = false;
                    Logger.logError(e);
                    return FileVisitResult.TERMINATE;
                }

                /*
                 * Detect local changes and synchronize the changes. Lock the
                 * file during the detection and change commit phase. We use a
                 * shared lock, as we will not modify the file.
                 */
                try (RandomAccessFile fileRA = new RandomAccessFile(
                        file.toFile(), "r");) {
                    FileLock lock = fileRA.getChannel().tryLock(0,
                            Long.MAX_VALUE, true);

                    if (lock != null) {
                        Path fileName = Paths
                                .get(fileFolder.toString(),
                                        pathLocal.toString()).normalize()
                                .relativize(file).normalize();
                        Path syncFile = Paths.get(syncFolder.toString(),
                                pathLocal.toString(), fileName.toString())
                                .normalize();
                        Path relativeLocal = Paths.get(pathLocal.toString(),
                                fileName.toString()).normalize();
                        boolean successAction = false;
                        long fileSize = Files.size(file);
                        byte[] localFileChecksum = null;
                        Long syncFileSize = syncCollection.getB(syncFile);

                        /*
                         * Compare the synchronization file to the local file in
                         * order to detect modifications. There is no need to
                         * lock the synchronization file.
                         */
                        if ((syncFileSize != null)
                                && (syncFileSize == fileSize)
                                && MessageDigest
                                        .isEqual(
                                                FileHandler
                                                        .getChecksum(syncFile),
                                                localFileChecksum = FileHandler
                                                        .getChecksum(
                                                                new FileInputStream(
                                                                        fileRA.getFD()),
                                                                fileSize))) {
                            /*
                             * File unchanged. Remove the sync file from the
                             * collection.
                             */
                            syncCollection.remove(syncFile);
                        } else {
                            /*
                             * The local file is was renamed, modified or is
                             * new. Check whether it was renamed first, upload
                             * the change, if it was modified or upload the
                             * complete file, if it is new.
                             * 
                             * Rename detection: possibleRenameCandidates is a
                             * set containing the synchronization files with the
                             * same size as the current local file. The path
                             * names start with the synchronization folder name.
                             */
                            boolean renamed = false;
                            Set<Path> possibleRenameCandidates = syncCollection
                                    .getSet(fileSize);

                            if ((possibleRenameCandidates != null)
                                    && !possibleRenameCandidates.isEmpty()) {
                                if (localFileChecksum == null) {
                                    localFileChecksum = FileHandler
                                            .getChecksum(new FileInputStream(
                                                    fileRA.getFD()), fileSize);
                                }

                                for (Path renameCandidate : possibleRenameCandidates) {
                                    /*
                                     * The sync file, if it exists, is not a
                                     * rename candidate.
                                     */
                                    if (!renameCandidate.equals(syncFile)) {
                                        /*
                                         * The size and checksums of the rename
                                         * candidate and the current local file
                                         * must match.
                                         */
                                        Path candidateFileRelative = syncFolder
                                                .normalize().relativize(
                                                        renameCandidate);
                                        byte[] candidateChecksum = syncCollection
                                                .getC(renameCandidate);

                                        /*
                                         * Add the checksum for fast later
                                         * retrieval.
                                         */
                                        if (candidateChecksum == null) {
                                            candidateChecksum = FileHandler
                                                    .getChecksum(renameCandidate);
                                            assert (candidateChecksum != null);
                                            syncCollection.addC(
                                                    renameCandidate,
                                                    candidateChecksum);
                                        }

                                        /*
                                         * Compare the checksums of the local
                                         * file and the rename candidate.
                                         */
                                        if (MessageDigest.isEqual(
                                                localFileChecksum,
                                                candidateChecksum)) {
                                            Path candidateFileName = Paths
                                                    .get(syncFolder.toString(),
                                                            pathLocal
                                                                    .toString())
                                                    .normalize()
                                                    .relativize(renameCandidate)
                                                    .normalize();
                                            PostMoveData data = new PostMoveData(
                                                    owner, pathServer,
                                                    candidateFileName, fileName);
                                            renamed = true;
                                            successAction = handler.postMove(
                                                    data,
                                                    candidateFileRelative,
                                                    relativeLocal);
                                            syncCollection
                                                    .remove(renameCandidate);

                                            // we already found a matching
                                            // candidate
                                            break;
                                        }
                                    }
                                }
                            }

                            if (!renamed) {
                                // File was modified or is new.
                                if (syncFileSize != null) {
                                    assert (syncFileSize >= 0);
                                    // File was modified. Upload a diff.
                                    successAction = handler.handleModification(
                                            owner, pathServer, fileName,
                                            relativeLocal, syncFile, file);
                                    syncCollection.remove(syncFile);
                                } else {
                                    // File is new. Upload it.
                                    successAction = handler.putFile(owner,
                                            pathServer, fileName,
                                            relativeLocal, false, null);
                                }
                            }

                            if (successAction) {
                                changes++;
                            } else {
                                success = false;
                                return FileVisitResult.TERMINATE;
                            }
                        }
                    }
                } catch (Exception e) {
                    success = false;
                    Logger.logError(e);
                    return FileVisitResult.TERMINATE;
                }

                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult preVisitDirectory(Path dir,
                    BasicFileAttributes attrs) {
                try {
                    /*
                     * Ignore hidden and shared sub-folders. Ignore the
                     * synchronization folder.
                     */
                    if (Files.isHidden(dir)
                            || dir.getFileName().toString().startsWith(".")
                            || syncFolder.equals(dir)
                            || (Files.exists(Paths.get(dir.toString(),
                                    GroupAccessBundle.ACCESS_BUNDLE_FILENAME)) && !toCrawl
                                    .equals(dir))) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                } catch (IOException e) {
                    success = false;
                    Logger.logError(e);
                    return FileVisitResult.TERMINATE;
                }

                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                success = false;
                Logger.logError(exc);
                return FileVisitResult.TERMINATE;
            }
        }
    }

    /**
     * Class maintains three hash maps. One hash map maps from A to B. Another
     * hash map maps from B to Set<A>. The other hash map maps from A to C.
     * 
     * @author Fabian Foerg
     * 
     * @param <A>
     *            the type for the set.
     * @param <B>
     *            the type of the property.
     * @param <C>
     *            the type of information for objects of type A.
     */
    private static final class SetAndMap<A, B, C> {
        private final Map<A, B> mapAtoB;
        private final Map<B, Set<A>> mapBtoSetA;
        private final Map<A, C> mapAtoC;

        public SetAndMap() {
            mapAtoB = new HashMap<>();
            mapBtoSetA = new HashMap<>();
            mapAtoC = new HashMap<>();
        }

        public void clear() {
            mapAtoB.clear();
            mapBtoSetA.clear();
            mapAtoC.clear();
        }

        public void addB(A a, B b) {
            Set<A> image = mapBtoSetA.get(b);
            if (image != null) {
                image.add(a);
            } else {
                Set<A> valueSet = new HashSet<A>();
                valueSet.add(a);
                mapBtoSetA.put(b, valueSet);
            }
            mapAtoB.put(a, b);
        }

        public void addC(A a, C c) {
            mapAtoC.put(a, c);
        }

        public void remove(A a) {
            B b = mapAtoB.get(a);

            if (b != null) {
                Set<A> image = mapBtoSetA.get(b);

                if (image != null) {
                    image.remove(a);
                    // remove empty sets in map
                    if (image.isEmpty()) {
                        mapBtoSetA.remove(b);
                    }
                }

                mapAtoB.remove(a);
            }

            mapAtoC.remove(a);
        }

        public B getB(A a) {
            return mapAtoB.get(a);
        }

        public C getC(A a) {
            return mapAtoC.get(a);
        }

        public Set<A> getSet() {
            return mapAtoB.keySet();
        }

        public Set<A> getSet(B b) {
            return mapBtoSetA.get(b);
        }
    }
}
