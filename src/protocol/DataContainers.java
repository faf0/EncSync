package protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

import misc.Coder;
import misc.FileHandler;
import misc.Logger;
import configuration.ClientConfiguration;
import configuration.Key;
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
 * Class which collects data classes. Data classes allow access to data parsed
 * from client requests or server responses.
 * 
 * @author Fabian Foerg
 */
public final class DataContainers {
    /**
     * Constant for the key version of public, plaintext files.
     */
    public static final int PUBLIC_FILE_KEY_VERSION = -1;

    /**
     * Hidden constructor.
     */
    private DataContainers() {
    }

    /**
     * Represents the data which is sent by the client along with a GET sync
     * request.
     * 
     * @author Fabian Foerg
     */
    public static class GetSyncData {
        private final String owner;
        private final Path folder;
        private final int version;

        /**
         * Creates a GetSyncData instance.
         * 
         * @param owner
         *            the owner of the file to get. May be <code>null</code>.
         * @param folder
         *            the path of the folder to synchronize relative to the
         *            owner's root directory. May not be <code>null</code>.
         * @param version
         *            the version of the file to get. Must be at least zero.
         */
        public GetSyncData(String owner, Path folder, int version) {
            if (!FileHandler.isFolderName(folder)) {
                throw new IllegalArgumentException(
                        "folder must be a valid folder name!");
            }
            if (version < 0) {
                throw new IllegalArgumentException(
                        "version must at least zero!");
            }

            this.owner = owner;
            this.folder = FileHandler.normalizeFolder(folder);
            this.version = version;
        }

        public String getOwner() {
            return owner;
        }

        public Path getFolder() {
            return folder;
        }

        public int getVersion() {
            return version;
        }
    }

    /**
     * Represents the data which is sent by the client along with a GET metadata
     * request.
     * 
     * @author Fabian Foerg
     */
    public static final class GetMetadataData extends GetSyncData {
        private final Path file;

        /**
         * Creates a GetMetadataData instance.
         * 
         * @param owner
         *            the owner of the file to get the metadata from. May be
         *            <code>null</code>.
         * @param folder
         *            the relative path to the owner's root directory of the
         *            folder containing the file. May not be <code>null</code>.
         * @param file
         *            the path of the file to get the metadata from. Must be
         *            relative to <code>folder</code>. May not be
         *            <code>null</code>.
         * @param version
         *            the version of the file to get. Must be at least zero.
         */
        public GetMetadataData(String owner, Path folder, Path file, int version) {
            super(owner, folder, version);

            if (!FileHandler.isFolderName(folder)) {
                throw new IllegalArgumentException(
                        "folder must be a valid foldername!");
            }
            if (!FileHandler.isFileName(file)) {
                throw new IllegalArgumentException(
                        "file must be a valid filename!");
            }

            this.file = file.normalize();
        }

        public Path getFile() {
            return file;
        }
    }

    /**
     * Represents a GET sync action.
     * 
     * @author Fabian Foerg
     */
    public static enum ActionType {
        ADD('A'),
        MODIFY('M'),
        DELETE('D'),
        RENAME('R');

        private final char c;

        private ActionType(char c) {
            this.c = c;
        }

        public static ActionType fromChar(char c) {
            for (ActionType action : values()) {
                if (c == action.c) {
                    return action;
                }
            }

            return null;
        }

        public char toChar() {
            return c;
        }

        @Override
        public String toString() {
            return String.valueOf(c);
        }
    }

    /**
     * Represents the data which is sent by the server in response to a GET sync
     * request or an action which was already executed locally, but needs to be
     * committed to the server. The latter might type originate from a file
     * system watcher which detects user activities.
     * 
     * @author Fabian Foerg
     */
    public static final class ActionData {
        private final int version;
        private final ActionType action;
        private final String object;

        /**
         * Creates a GetSyncResponse instance.
         * 
         * @param version
         *            the version number.
         * @param action
         *            the action executed.
         * @param object
         *            the object of the action.
         */
        public ActionData(int version, ActionType action, String object) {
            if (action == null) {
                throw new NullPointerException("action may not be null");
            }

            this.version = version;
            this.action = action;
            this.object = object;
        }

        public int getVersion() {
            return version;
        }

        public ActionType getAction() {
            return action;
        }

        public String getObject() {
            return object;
        }
    }

    /**
     * Represents the data which is sent by the client along with a GET file
     * request.
     * 
     * @author Fabian Foerg
     */
    public static final class GetFileData extends GetSyncData {
        private final Path file;
        private final Long byteFirst;
        private final Long byteLast;

        /**
         * Creates a GetFileData instance.
         * 
         * @param owner
         *            the owner of the file to get. May be <code>null</code>.
         * @param folder
         *            the relative path to the owner's root directory of the
         *            folder containing the file. May not be <code>null</code>.
         * @param file
         *            the path of the file to get relative to
         *            <code>folder</code> on the server.
         * @param version
         *            the version of the file to get. Must be at least zero.
         * @param byteFirst
         *            the first byte of the file to get. May be <code>null
         *            </code>.
         * @param byteLast
         *            the last byte of the file to get. May be <code>null</code>
         *            .
         */
        public GetFileData(String owner, Path folder, Path file, int version,
                Long byteFirst, Long byteLast) {
            super(owner, folder, version);

            if (!FileHandler.isFolderName(folder)) {
                throw new IllegalArgumentException(
                        "folder must be a valid foldername!");
            }
            if (!FileHandler.isFileName(file)) {
                throw new IllegalArgumentException(
                        "file must be a valid filename!");
            }
            if ((byteFirst != null) && (byteFirst < 1)) {
                throw new IllegalArgumentException(
                        "byteFirst must be null or at least one!");
            }
            if ((byteLast != null) && (byteLast < 1)) {
                throw new IllegalArgumentException(
                        "byteLast must be null or at least one!");
            }

            this.file = file.normalize();
            this.byteFirst = byteFirst;
            this.byteLast = byteLast;
        }

        public Path getFile() {
            return file;
        }

        public Long getByteFirst() {
            return byteFirst;
        }

        public Long getByteLast() {
            return byteLast;
        }

        public GetMetadataData toMetadataData() {
            return new GetMetadataData(super.owner, super.folder, file,
                    super.version);
        }
    }

    /**
     * Represents protected data, that is metadata of files which are used to
     * build the keyed Message Authentication Code for the file.
     * 
     * @author Fabian Foerg
     */
    public static final class ProtectedData {
        /**
         * The default key size in bits.
         */
        public static final int KEY_SIZE = 256;

        private final boolean isDiff;
        private final long size;
        private final byte[] hash;
        private final int keyVersion;
        private final byte[] extra;

        /**
         * Creates a ProtectedData instance with the given parameters.
         * 
         * @param isDiff
         *            <code>true</code>, if the file is a binary diff.
         *            <code>false</code>, otherwise.
         * @param size
         *            the size of the file in bytes. Must be at least zero.
         * @param hash
         *            the hash of the possibly encrypted file.
         * @param keyVersion
         *            the key version number of the file used to encrypt the
         *            file. Must be at least one or
         *            <code>PUBLIC_FILE_KEY_VERSION</code> for plaintext files.
         * @param extra
         *            an extra protected value. Can be, for example, an
         *            initialization vector. May be <code>null</code>.
         */
        public ProtectedData(boolean isDiff, long size, byte[] hash,
                int keyVersion, byte[] extra) {
            if (size < 0) {
                throw new IllegalArgumentException(
                        "size must be at least zero!");
            }
            if (hash == null) {
                throw new IllegalArgumentException("hash may not be null!");
            }
            if ((keyVersion < 1) && (keyVersion != PUBLIC_FILE_KEY_VERSION)) {
                throw new IllegalArgumentException(
                        "keyVersion must be at least one or the public key version!");
            }

            this.isDiff = isDiff;
            this.size = size;
            this.hash = hash;
            this.keyVersion = keyVersion;
            this.extra = extra;
        }

        /**
         * Returns the keyed Message Authentication Code for this data.
         * 
         * @param key
         *            the key used for computing the MAC. May not be
         *            <code>null</code>.
         * @return the computed MAC or <code>null</code>, if an error occurs.
         */
        public byte[] getMAC(Key key) {
            if (key == null) {
                throw new NullPointerException("key may not be null!");
            }

            byte[] result = null;
            ByteArrayOutputStream byteArray = new ByteArrayOutputStream(128);

            try {
                // fill the byte array with the protected data
                byteArray.write(Coder.stringToByteRaw(String.valueOf(isDiff)));
                byteArray.write(Coder.stringToByte(String.valueOf(size)));
                byteArray.write(hash);
                byteArray.write(Coder.stringToByteRaw(String
                        .valueOf(keyVersion)));
                if (extra != null) {
                    byteArray.write(extra);
                }

                // compute the MAC of the byte array
                Mac mac = Mac.getInstance(key.getAlgorithm());
                mac.init(key.getKey());
                result = mac.doFinal(byteArray.toByteArray());
            } catch (IOException | NoSuchAlgorithmException
                    | InvalidKeyException e) {
                Logger.logError(e);
            }

            return result;
        }

        public boolean isDiff() {
            return isDiff;
        }

        public long getSize() {
            return size;
        }

        public byte[] getHash() {
            return hash;
        }

        public int getKeyVersion() {
            return keyVersion;
        }

        public byte[] getExtra() {
            return extra;
        }
    }

    /**
     * Represents the data which is sent by the server after a successful GET
     * metadata request. This data is parsed by the client.
     * 
     * @author Fabian Foerg
     */
    public static class GetMetadataResponseData {
        private final int version;
        private final boolean isDiff;
        private final long size;
        private final byte[] hash;
        private final int keyVersion;
        private final byte[] extra;
        private final byte[] mac;

        /**
         * Creates a GetMetadataResponseData instance.
         * 
         * @param isDiff
         *            <code>true</code>, if the file is a diff.
         *            <code>false</code>, otherwise.
         * @param version
         *            the version of the file.
         * @param size
         *            the size of the file. Must be at least zero.
         * @param hash
         *            the hash of the file.
         * @param keyVersion
         *            the key version number of the file used to encrypt the
         *            file. Must be at least one or
         *            <code>PUBLIC_FILE_KEY_VERSION</code> for plaintext files.
         * @param extra
         *            an extra protected value. Can be, for example, an
         *            initialization vector. May be <code>null</code>.
         * @param mac
         *            the message authentication code of the file metadata.
         */
        public GetMetadataResponseData(boolean isDiff, int version, long size,
                byte[] hash, int keyVersion, byte[] extra, byte[] mac) {
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
            if ((keyVersion < 1) && (keyVersion != PUBLIC_FILE_KEY_VERSION)) {
                throw new IllegalArgumentException(
                        "keyVersion must be at least one or the public key version!");
            }
            if ((mac == null) && (keyVersion != PUBLIC_FILE_KEY_VERSION)) {
                throw new IllegalArgumentException(
                        "mac must not be null, if the key version is non-public!");
            }

            this.version = version;
            this.isDiff = isDiff;
            this.size = size;
            this.hash = hash;
            this.keyVersion = keyVersion;
            this.extra = extra;
            this.mac = mac;
        }

        public int getVersion() {
            return version;
        }

        public boolean isDiff() {
            return isDiff;
        }

        public long getSize() {
            return size;
        }

        public byte[] getHash() {
            return hash;
        }

        public int getKeyVersion() {
            return keyVersion;
        }

        public byte[] getExtra() {
            return extra;
        }

        public byte[] getMAC() {
            return mac;
        }

        public ProtectedData toProtectedData() {
            return new ProtectedData(isDiff, size, hash, keyVersion, extra);
        }
    }

    /**
     * Represents the data which is sent by the client with a PUT auth request.
     * This data is parsed by the server.
     * 
     * @author Fabian Foerg
     */
    public static final class PutAuthData {
        private final String name;
        private final String password;
        private final String currentPassword;

        /**
         * Creates a PutAuthData instance.
         * 
         * @param name
         *            the user name.
         * @param password
         *            the password to set.
         * @param currentPassword
         *            May be <code>null</code>, if the user is not registered
         *            yet.
         */
        public PutAuthData(String name, String password, String currentPassword) {
            if (!ClientConfiguration.isValidUserName(name)) {
                throw new IllegalArgumentException("name must be valid!");
            }
            if (!ClientConfiguration.isValidPassword(password)) {
                throw new IllegalArgumentException("password must be valid!");
            }
            if ((currentPassword != null)
                    && !ClientConfiguration.isValidPassword(currentPassword)) {
                throw new IllegalArgumentException(
                        "currentPassword must be valid!");
            }

            this.name = name;
            this.password = password;
            this.currentPassword = currentPassword;
        }

        public String getName() {
            return name;
        }

        public String getPassword() {
            return password;
        }

        public String getCurrentPassword() {
            return currentPassword;
        }
    }

    /**
     * Represents the data which is sent by the client with a PUT folder
     * request. This data is parsed by the server.
     * 
     * @author Fabian Foerg
     */
    public static final class PutFolderData {
        private final String owner;
        private final String folder;
        private final Permission[] permissions;
        private final int keyVersion;

        /**
         * Creates a PutFileData instance.
         * 
         * @param owner
         *            the owner of the file. May be <code>null</code>.
         * @param folderName
         *            the name of the folder.
         * @param permissions
         *            the access permissions of the folder to create. May be
         *            <code>null</code> for private folders.
         * @param keyVersion
         *            the minimum allowed key version number. Must be at least
         *            one or <code>DataContainers.PUBLIC_FILE_KEY_VERSION</code>
         *            for public files.
         */
        public PutFolderData(String owner, String folderName,
                Permission[] permissions, int keyVersion) {
            if ((folderName == null)
                    || !FileHandler.isSharedFolderName(Paths.get(folderName))) {
                throw new IllegalArgumentException(
                        "folder must be a valid shared foldername!");
            }
            if ((keyVersion < 1) && (keyVersion != PUBLIC_FILE_KEY_VERSION)) {
                throw new IllegalArgumentException(
                        "keyVersion must be at least one or the public key version!");
            }

            /*
             * owner may be null. In this case, the user who sends the request
             * is taken as the owner.
             */
            this.owner = owner;
            this.folder = folderName;
            this.permissions = permissions;
            this.keyVersion = keyVersion;
        }

        public String getOwner() {
            return owner;
        }

        public String getFolder() {
            return folder;
        }

        public Permission[] getPermissions() {
            return permissions;
        }

        public int getKeyVersion() {
            return keyVersion;
        }
    }

    /**
     * Represents the data which is sent by the client with a PUT file request.
     * This data is parsed by the server.
     * 
     * @author Fabian Foerg
     */
    public static final class PutFileData extends GetMetadataResponseData {
        private final String owner;
        private final Path serverFolder;
        private final Path serverFile;

        /**
         * Creates a PutFileData instance.
         * 
         * @param owner
         *            the owner of the file. May be <code>null</code>.
         * @param serverFolder
         *            the folder relative to the owner's root directory
         *            containing the file on the server. May not be
         *            <code>null</code>.
         * @param serverFile
         *            the relative path to <code>serverFolder</code> of the file
         *            on the server.
         * @param isDiff
         *            <code>true</code>, if the file is a diff. Otherwise,
         *            <code>false</code>.
         * @param size
         *            the size of the file.
         * @param hash
         *            the hash of the file.
         * @param keyVersion
         *            the key version used to encrypt the file.
         * @param extra
         *            an extra protected value. Can be, for example, an
         *            initialization vector. May be <code>null</code>.
         * @param mac
         *            the message authentication code of the file metadata.
         */
        public PutFileData(String owner, Path serverFolder, Path serverFile,
                boolean isDiff, long size, byte[] hash, int keyVersion,
                byte[] extra, byte[] mac) {
            super(isDiff, 1, size, hash, keyVersion, extra, mac);

            if (!FileHandler.isFolderName(serverFolder)) {
                throw new IllegalArgumentException(
                        "serverFolder must be a valid foldername!");
            }
            if (!FileHandler.isFileName(serverFile)) {
                throw new IllegalArgumentException(
                        "serverPath must be a valid filename!");
            }

            /*
             * owner may be null. In this case, the user who sends the request
             * is taken as the owner.
             */
            this.owner = owner;
            this.serverFolder = FileHandler.normalizeFolder(serverFolder);
            this.serverFile = serverFile.normalize();
        }

        public String getOwner() {
            return owner;
        }

        public Path getFolder() {
            return serverFolder;
        }

        public Path getFile() {
            return serverFile;
        }

        public static PutFileData from(ProtectedData data, String owner,
                Path folder, Path file, byte[] mac) {
            if (data == null) {
                throw new NullPointerException("data may not be null!");
            }
            if (!FileHandler.isFolderName(folder)) {
                throw new IllegalArgumentException(
                        "folder must be a valid foldername!");
            }
            if (!FileHandler.isFileName(file)) {
                throw new IllegalArgumentException(
                        "file must be a valid filename!");
            }
            if ((mac == null)
                    && (data.getKeyVersion() != DataContainers.PUBLIC_FILE_KEY_VERSION)) {
                throw new IllegalArgumentException(
                        "mac must not be null, if the key version is non-public!");
            }

            return new PutFileData(owner, folder, file, data.isDiff, data.size,
                    data.hash, data.keyVersion, data.extra, mac);
        }
    }

    /**
     * Represents the data which is sent by the client along with a DELETE file
     * request.
     * 
     * @author Fabian Foerg
     */
    public static class DeleteFileData {
        private final String owner;
        private final Path folder;
        private final Path file;

        /**
         * Creates a DeleteFileData instance.
         * 
         * @param owner
         *            the owner of the file to delete. May be <code>null</code>.
         * @param folder
         *            the folder relative to the owner's root directory
         *            containing the deleted file. May not be <code>null</code>.
         * @param file
         *            the path relative to <code>folder</code> of the deleted
         *            file. May not be <code>null</code>.
         */
        public DeleteFileData(String owner, Path folder, Path file) {
            if (!FileHandler.isFolderName(folder)) {
                throw new IllegalArgumentException(
                        "folder must be a valid foldername!");
            }
            if (file == null) {
                throw new NullPointerException("file may not be null!");
            }

            this.owner = owner;
            this.folder = FileHandler.normalizeFolder(folder);
            this.file = file.normalize();
        }

        public String getOwner() {
            return owner;
        }

        public Path getFolder() {
            return folder;
        }

        public Path getFile() {
            return file;
        }
    }

    /**
     * Represents the data which is sent by the client along with a POST move
     * request.
     * 
     * @author Fabian Foerg
     */
    public static class PostMoveData {
        private final String owner;
        private final Path folder;
        private final Path from;
        private final Path to;

        /**
         * Creates a PostMoveData instance.
         * 
         * @param owner
         *            the owner of the moved file. May be <code>null</code>.
         * @param folder
         *            the folder relative to the owner's root directory
         *            containing the moved file. May not be <code>null</code>.
         * @param file
         *            the path relative to <code>folder</code> of the moved
         *            file. May not be <code>null</code>.
         * @param to
         *            the path relative to <code>folder</code> of the
         *            destination file. May not be <code>null</code>.
         */
        public PostMoveData(String owner, Path folder, Path from, Path to) {
            if (!FileHandler.isFolderName(folder)) {
                throw new IllegalArgumentException(
                        "folder must be a valid foldername!");
            }
            if (from == null) {
                throw new NullPointerException("from may not be null!");
            }
            if (to == null) {
                throw new NullPointerException("to may not be null!");
            }

            this.owner = owner;
            this.folder = FileHandler.normalizeFolder(folder);
            this.from = from.normalize();
            this.to = to.normalize();
        }

        public String getOwner() {
            return owner;
        }

        public Path getFolder() {
            return folder;
        }

        public Path getFrom() {
            return from;
        }

        public Path getTo() {
            return to;
        }
    }

    /**
     * Generic class for representing pairs of objects.
     * 
     * @author Fabian Foerg
     * 
     * @param <T1>
     *            type of the first component.
     * @param <T2>
     *            type of the second component.
     */
    public static class Pair<T1, T2> {
        private final T1 t1;
        private final T2 t2;
        private final int hashCode;

        public Pair(T1 t1, T2 t2) {
            this.t1 = t1;
            this.t2 = t2;

            int localHashCode = 0;
            if (t1 != null) {
                localHashCode += t1.hashCode();
            }
            if (t2 != null) {
                localHashCode += 7 * t2.hashCode();
            }
            hashCode = localHashCode;
        }

        public T1 getFirst() {
            return t1;
        }

        public T2 getSecond() {
            return t2;
        }

        @Override
        public boolean equals(Object o) {
            if ((o == null) || !(o instanceof Pair<?, ?>) || (t1 == null)
                    || (t2 == null)) {
                return false;
            }

            Pair<?, ?> oPair = (Pair<?, ?>) o;
            return t1.equals(oPair.t1) && t2.equals(oPair.t2);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
    }

    /**
     * Generic class for representing triples of objects.
     * 
     * @author Fabian Foerg
     * 
     * @param <T1>
     *            type of the first component.
     * @param <T2>
     *            type of the second component.
     * @param <T3>
     *            type of the third component.
     */
    public static final class Triple<T1, T2, T3> extends Pair<T1, T2> {
        private final T3 t3;
        private final int hashCode;

        public Triple(T1 t1, T2 t2, T3 t3) {
            super(t1, t2);
            this.t3 = t3;
            hashCode = (t3 != null) ? (super.hashCode + (13 * t3.hashCode()))
                    : super.hashCode;
        }

        public T3 getThird() {
            return t3;
        }

        @Override
        public boolean equals(Object o) {
            if ((o == null) || !(o instanceof Triple<?, ?, ?>)
                    || (super.t1 == null) || (super.t2 == null) || (t3 == null)) {
                return false;
            }

            Triple<?, ?, ?> oTriple = (Triple<?, ?, ?>) o;
            return getFirst().equals(oTriple.getFirst())
                    && getSecond().equals(oTriple.getSecond())
                    && t3.equals(oTriple.t3);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
    }
}
