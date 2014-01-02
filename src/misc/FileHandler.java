package misc;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;

import org.json.simple.parser.ParseException;

import protocol.DataContainers.GetSyncData;
import protocol.DataContainers.ProtectedData;
import protocol.DataContainers.Triple;
import server.ServerConnectionHandler;
import client.executors.SynchronizationExecutor;
import client.prepare.PreparationProvider;
import client.prepare.PreparationProviderFactory;
import configuration.AccessBundle;
import configuration.GroupAccessBundle;
import configuration.Key;
import configuration.OwnerAccessBundle;

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
 * Provides methods for handling files.
 * 
 * @author Fabian Foerg
 */
public final class FileHandler {
    /**
     * The string representation of the root path.
     */
    public static final Path ROOT_PATH = Paths.get(".");

    /**
     * The message digest algorithm used to compute checksums.
     */
    public static final String MESSAGE_DIGEST = "SHA-256";

    /**
     * The suffix of temporary files.
     */
    public static final String TEMP_FILE_SUFFIX = "-filehandler.tmp";

    /**
     * The pattern for folder names on the server.
     */
    private static final Pattern FOLDER_PATTERN = Pattern
            .compile("[a-z]{1}[a-z0-9]{0,9}");

    /**
     * The blacklist pattern for file names on the server.
     */
    private static final Pattern FILE_NAME_BLACKLIST_PATTERN = Pattern
            .compile(".*\\.\\..*");

    /**
     * The buffer size in bytes for file chunks.
     */
    private static final int BUFFER_SIZE = 16 * 1024;

    /**
     * Copies the source file with the given options to the target file. The
     * source is first copied to the system's default temporary directory and
     * the temporary copy is then moved to the target file. In order to avoid
     * performance problems, the file is directly copied from the source to a
     * temporary file in the target directory first, if the temporary directory
     * and the target file lie on a different <code>FileStore</code>. The
     * temporary file is also moved to the target file.
     * 
     * @param source
     *            the file to copy.
     * @param target
     *            the target location where the file should be stored. Must not
     *            be identical with source. The file might or might not exist.
     *            The parent directory must exist.
     * @param replaceExisting
     *            <code>true</code>, if the target file may be overwritten.
     *            Otherwise, <code>false</code>.
     * @return <code>true</code>, if the file was successfully copied.
     *         Otherwise, <code>false</code>.
     */
    public static boolean copyFile(Path source, Path target,
            boolean replaceExisting) {
        if ((source == null) || !Files.isReadable(source)) {
            throw new IllegalArgumentException(
                    "source must exist and be readable!");
        }
        if (target == null) {
            throw new IllegalArgumentException("target may not be null!");
        }
        if (source.toAbsolutePath().normalize()
                .equals(target.toAbsolutePath().normalize())) {
            throw new IllegalArgumentException(
                    "source and target must not match!");
        }

        boolean success = false;
        Path tempFile = null;

        target = target.normalize();

        try {
            tempFile = FileHandler.getTempFile(target);

            if (tempFile != null) {
                Files.copy(source, tempFile,
                        StandardCopyOption.COPY_ATTRIBUTES,
                        StandardCopyOption.REPLACE_EXISTING);
                if (replaceExisting) {
                    Files.move(tempFile, target,
                            StandardCopyOption.REPLACE_EXISTING);
                } else {
                    Files.move(tempFile, target);
                }
                success = true;
            }
        } catch (IOException e) {
            Logger.logError(e);
        } finally {
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException eDelete) {
                    Logger.logError(eDelete);
                }
            }
        }

        return success;
    }

    /**
     * Returns a string representation of the given canonical path.
     * 
     * @param canonicalPath
     *            the canonical path to convert.
     * @return a string representation of the given canonical path.
     */
    public static String fromCanonicalPath(String canonicalPath) {
        return URI.create(canonicalPath).getPath();
    }

    /**
     * Returns the access bundle for the given location or <code>null</code>, if
     * no parseable access bundle was found.
     * 
     * @param prefix
     *            the path to the client's root directory. May not be
     *            <code>null</code>.
     * @param folder
     *            a folder path relative to prefix containing an access bundle.
     *            May not be <code>null</code>.
     * @return the parsed access bundle, if the bundle exists and the bundle is
     *         syntactically correct. <code>null</code>, otherwise.
     */
    public static AccessBundle getAccessBundle(Path prefix, Path folder) {
        if (prefix == null) {
            throw new NullPointerException("prefix may not be null!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }

        AccessBundle bundle = null;
        Path completePath = Paths.get(prefix.toString(), folder.toString());

        try {
            if (isShared(prefix, folder)) {
                bundle = GroupAccessBundle.parse(Paths.get(
                        completePath.toString(),
                        AccessBundle.ACCESS_BUNDLE_FILENAME));

            } else {
                bundle = OwnerAccessBundle.parse(Paths.get(
                        completePath.toString(),
                        AccessBundle.ACCESS_BUNDLE_FILENAME));
            }
        } catch (IOException | ParseException e) {
            Logger.logError(e);
        }

        return bundle;
    }

    /**
     * Returns the relative directory to the client's root directory containing
     * the access bundle for the given file name or <code>null</code>, if an
     * access bundle is not found.
     * 
     * @param clientRoot
     *            the complete path to the client's root directory. Must exist.
     * @param fileName
     *            a valid file name which may be inexistent. Must be relative to
     *            <code>clientRoot</code>.
     * @return the relative directory to the client's root directory containing
     *         the access bundle for the given file name or <code>null</code>,
     *         if an access bundle is not found.
     */
    public static Path getAccessBundleDirectory(Path clientRoot, Path fileName) {
        if ((clientRoot == null) || !Files.isDirectory(clientRoot)) {
            throw new IllegalArgumentException(
                    "clientRoot must be an existing directory!");
        }
        if (!isFileName(fileName)) {
            throw new IllegalArgumentException(
                    "fileName must be a valid file name!");
        }

        Path upperMostDirectory = FileHandler.getUpperMostDirectory(fileName);
        Path completeUpperMostDirectory = Paths.get(clientRoot.toString(),
                upperMostDirectory.toString());

        if (!ROOT_PATH.equals(upperMostDirectory)
                && Files.exists(Paths.get(
                        completeUpperMostDirectory.toString(),
                        AccessBundle.ACCESS_BUNDLE_FILENAME))) {
            return upperMostDirectory;
        } else if (Files.exists(Paths.get(clientRoot.toString(),
                AccessBundle.ACCESS_BUNDLE_FILENAME))) {
            return ROOT_PATH;
        } else {
            return null;
        }
    }

    /**
     * Returns a <code>MESSAGE_DIGEST</code> checksum of the given stream data.
     * At least <code>length</code> bytes from the input stream are read. If the
     * input stream is closed before <code>length</code> bytes have been read,
     * the checksum of the bytes read before the stream was closed is returned.
     * Note that the given input stream is not closed and should therefore be
     * closed in the calling function. The
     * 
     * @param in
     *            the input stream with the data.
     * @param size
     *            the maximum number of bytes to read from input stream.
     * @return the checksum of the given input stream data or <code>null</code>,
     *         if an error occurs.
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] getChecksum(InputStream in, long size)
            throws IOException, NoSuchAlgorithmException {
        if (in == null) {
            throw new NullPointerException("in may not be null!");
        }

        MessageDigest digest = MessageDigest.getInstance(MESSAGE_DIGEST);
        byte[] buffer = new byte[BUFFER_SIZE];
        int count = 0;
        int read;

        while ((count < size)
                && ((read = in.read(buffer, 0,
                        Math.min(buffer.length, (int) (size - count)))) != -1)) {
            digest.update(buffer, 0, read);
            count += read;
        }

        return digest.digest();
    }

    /**
     * Returns a <code>MESSAGE_DIGEST</code> checksum of the given file.
     * 
     * @param file
     *            the file to checksum.
     * @return the checksum of the given file or <code>null</code>, if an error
     *         occurs.
     */
    public static byte[] getChecksum(Path file) {
        if ((file == null) || !Files.isReadable(file)) {
            throw new IllegalArgumentException(
                    "file must exist and be readable!");
        }

        byte[] checksum = null;

        try (FileInputStream in = new FileInputStream(file.toFile());) {
            checksum = getChecksum(in, Files.size(file));
        } catch (IOException | NoSuchAlgorithmException e) {
            Logger.logError(e);
        }

        return checksum;
    }

    /**
     * Encrypts the given file using the newest key found in the respective
     * access bundle and protects the metadata with a message authentication
     * code using the respective integrity key, if desired. Otherwise, the file
     * stays as is and no message authentication code is computed.
     * 
     * @param prefix
     *            the path to the client's root directory. May not be
     *            <code>null</code>.
     * @param file
     *            the relative path to the client's root directory of the
     *            original file to protect. May not be <code>null</code>.
     * @param isDiff
     *            <code>true</code>, if the <code>file</code> is a binary diff.
     *            </code>false</code>, otherwise.
     * @param diff
     *            the complete path to the diff file. If <code>isDiff</code> is
     *            <code>true</code>, this parameter may not be <code>null</code>
     *            .
     * @return the complete path of the file, the metadata of the file as well
     *         as the MAC of the protected data (if applicable).
     *         <code>null</code>, if an error occurs (for example, if the access
     *         bundle is not found).
     */
    public static Triple<Path, ProtectedData, byte[]> getData(Path prefix,
            Path file, boolean isDiff, Path diff) {
        if (prefix == null) {
            throw new NullPointerException("prefix may not be null!");
        }
        if (file == null) {
            throw new NullPointerException("file may not be null!");
        }
        if (isDiff && (diff == null)) {
            throw new IllegalArgumentException(
                    "if isDiff is true, diff must not be null!");
        }

        Path completePath = isDiff ? diff : Paths.get(prefix.toString(),
                file.toString());

        if (!Files.isReadable(completePath)) {
            Logger.logError(String.format(
                    "file %s must exist and be readable!",
                    completePath.toString()));
            return null;
        }

        Triple<Path, ProtectedData, byte[]> result = null;
        Path accessBundleDirectory = FileHandler.getAccessBundleDirectory(
                prefix, file);
        AccessBundle bundle = FileHandler.getAccessBundle(prefix,
                accessBundleDirectory);

        if (bundle != null) {
            if ((bundle.getHighestContentKey() != null)) {
                PreparationProvider provider = PreparationProviderFactory
                        .getInstance(bundle.getHighestContentKey()
                                .getAlgorithm(), bundle
                                .getHighestIntegrityKey().getAlgorithm());
                result = provider.prepareSend(completePath,
                        bundle.getHighestContentKey(),
                        bundle.getHighestIntegrityKey(), isDiff);
            } else if ((bundle.getHighestContentKey() == null)
                    && (bundle.getHighestIntegrityKey() == null)) {
                PreparationProvider provider = PreparationProviderFactory
                        .getInstance(null, null);
                result = provider.prepareSend(completePath, null, null, isDiff);
            } else {
                Logger.logError(String.format("Invalid access bundle in %s",
                        accessBundleDirectory.toString()));
            }
        } else {
            Logger.logError(String.format(
                    "No or invalid access bundle present in %s",
                    accessBundleDirectory.toString()));
        }

        return result;
    }

    /**
     * Returns the group access bundle for the given folder.
     * 
     * @param prefix
     *            the path to the client's root directory. May not be
     *            <code>null</code>.
     * @param folder
     *            a folder path relative to prefix containing a group access
     *            bundle. May not be <code>null</code>.
     * @return the parsed access bundle, if the bundle exists and the bundle is
     *         syntactically correct. <code>null</code>, otherwise.
     */
    public static GroupAccessBundle getGroupAccessBundle(Path prefix,
            Path folder) {
        if (prefix == null) {
            throw new NullPointerException("prefix may not be null!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }

        Path location = Paths.get(prefix.toString(), folder.toString(),
                AccessBundle.ACCESS_BUNDLE_FILENAME);

        if (Files.exists(location)) {
            try {
                return GroupAccessBundle.parse(location);
            } catch (IOException | ParseException e) {
                Logger.logError(e);
            }
        }

        return null;
    }

    /**
     * Returns the owner access bundle for the given folder.
     * 
     * @param prefix
     *            the path to the client's root directory. May not be
     *            <code>null</code>.
     * @param folder
     *            a folder path relative to prefix containing an owner access
     *            bundle. May not be <code>null</code>.
     * @return the parsed access bundle, if the bundle exists and the bundle is
     *         syntactically correct. <code>null</code>, otherwise.
     */
    public static OwnerAccessBundle getOwnerAccessBundle(Path prefix,
            Path folder) {
        if (prefix == null) {
            throw new NullPointerException("prefix may not be null!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }

        Path location = Paths.get(prefix.toString(), folder.toString(),
                AccessBundle.ACCESS_BUNDLE_FILENAME);

        if (Files.exists(location)) {
            try {
                return OwnerAccessBundle.parse(location);
            } catch (IOException | ParseException e) {
                Logger.logError(e);
            }
        }

        return null;
    }

    /**
     * Returns the synchronization data, including the owner name, the server
     * path and the version number or <code>null</code>, if sync data cannot be
     * retrieved.
     * 
     * @param clientRoot
     *            the complete path to the client's root directory. Must exist.
     * @param syncRoot
     *            the complete path to the synchronization root directory. Must
     *            exist.
     * @param fileName
     *            a valid file name which may be inexistent. Must be relative to
     *            <code>clientRoot</code>.
     * @return the synchronization data, including the owner name, the server
     *         path and the version number or <code>null</code>, if sync data
     *         cannot be retrieved.
     */
    public static GetSyncData getSyncData(Path clientRoot, Path syncRoot,
            Path fileName) {
        if ((clientRoot == null) || !Files.isDirectory(clientRoot)) {
            throw new IllegalArgumentException(
                    "clientRoot must be an existing directory!");
        }
        if ((syncRoot == null) || !Files.isDirectory(syncRoot)) {
            throw new IllegalArgumentException(
                    "syncRoot must be an existing directory!");
        }
        if (!isFileName(fileName)) {
            throw new IllegalArgumentException(
                    "fileName must be a valid file name!");
        }

        GetSyncData result = null;
        Path accessBundleDirectory = FileHandler.getAccessBundleDirectory(
                clientRoot, fileName);

        if (accessBundleDirectory != null) {
            int version = 0;
            Path versionFile = Paths.get(syncRoot.toString(),
                    accessBundleDirectory.toString(),
                    SynchronizationExecutor.VERSION_FILE);

            // Parse the version file, if it exists.
            // Otherwise, we are at version 0.
            if (Files.exists(versionFile)) {
                try (BufferedReader reader = Files.newBufferedReader(
                        versionFile, Coder.CHARSET);) {
                    String read = reader.readLine();
                    version = Integer.parseInt(read);
                } catch (IOException | NumberFormatException e) {
                    Logger.logError(e);
                }
            }

            // Parse the access bundle.
            if (ROOT_PATH.equals(accessBundleDirectory)) {
                // We deal with an owner access bundle.
                result = new GetSyncData(null, accessBundleDirectory, version);
            } else {
                // Get owner and server directory from the group access
                // bundle.
                Path bundlePath = Paths.get(clientRoot.toString(),
                        accessBundleDirectory.toString(),
                        AccessBundle.ACCESS_BUNDLE_FILENAME);

                try {
                    GroupAccessBundle accessBundle = GroupAccessBundle
                            .parse(bundlePath);

                    if (accessBundle != null) {
                        String owner = accessBundle.getOwner();
                        String serverPath = accessBundle.getFolder();
                        result = new GetSyncData(owner, Paths.get(serverPath)
                                .normalize(), version);
                    } else {
                        Logger.logError(String.format(
                                "Cannot parse group access bundle %s",
                                bundlePath.toString()));
                    }
                } catch (IOException | ParseException e) {
                    Logger.logError(e);
                }
            }
        }

        return result;
    }

    /**
     * Returns the upper-most directory of the given file path.
     * 
     * @param fileName
     *            the file path to check. Must be a valid path to a file or just
     *            the name of a file (can be inexistent).
     * @return the possibly inexistent upper-most directory of the given file
     *         path. If the file path consists only of the file name, then the
     *         path <code>.</code> is returned.
     */
    public static Path getUpperMostDirectory(Path fileName) {
        if (!isFileName(fileName)) {
            throw new IllegalArgumentException(
                    "fileName must be a valid file name!");
        }

        Path relativePath = ROOT_PATH.resolve(fileName).normalize();
        if (relativePath.getNameCount() >= 2) {
            return relativePath.getName(0);
        } else {
            return ROOT_PATH;
        }
    }

    /**
     * Returns a temporary file path that is on the same file store as the given
     * file. The temporary file is created without content, if the given file's
     * file store is identical to the system's default temporary directory file
     * store.
     * 
     * @param target
     *            the file which determines the file store.
     * @return the path of the temporary file or <code>null</code>, if an error
     *         occurred.
     */
    public static Path getTempFile(Path target) {
        Path tempFile = null;
        boolean success = false;

        target = target.normalize();

        try {
            Path targetDirectory = target.toAbsolutePath().getParent();
            tempFile = Files.createTempFile(target.getFileName().toString(),
                    TEMP_FILE_SUFFIX);

            if (!Files.getFileStore(tempFile).equals(
                    Files.getFileStore(targetDirectory))) {
                // the temporary file should be in the target directory.
                Files.delete(tempFile);
                tempFile = Paths.get(targetDirectory.toString(), tempFile
                        .getFileName().toString());
                success = true;
            } else {
                success = true;
            }
        } catch (IOException e) {
            Logger.logError(e);
        } finally {
            if (!success && (tempFile != null)) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException innerE) {
                    Logger.logError(innerE);
                }
            }
        }

        return success ? tempFile : null;
    }

    /**
     * Returns whether the given file name is a valid file name indeed. In order
     * to be a valid file name, the file can be in an arbitrary level
     * sub-directory of the current folder. The file can also be in the current
     * directory. The name must not contain navigation elements like '..'.
     * 
     * @param fileName
     *            the file name to check.
     * @return <code>true</code>, if the file name is valid. Otherwise,
     *         <code>false</code> is returned.
     */
    public static boolean isFileName(Path fileName) {
        if ((fileName == null)
                || FILE_NAME_BLACKLIST_PATTERN.matcher(fileName.toString())
                        .matches()) {
            return false;
        }

        Path relativePath = Paths.get("./").resolve(fileName).normalize();
        return (relativePath.getNameCount() >= 2)
                || !"".equals(relativePath.toString().trim());
    }

    /**
     * Returns whether the given path is a folder name. The current path
     * <code>.</code> is considered a folder name.
     * 
     * @param folderName
     *            the folder name to check.
     * @return <code>true</code>, if the folder name is a folder name.
     *         Otherwise, <code>false</code> is returned.
     */
    public static boolean isFolderName(Path folderName) {
        if (folderName == null) {
            return false;
        }
        Path relativePath = ROOT_PATH.resolve(folderName).normalize();
        return ROOT_PATH.equals(folderName)
                || (!"".equals(relativePath.toString()) && (relativePath
                        .getNameCount() == 1));
    }

    /**
     * Returns whether the given folder is shared. A folder is shared, if a
     * group access bundle exists in the folder.
     * 
     * @param prefix
     *            the path to the client's root directory. May not be
     *            <code>null</code>.
     * @param folder
     *            a folder path relative to prefix which may contain a group
     *            access bundle. May not be <code>null</code>.
     * @return <code>true</code>, if and only if the given folder is shared.
     *         <code>false</code>, otherwise.
     */
    public static boolean isShared(Path prefix, Path folder) {
        if (prefix == null) {
            throw new NullPointerException("prefix may not be null!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }

        return !"".equals(folder.normalize().toString().trim())
                && (Files
                        .exists(Paths.get(prefix.toString(), folder.toString(),
                                AccessBundle.ACCESS_BUNDLE_FILENAME)));
    }

    /**
     * Returns whether the given path is a folder name suitable for server
     * storage. A folder name is suitable for server storage, if it consists of
     * only lower-case alphanumeric characters, starts with a letter and has a
     * maximum length of 10. Moreover, the folder name must not match
     * <code>ServerConnectionHandler.PRIVATE_FOLDER</code>.
     * 
     * @param folderName
     *            the folder name to check.
     * @return <code>true</code>, if the folder name is a folder name suitable
     *         for server storage. Otherwise, <code>false</code> is returned.
     */
    public static boolean isSharedFolderName(Path folderName) {
        return isFolderName(folderName)
                && !ServerConnectionHandler.PRIVATE_FOLDER.equals(folderName
                        .toString())
                && FOLDER_PATTERN.matcher(folderName.toString()).matches();
    }

    /**
     * Creates any non-existing parent directories for the given file name path.
     * 
     * @param fileName
     *            path to a file name. May include arbitrary many parent
     *            directories. May not be <code>null</code>.
     * @return <code>true</code>, if all parent directories were created
     *         successfully or if there were not any parent directories to
     *         create. Otherwise, <code>false</code> is returned.
     */
    public static boolean makeParentDirs(Path fileName) {
        if (fileName == null) {
            throw new NullPointerException("fileName may not be null!");
        }

        boolean result = true;
        Path normalizedPath = fileName.normalize();
        Path parent = normalizedPath.getParent();

        if (parent != null) {
            result = parent.toFile().mkdirs();
        }

        return result;
    }

    /**
     * Normalizes the given folder name, so that it can be stored in the
     * database.
     * 
     * @param folderName
     *            the folder name to normalize. May be <code>null</code>.
     * @return the normalized folder name.
     */
    public static Path normalizeFolder(Path folderName) {
        if (folderName != null) {
            Path normalized = folderName.normalize();
            return ("".equals(normalized.toString().trim())) ? ROOT_PATH
                    : normalized;
        } else {
            return ROOT_PATH;
        }
    }

    /**
     * Reads data from the input stream and converts it using the algorithms
     * that are specified in the corresponding access bundle. The file is stored
     * in a temporary file. If the integrity of the file is valid, it is moved
     * to the given location, overwriting a possibly existing file with the same
     * name. The input stream is not closed in this method.
     * 
     * @param in
     *            the input stream with the data to receive and convert.
     * @param data
     *            protected data of the file to receive.
     * @param prefix
     *            the path to the client's root directory. May not be
     *            <code>null</code>.
     * @param folder
     *            a folder path relative to prefix which contains an access
     *            bundle. May not be <code>null</code>.
     * @param store
     *            the complete path where the converted file is supposed to be
     *            stored.
     * @return <code>true</code>, if the file was successfully received and
     *         stored. <code>false</code>, otherwise.
     */
    public static boolean receiveAndConvert(InputStream in, ProtectedData data,
            Path prefix, Path folder, Path store) {
        if (in == null) {
            throw new NullPointerException("in may not be null!");
        }
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }
        if (prefix == null) {
            throw new NullPointerException("prefix may not be null!");
        }
        if (folder == null) {
            throw new NullPointerException("folder may not be null!");
        }
        if (store == null) {
            throw new IllegalArgumentException("store may not be null!");
        }

        boolean success = false;
        AccessBundle bundle = FileHandler.getAccessBundle(prefix, folder);

        if (bundle != null) {
            Key decryptionKey = null;
            Key integrityKey = null;
            String decryptionAlgorithm = null;
            String integrityAlgorithm = null;

            if (data.getKeyVersion() >= 1) {
                decryptionKey = bundle.getContentKey(data.getKeyVersion());
                integrityKey = bundle.getIntegrityKey(data.getKeyVersion());

                if ((decryptionKey != null) && (integrityKey != null)) {
                    decryptionAlgorithm = decryptionKey.getAlgorithm();
                    integrityAlgorithm = integrityKey.getAlgorithm();
                }

                if ((decryptionAlgorithm == null)
                        || (integrityAlgorithm == null)) {
                    Logger.logError(String.format(
                            "Invalid access bundle present in %s",
                            folder.toString()));
                    return false;
                }
            }

            PreparationProvider provider = PreparationProviderFactory
                    .getInstance(decryptionAlgorithm, integrityAlgorithm);
            success = provider.prepareReceive(in, data, decryptionKey,
                    integrityKey, store);
        } else {
            Logger.logError(String.format(
                    "No or invalid access bundle present in %s",
                    folder.toString()));
        }

        return success;
    }

    /**
     * Receives data from the given input stream and writes it to the given
     * file. This method reads data from the input stream until the given number
     * of bytes was read or the input stream is closed. Note that this function
     * does not close the given input stream. The output file is locked.
     * 
     * @param in
     *            the input stream with the data to write to the file.
     * @param data
     *            protected data of the file to receive.
     * @param store
     *            the complete path where the decrypted file is supposed to be
     *            stored.
     * @return <code>true</code>, if the file was successfully received and
     *         stored. <code>false</code>, otherwise.
     */
    public static boolean receiveFile(InputStream in, ProtectedData data,
            Path store) {
        if (in == null) {
            throw new NullPointerException("in may not be null!");
        }
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }
        if (store == null) {
            throw new NullPointerException("file may not be null!");
        }

        MessageDigest digest = null;

        try {
            digest = MessageDigest.getInstance(MESSAGE_DIGEST);

            try (FileOutputStream out = new FileOutputStream(store.toFile(),
                    false);) {
                FileLock lock = out.getChannel().tryLock(0, Long.MAX_VALUE,
                        false);

                if (lock != null) {
                    byte[] buffer = new byte[BUFFER_SIZE];
                    long count = 0;
                    int read;

                    while ((count < data.getSize())
                            && ((read = in.read(
                                    buffer,
                                    0,
                                    Math.min(buffer.length,
                                            (int) (data.getSize() - count)))) != -1)) {
                        out.write(buffer, 0, read);
                        digest.update(buffer, 0, read);
                        count += read;
                    }
                    out.flush();
                }
            } catch (IOException | OverlappingFileLockException e) {
                Logger.logError(e);
            }
        } catch (NoSuchAlgorithmException e) {
            Logger.logError(e);
        }

        // check hash
        return (digest != null)
                && MessageDigest.isEqual(data.getHash(), digest.digest());
    }

    /**
     * Returns a canonical representation of the given path as a string.
     * 
     * @param path
     *            the path to convert
     * @return a canonical representation of the given path as a String.
     */
    public static String toCanonicalPath(Path path) {
        if (path == null) {
            return null;
        }

        URI pathUri = path.normalize().toUri();
        return Paths.get("").toUri().relativize(pathUri).toASCIIString();
    }

    /**
     * Transmits the given file over the given output stream. Note that the
     * output stream is not closed by this function.
     * 
     * @param file
     *            the file to transmit.
     * @param byteFirst
     *            first byte of the file to transmit. One-based. If
     *            <code>null</code>, transmission starts at the first byte.
     * @param byteLast
     *            the last byte of the file to transmit. Can be the file size at
     *            max. If <code>null</code>, the file size is taken as this
     *            argument.
     * @param out
     *            the output stream over which the file should be sent.
     * @return <code>true</code>, if the file was successfully transmitted.
     *         <code>false</code>, otherwise.
     */
    public static boolean transmitFile(Path file, Long byteFirst,
            Long byteLast, OutputStream out) {
        if ((file == null) || !Files.isReadable(file)) {
            throw new IllegalArgumentException(
                    "file must exist and be readable!");
        }
        if (byteFirst == null) {
            byteFirst = 1L;
        } else if (byteFirst < 1) {
            throw new IllegalArgumentException(
                    "byteFirst must be at least one!");
        }
        if (byteLast == null) {
            try {
                byteLast = Files.size(file);
            } catch (IOException e) {
                Logger.logError(e);
                return false;
            }
        } else if (byteLast < 1) {
            throw new IllegalArgumentException("byteLast must be at least one!");
        }
        if (out == null) {
            throw new NullPointerException("out may not be null!");
        }

        boolean success = false;

        try (FileInputStream in = new FileInputStream(file.toFile());) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int count = 0;
            int read;

            in.skip(byteFirst - 1L);
            while ((count < byteLast)
                    && ((read = in.read(buffer, 0,
                            Math.min(buffer.length, (int) (byteLast - count)))) != -1)) {
                out.write(buffer, 0, read);
                count += read;
            }
            out.flush();
            success = true;
        } catch (IOException e) {
            Logger.logError(e);
        }

        return success;
    }

    /**
     * Writes the given synchronization version to the version file which
     * belongs to the given file name. The version file is created, if it does
     * not exist yet. Returns whether the version file was successfully written.
     * 
     * @param version
     *            the version number up to which all actions have been executed.
     *            Must be at least <code>0</code>.
     * @param clientRoot
     *            the complete path to the client's root directory. Must exist.
     * @param syncRoot
     *            the complete path to the synchronization root directory. Must
     *            exist.
     * @param pathLocal
     *            the local path to synchronize containing an access bundle.
     *            Must be relative to <code>clientRoot</code>. May not be
     *            <code>null</code>.
     * @return <code>true</code>, if the version file was successfully written.
     *         Otherwise, <code>false</code>.
     */
    public static boolean writeVersion(int version, Path clientRoot,
            Path syncRoot, Path pathLocal) {
        if (version < 0) {
            throw new IllegalArgumentException("version must be at least 0!");
        }
        if ((clientRoot == null) || !Files.isDirectory(clientRoot)) {
            throw new IllegalArgumentException(
                    "clientRoot must be an existing directory!");
        }
        if ((syncRoot == null) || !Files.isDirectory(syncRoot)) {
            throw new IllegalArgumentException(
                    "syncRoot must be an existing directory!");
        }
        if (pathLocal == null) {
            throw new NullPointerException("pathLocal may not be null!");
        }

        boolean success = false;
        Path arbitraryFileName = Paths.get(pathLocal.toString(), "arbitrary");
        Path accessBundleDirectory = FileHandler.getAccessBundleDirectory(
                clientRoot, arbitraryFileName);

        if (accessBundleDirectory != null) {
            Path versionFile = Paths.get(syncRoot.toString(),
                    accessBundleDirectory.toString(),
                    SynchronizationExecutor.VERSION_FILE);
            FileHandler.makeParentDirs(versionFile);

            /*
             * Write the new version into a temporary file and rename it to the
             * version file.
             */
            Path tempFile = FileHandler.getTempFile(versionFile);

            if (tempFile != null) {
                try (BufferedWriter writer = Files.newBufferedWriter(tempFile,
                        Coder.CHARSET);) {
                    writer.write(String.valueOf(version));
                    writer.write('\n');
                    writer.flush();
                    Files.move(tempFile, versionFile,
                            StandardCopyOption.REPLACE_EXISTING);
                    success = true;
                } catch (IOException e) {
                    Logger.logError(e);
                } finally {
                    if (tempFile != null) {
                        try {
                            Files.deleteIfExists(tempFile);
                        } catch (IOException e) {
                            Logger.logError(e);
                        }
                    }
                }
            }
        }

        return success;
    }

    /**
     * Hidden constructor.
     */
    private FileHandler() {
    }
}
