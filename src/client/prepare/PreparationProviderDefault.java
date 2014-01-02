package client.prepare;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import misc.FileHandler;
import misc.Logger;
import protocol.DataContainers;
import protocol.DataContainers.ProtectedData;
import protocol.DataContainers.Triple;
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
 * Uses the algorithm implementation from the most preferred cryptography
 * provider found by the Java Virtual Machine to encrypt and decrypt files.
 * Works for cipher algorithms which depend on an initialization vector. Is able
 * to transmit and receive plaintext data as well.
 * 
 * @author Fabian Foerg
 */
public final class PreparationProviderDefault implements PreparationProvider {
    /**
     * The buffer size in bytes for file chunks.
     */
    private static final int BUFFER_SIZE = 16 * 1024;

    /**
     * Default constructor.
     */
    public PreparationProviderDefault() {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Triple<Path, ProtectedData, byte[]> prepareSend(Path file,
            Key encryptionKey, Key integrityKey, boolean isDiff) {
        if ((file == null) || !Files.isReadable(file)) {
            throw new IllegalArgumentException(
                    "file must exist and be readable!");
        }

        if ((encryptionKey != null) && (integrityKey != null)) {
            return prepareCiphertextSend(file, encryptionKey, integrityKey,
                    isDiff);
        } else {
            return preparePlaintextSend(file, isDiff);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean prepareReceive(InputStream in, ProtectedData data,
            Key decryptionKey, Key integrityKey, Path store) {
        if (in == null) {
            throw new NullPointerException("in may not be null!");
        }
        if (data == null) {
            throw new NullPointerException("data may not be null!");
        }
        if (store == null) {
            throw new IllegalArgumentException("store may not be null!");
        }

        if (decryptionKey != null) {
            return prepareCiphertextReceive(in, data, decryptionKey, store);
        } else {
            return FileHandler.receiveFile(in, data, store);
        }
    }

    /**
     * Encrypts the given file and computes a MAC for the file's metadata.
     * 
     * @param file
     *            the file to encrypt.
     * @param encryptionKey
     *            the key to encrypt the file.
     * @param integrityKey
     *            the key to compute the MAC.
     * @param isDiff
     *            <code>true</code>, if the file is a diff. Otherwise,
     *            <code>false</code>.
     * @return the path of the resulting file, its protected data and a HMAC.
     *         <code>null</code> is returned to indicate than an error occurred.
     */
    private static Triple<Path, ProtectedData, byte[]> prepareCiphertextSend(
            Path file, Key encryptionKey, Key integrityKey, boolean isDiff) {
        assert ((file != null) && Files.isReadable(file)
                && (encryptionKey != null) && (integrityKey != null));

        Path tmpFile = null;
        ProtectedData data = null;
        byte[] mac = null;
        MessageDigest digest = getDigest(FileHandler.MESSAGE_DIGEST);
        Cipher cipher = getCipher(encryptionKey.getAlgorithm());

        if ((digest != null) && (cipher != null)) {
            SecretKey secret = encryptionKey.getKey();

            try (FileInputStream in = new FileInputStream(file.toFile());
                    FileOutputStream out = new FileOutputStream(
                            (tmpFile = Files.createTempFile(null,
                                    FileHandler.TEMP_FILE_SUFFIX)).toFile(),
                            false);) {
                cipher.init(Cipher.ENCRYPT_MODE, secret);
                byte[] iv = cipher.getIV();
                byte[] buffer = new byte[BUFFER_SIZE];
                int read;

                while ((read = in.read(buffer)) != -1) {
                    byte[] encrypted = cipher.update(buffer, 0, read);
                    if (encrypted != null) {
                        out.write(encrypted);
                        digest.update(encrypted);
                    }
                }

                /*
                 * Ensure that remaining bytes in the cipher buffer are also
                 * encrypted and padded.
                 */
                byte[] encrypted = cipher.doFinal();
                out.write(encrypted);
                digest.update(encrypted);
                // otherwise we might get a wrong file size
                out.flush();

                data = new ProtectedData(isDiff, Files.size(tmpFile),
                        digest.digest(), encryptionKey.getVersion(), iv);
                mac = data.getMAC(integrityKey);
            } catch (InvalidKeyException | IOException
                    | IllegalBlockSizeException | BadPaddingException e) {
                if (tmpFile != null) {
                    try {
                        Files.deleteIfExists(tmpFile);
                    } catch (IOException eInner) {
                        Logger.logError(eInner);
                    } finally {
                        tmpFile = null;
                    }
                }

                Logger.logError(e);
            }
        }

        return ((tmpFile != null) && (data != null) && (mac != null)) ? new Triple<Path, ProtectedData, byte[]>(
                tmpFile, data, mac) : null;
    }

    /**
     * Does not convert the file, i.e. the file stays as is (plaintext).
     * Computes <code>ProtectedData</code> (metadata) for the file.
     * 
     * @param file
     *            the file to use.
     * @param isDiff
     *            <code>true</code>, if the file is a diff. Otherwise,
     *            <code>false</code>.
     * @return the given path of the file, its protected data and
     *         <code>null</code> as the third parameter. <code>null</code> is
     *         returned to indicate than an error occurred.
     */
    private static Triple<Path, ProtectedData, byte[]> preparePlaintextSend(
            Path file, boolean isDiff) {
        assert ((file != null) && Files.isReadable(file));

        Triple<Path, ProtectedData, byte[]> result = null;

        try {
            ProtectedData plaintextMetadata = new ProtectedData(isDiff,
                    Files.size(file), FileHandler.getChecksum(file),
                    DataContainers.PUBLIC_FILE_KEY_VERSION, null);
            result = new Triple<Path, ProtectedData, byte[]>(file,
                    plaintextMetadata, null);
        } catch (IOException e) {
            Logger.logError(e);
        }

        return result;
    }

    /**
     * Decrypts the data read from the given input stream is and stores the
     * plaintext in a temporary file. If the integrity of the file is valid, it
     * is moved to the given location, thereby possibly overwriting an existing
     * file with the same name. The input stream is not closed in this method.
     * Uses <code>FileHandler.MESSAGE_DIGEST</code> to compute the hash of the
     * file.
     * 
     * @param in
     *            the input stream with the data to decrypt and store.
     * @param data
     *            protected data of the received data.
     * @param decryptionKey
     *            the key used to decrypt the data. May be <code>null</code>.
     * @param store
     *            the complete path where the plaintext file is supposed to be
     *            stored.
     * @return <code>true</code>, if data was successfully received, decrypted
     *         and stored under the given path. <code>false</code>, otherwise.
     */
    private static boolean prepareCiphertextReceive(InputStream in,
            ProtectedData data, Key decryptionKey, Path store) {
        assert ((in != null) && (decryptionKey != null) && (store != null));

        boolean success = false;
        Path tempFile = null;
        MessageDigest digest = getDigest(FileHandler.MESSAGE_DIGEST);
        Cipher cipher = getCipher(decryptionKey.getAlgorithm());

        if ((digest != null) && (cipher != null)) {
            SecretKey secret = decryptionKey.getKey();

            try {
                if (data.getExtra() != null) {
                    cipher.init(Cipher.DECRYPT_MODE, secret,
                            new IvParameterSpec(data.getExtra()));
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, secret);
                }

                tempFile = FileHandler.getTempFile(store);

                if (tempFile != null) {
                    try (FileOutputStream out = new FileOutputStream(
                            tempFile.toFile(), false);) {
                        byte[] buffer = new byte[BUFFER_SIZE];
                        long count = 0;
                        int read;

                        // Hash the encrypted data and store the decrypted data.
                        while ((count < data.getSize())
                                && ((read = in
                                        .read(buffer, 0, Math.min(
                                                buffer.length,
                                                (int) (data.getSize() - count)))) != -1)) {
                            digest.update(buffer, 0, read);
                            byte[] decrypted = cipher.update(buffer, 0, read);
                            if (decrypted != null) {
                                out.write(decrypted);
                            }
                            count += read;
                        }
                        byte[] decrypted = cipher.doFinal();
                        out.write(decrypted);
                        out.flush();

                        // check hash
                        boolean hashOK = MessageDigest.isEqual(data.getHash(),
                                digest.digest());
                        // move the temporary file to the desired location
                        success = hashOK
                                && (Files.move(tempFile, store,
                                        StandardCopyOption.REPLACE_EXISTING) != null);
                    } catch (IOException | IllegalBlockSizeException
                            | BadPaddingException e) {
                        Logger.logError(e);
                    }
                }
            } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
                Logger.logError(e);
            }
        }

        // Delete the temporary file, if it is still there.
        if (tempFile != null) {
            try {
                Files.deleteIfExists(tempFile);
            } catch (IOException e) {
                Logger.logError(e);
            }
        }

        return success;
    }

    /**
     * Returns the cipher instance for the given algorithm.
     * 
     * @param algorithm
     *            the cipher algorithm to use.
     * @return the cipher used along with this key or <code>null</code>, if the
     *         key algorithm cannot be used as a cipher.
     */
    private static Cipher getCipher(String algorithm) {
        Cipher result = null;

        try {
            result = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            Logger.logError(e);
        }

        return result;
    }

    /**
     * Returns the message digest instance for the given algorithm.
     * 
     * @param algorithm
     *            the message digest algorithm to use.
     * @return the message digest used along with this key or <code>null</code>,
     *         if the key algorithm cannot be used as a message digest.
     */
    private static MessageDigest getDigest(String algorithm) {
        MessageDigest result = null;

        try {
            result = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            Logger.logError(e);
        }

        return result;
    }
}
