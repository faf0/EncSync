package client.prepare;

import java.io.InputStream;
import java.nio.file.Path;

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
 * Prepares files for transmission to the server: Possibly encrypts files using
 * the algorithm specified by the encryption key. Possbibly protects metadata
 * with the help of a Message Authentication Code specified by the integrity
 * key. <br />
 * 
 * Converts files which are received from the server into plaintext: Possibly
 * decrypts files using the algorithm specified by the encryption key. Possibly
 * checks the Message Authentication Code of metadata using the Message Code
 * Authentication algorithm specified by the integrity key.
 * 
 * @author Fabian Foerg
 */
public interface PreparationProvider {
    /**
     * Prepares the given file for transmission to the server. Possibly encrypts
     * the given file using the given key. The integrity key may be used to
     * compute a Message Authentication Code (MAC). Must use
     * <code>FileHandler.MESSAGE_DIGEST</code> to compute the hash of the
     * converted file.
     * 
     * @param file
     *            the file to convert.
     * @param encryptionKey
     *            the key used to encrypt the file. May be <code>null</code>, if
     *            encryption is not desired.
     * @param integrityKey
     *            the key used to compute the HMAC. May be <code>null</code>, if
     *            HMAC integrity protection is not desired.
     * @param isDiff
     *            <code>true</code>, if <code>file</code> is a diff.
     *            <code>false</code>, otherwise. This becomes part of the
     *            protected metadata.
     * @return the path of the resulting file, its protected data and a HMAC.
     *         <code>null</code> is returned to indicate than an error occurred.
     */
    public Triple<Path, ProtectedData, byte[]> prepareSend(Path file,
            Key encryptionKey, Key integrityKey, boolean isDiff);

    /**
     * Converts files that were received from the server into plaintext.
     * Possibly decrypts the data read from the given input stream is and stores
     * the plaintext in a temporary file. If the integrity of the file is valid,
     * it is moved to the given location, thereby possibly overwriting an
     * existing file with the same name. The input stream is not closed in this
     * method. Uses <code>FileHandler.MESSAGE_DIGEST</code> to compute the hash
     * of the file. Checks the MAC, if present and desired. Note that the MAC of
     * metadata is checked before a file is received.
     * 
     * @param in
     *            the input stream with the data to convert.
     * @param data
     *            protected data of the received data.
     * @param decryptionKey
     *            the key used to decrypt the data. May be <code>null</code>.
     * @param integrityKey
     *            the key used to check the integrity. May be <code>null</code>.
     * @param store
     *            the complete path where the converted file is supposed to be
     *            stored.
     * @return <code>true</code>, if data was successfully received, converted
     *         and stored under the given path. <code>false</code>, otherwise.
     */
    public boolean prepareReceive(InputStream in, ProtectedData data,
            Key decryptionKey, Key integrityKey, Path store);
}
