package server.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import misc.Coder;
import misc.Logger;
import server.database.DatabaseConnection;
import configuration.ClientConfiguration;

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
 * Utility class for salted password creation and credential verification. The
 * creation method uses PBEWithMD5andDES.
 * 
 * @author Fabian Foerg
 */
public final class Authentication {
    public static final int ITERATIONS = 1000;

    /**
     * Hidden constructor.
     */
    private Authentication() {
    }

    /**
     * Returns a salted hash using 8 random bytes as the salt and the given
     * password as the secret. (see {@link http
     * ://download.oracle.com/javase/7/docs/technotes/guides/security
     * /crypto/CryptoSpec.html for a sample implementation})
     * 
     * @param plainTextPassword
     *            the plain text password.
     * @param salt
     *            a byte array of 8 random bytes.
     * @return a salted hash of password.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] createSaltedHash(String plainTextPassword, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {
        PBEKeySpec pbeKeySpec;
        PBEParameterSpec pbeParamSpec;
        SecretKeyFactory keyFac;
        SecretKey pbeKey;
        Cipher pbeCipher;

        if ((plainTextPassword == null) || (plainTextPassword.length() < 1)) {
            throw new IllegalArgumentException(
                    "password must exist and have at least length one.");
        }
        if (salt.length != 8) {
            throw new IllegalArgumentException("salt has to have length eight.");
        }

        pbeParamSpec = new PBEParameterSpec(salt, ITERATIONS);
        pbeKeySpec = new PBEKeySpec(Coder.stringToChar(plainTextPassword));

        keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        pbeKey = keyFac.generateSecret(pbeKeySpec);

        pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

        return pbeCipher.doFinal(Coder.stringToByte(plainTextPassword));
    }

    /**
     * Checks whether the given user name and password combination is valid.
     * 
     * @param userName
     *            the user name.
     * @param password
     *            the password.
     * @return <code>true</code>, if the combination is valid. Otherwise,
     *         <code>false</code> is returned.
     */
    public static boolean isValidCredentials(String userName, String password) {
        boolean valid = false;
        ResultSet rs = null;
        byte[] computedSaltedHash = null;

        if (!(ClientConfiguration.isValidUserName(userName) && ClientConfiguration
                .isValidPassword(password))) {
            return false;
        }

        try (Connection connection = DatabaseConnection.getConnection();
                PreparedStatement query = connection
                        .prepareStatement("SELECT salted_hash,salt FROM users WHERE user=?;");) {
            query.setString(1, userName);
            rs = query.executeQuery();
            if (rs.next()) {
                computedSaltedHash = Authentication.createSaltedHash(password,
                        rs.getBytes("salt"));
                valid = MessageDigest.isEqual(computedSaltedHash,
                        rs.getBytes("salted_hash"));
            }
        } catch (Exception e) {
            Logger.logError(e);
        }

        return valid;
    }
}
