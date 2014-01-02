package configuration;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import misc.Coder;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

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
 * Represents and manages symmetric keys.
 * 
 * @author Fabian Foerg
 */
public final class Key {
    public static final String KEY_VERSION = "version";
    public static final String KEY_ALGORITHM = "algorithm";
    public static final String KEY_KEY = "key";

    private final SecretKey key;
    private final int version;
    private final String algorithm;

    /**
     * Creates a new key with the given parameters.
     * 
     * @param key
     *            the symmetric key itself
     * @param version
     *            the version of the key
     * @param algorithm
     *            the cipher algorithm name or the HMAC algorithm used with the
     *            key
     */
    public Key(SecretKey key, int version, String algorithm) {
        if (key == null) {
            throw new NullPointerException("key may not be null!");
        }
        if (version < 1) {
            throw new IllegalArgumentException("version must be at least one!");
        }
        if (algorithm == null) {
            throw new NullPointerException("algorithm may not be null!");
        }

        this.key = key;
        this.version = version;
        this.algorithm = algorithm;
    }

    /**
     * Returns the key itself.
     * 
     * @return the key itself.
     */
    public SecretKey getKey() {
        return key;
    }

    /**
     * Returns the version of this key.
     * 
     * @return the version of this key.
     */
    public int getVersion() {
        return version;
    }

    /**
     * Returns the cipher algorithm name or the HMAC algorithm used with this
     * key.
     * 
     * @return the cipher algorithm name or the HMAC algorithm used with this
     *         key.
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Returns a map representation of this key.
     * 
     * @return a map representation of this key.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> thisMap = new LinkedHashMap<>();

        thisMap.put(KEY_VERSION, new Integer(version));
        thisMap.put(KEY_ALGORITHM, algorithm);
        /*
         * getEncoded() returns the raw bytes of the key (s.
         * http://docs.oracle.com/javase/7/docs/api/javax/crypto/SecretKey.html)
         */
        thisMap.put(KEY_KEY, Coder.encodeBASE64(key.getEncoded()));

        return thisMap;
    }

    /**
     * Creates a random key with the given parameters.
     * 
     * @param keySize
     *            the length of the key in bits.
     * @param version
     *            the version of the key.
     * @param algorithm
     *            the string representation of the cipher or HMAC algorithm
     *            used.
     * @return the random key with the specified parameters or <code>null</code>
     *         , if the key cannot be generated.
     */
    public static Key randomKey(int keySize, int version, String algorithm) {
        if (keySize < 1) {
            throw new IllegalArgumentException(
                    "keySize has to be at least one!");
        }
        if (version < 1) {
            throw new IllegalArgumentException("version must be at least one!");
        }
        if (algorithm == null) {
            throw new NullPointerException("algorithm may not be null!");
        }

        SecretKey secretKey = null;

        try {
            KeyGenerator generator = KeyGenerator
                    .getInstance(getSecretKeyAlgorithm(algorithm));
            generator.init(keySize);
            secretKey = generator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return (secretKey != null) ? new Key(secretKey, version, algorithm)
                : null;
    }

    /**
     * Returns the keys provided in the JSON array.
     * 
     * @param array
     *            the JSON array to parse for keys.
     * @return the keys provided in the JSON array.
     */
    public static Key[] parseKeys(JSONArray array) {
        List<Key> keys = new LinkedList<Key>();

        if (array == null) {
            throw new NullPointerException("array may not be null!");
        }

        for (int i = 0; i < array.size(); i++) {
            JSONObject object = (JSONObject) array.get(i);
            String key = (String) object.get(KEY_KEY);
            Long version = (Long) object.get(KEY_VERSION);
            int versionInt = version.intValue();
            String algorithm = (String) object.get(KEY_ALGORITHM);
            /*
             * getEncoded() returns the raw bytes of the key (s.
             * http://docs.oracle
             * .com/javase/7/docs/api/javax/crypto/SecretKey.html)
             */
            try {
                byte[] rawKey = Coder.decodeBASE64(key);
                SecretKey secretKey = new SecretKeySpec(rawKey,
                        getSecretKeyAlgorithm(algorithm));
                keys.add(new Key(secretKey, versionInt, algorithm));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return keys.toArray(new Key[0]);
    }

    /**
     * Returns the highest key version.
     * 
     * @param keys
     *            the keys to search through.
     * @return the highest key version or <code>-1</code>, if no key exists.
     */
    public static int getHighestKeyVersion(Key[] keys) {
        if (keys != null) {
            Key highestKey = Key.getHighestKey(keys);
            return (highestKey != null) ? highestKey.version : -1;
        } else {
            return -1;
        }
    }

    /**
     * Return the key with the highest version.
     * 
     * @param keys
     *            the keys to search through.
     * @return the key with the highest version or <code>null</code>, if no key
     *         exists.
     */
    public static Key getHighestKey(Key[] keys) {
        if (keys != null) {
            int max = -1;
            Key result = null;

            for (Key key : keys) {
                if (key.version > max) {
                    result = key;
                }
            }

            return result;
        } else {
            return null;
        }
    }

    /**
     * Returns the key with the given version.
     * 
     * @param keys
     *            the keys to search through.
     * @param version
     *            the version of the key. Must be at least one.
     * @return the key with the given version or <code>null</code>, if the key
     *         was not found.
     */
    public static Key getKey(Key[] keys, int version) {
        if (version < 1) {
            throw new IllegalArgumentException("version must be at least one!");
        }

        if (keys != null) {
            Key result = null;

            for (Key key : keys) {
                if (key.version == version) {
                    result = key;
                    break;
                }
            }

            return result;
        } else {
            return null;
        }
    }

    /**
     * Extracts the key generation algorithm from the possible cipher algorithm
     * string.
     * 
     * @param algorithm
     *            an algorithm string.
     * @return the extracted key generation algorithm from the given string.
     */
    private static String getSecretKeyAlgorithm(String algorithm) {
        int delimiterIndex = algorithm.indexOf('/');
        return (delimiterIndex != -1) ? algorithm.substring(0, delimiterIndex)
                : algorithm;
    }
}
