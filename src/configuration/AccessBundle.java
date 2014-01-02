package configuration;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

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
 * Abstract super class of owner and group access bundles.
 * 
 * @author Fabian Foerg
 */
public abstract class AccessBundle {
    /**
     * The filename of access bundles.
     */
    public static final String ACCESS_BUNDLE_FILENAME = ".access";

    public static final String KEY_CONTENT_KEYS = "content_keys";
    public static final String KEY_INTEGRITY_KEYS = "integrity_keys";

    private final Key[] contentKeys;
    private final Key[] integrityKeys;

    /**
     * Creates an access bundle without parameters.
     */
    public AccessBundle() {
        contentKeys = null;
        integrityKeys = null;
    }

    /**
     * Creates a new owner access bundle with the given parameters. The lengths
     * of both key arrays must match and are at least one. Additionally, the key
     * versions must match for each index.
     * 
     * @param contentKeys
     *            the keys to en- and decrypt files
     * @param integrityKeys
     *            the keys to compute HMACs. Must have the same length as
     *            <code>contentKeys</code>. the minimum allowed key version.
     */
    public AccessBundle(Key[] contentKeys, Key[] integrityKeys) {
        if (contentKeys == null) {
            throw new NullPointerException("contentKeys may not be null!");
        }
        if (integrityKeys == null) {
            throw new NullPointerException("integrityKeys may not be null!");
        }
        if (!isValid(contentKeys, integrityKeys)) {
            throw new IllegalArgumentException(
                    "the length of both arrays must match and be at least one! The key versions per index must also match!");
        }

        this.contentKeys = contentKeys;
        this.integrityKeys = integrityKeys;
    }

    /**
     * Returns whether the content key and integrity keys are valid, i.e. the
     * lengths of both key arrays match and are at least one. Additionally, the
     * key versions match for each index.
     * 
     * @param contentKeys
     * @param integrityKeys
     * @return <code>true</code>, if the arrays are valid. <code>false</code>,
     *         otherwise.
     */
    private static boolean isValid(Key[] contentKeys, Key[] integrityKeys) {
        if ((contentKeys != null) && (integrityKeys != null)
                && (contentKeys.length >= 1)
                && (contentKeys.length == integrityKeys.length)) {
            for (int i = 0; i < contentKeys.length; i++) {
                if (contentKeys[i].getVersion() != integrityKeys[i]
                        .getVersion()) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Returns the keys used to en- and decrypt the files.
     * 
     * @return the keys used to en- and decrypt the files.
     */
    public Key[] getContentKeys() {
        return contentKeys;
    }

    /**
     * Returns the keys used to compute HMACs.
     * 
     * @return the keys used to compute HMACs.
     */
    public Key[] getIntegrityKeys() {
        return integrityKeys;
    }

    /**
     * Returns the content key with the given version.
     * 
     * @param version
     *            the version of the key to get. Must be at least one.
     * @return the key with the given version or <code>null</code>, if the key
     *         does not exist.
     */
    public Key getContentKey(int version) {
        return Key.getKey(contentKeys, version);
    }

    /**
     * Returns the integrity key with the given version.
     * 
     * @param version
     *            the version of the key to get. Must be at least one.
     * @return the key with the given version or <code>null</code>, if the key
     *         does not exist.
     */
    public Key getIntegrityKey(int version) {
        return Key.getKey(integrityKeys, version);
    }

    /**
     * Returns the content key with the highest key number.
     * 
     * @return the content key with the highest key number or <code>null</code>,
     *         if there are no content keys.
     */
    public Key getHighestContentKey() {
        return Key.getHighestKey(contentKeys);
    }

    /**
     * Returns the integrity key with the highest key number.
     * 
     * @return the integrity key with the highest key number or
     *         <code>null</code>, if there are no integrity keys.
     */
    public Key getHighestIntegrityKey() {
        return Key.getHighestKey(integrityKeys);
    }

    /**
     * Returns the highest key version among all keys.
     * 
     * @return the highest key version among all keys.
     */
    public int getHighestKeyVersion() {
        return Key.getHighestKeyVersion(contentKeys);
    }

    /**
     * Returns a map representation of this object.
     * 
     * @return a map representation of this object.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> main = new HashMap<>();
        List<Map<String, Object>> listContentKeys = new LinkedList<>();
        List<Map<String, Object>> listIntegrityKeys = new LinkedList<>();

        for (Key contentKey : contentKeys) {
            listContentKeys.add(contentKey.toMap());
        }

        for (Key integrityKey : integrityKeys) {
            listIntegrityKeys.add(integrityKey.toMap());
        }

        main.put(KEY_CONTENT_KEYS, listContentKeys);
        main.put(KEY_INTEGRITY_KEYS, listIntegrityKeys);

        return main;
    }
}
