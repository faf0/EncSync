package configuration;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

import misc.Coder;
import misc.FileHandler;
import misc.JSONPrettyPrintWriter;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.ParseException;

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
 * Represents and manages group access bundle files.
 * 
 * @author Fabian Foerg
 */
public final class GroupAccessBundle extends AccessBundle {
    public static final String KEY_OWNER = "owner";
    public static final String KEY_FOLDER = "folder";

    private final String owner;
    private final String folder;
    private final boolean isPublic;

    /**
     * Creates a new group access bundle (public) with the given parameters.
     * 
     * @param owner
     *            the owner of the group.
     * @param folder
     *            the folder name under the owner's root directory.
     *            <code>null</code> for public bundles.
     */
    public GroupAccessBundle(String owner, String folder) {
        super();

        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if ((folder == null)
                || !FileHandler.isSharedFolderName(Paths.get(folder))) {
            throw new IllegalArgumentException("folder must be valid!");
        }

        this.owner = owner;
        this.folder = folder;
        isPublic = true;
    }

    /**
     * Creates a new group access bundle (non-public) with the given parameters.
     * 
     * @param owner
     *            the owner of the group.
     * @param folder
     *            the folder name under the owner's root directory.
     *            <code>null</code> for public bundles.
     * @param contentKeys
     *            the keys for en- and decrypting the file contents.
     *            <code>null</code> for public bundles.
     * @param integrityKeys
     *            the keys to compute HMACs. Must have the same length as
     *            <code>contentKeys</code>.
     */
    public GroupAccessBundle(String owner, String folder, Key[] contentKeys,
            Key[] integrityKeys) {
        super(contentKeys, integrityKeys);

        if (!ClientConfiguration.isValidUserName(owner)) {
            throw new IllegalArgumentException("owner must be valid!");
        }
        if ((folder == null)
                || !FileHandler.isSharedFolderName(Paths.get(folder))) {
            throw new IllegalArgumentException("folder must be valid!");
        }

        this.owner = owner;
        this.folder = folder;
        isPublic = false;
    }

    /**
     * Returns the owner of the group.
     */
    public String getOwner() {
        return owner;
    }

    /**
     * Returns the folder name under the owner's root directory.
     * 
     * @return folder name under the owner's root directory.
     */
    public String getFolder() {
        return folder;
    }

    /**
     * Returns whether this group access bundle is for publicly shared files.
     * 
     * @return <code>true</code>, if this access bundles is for publicly shared
     *         files. <code>false</code> otherwise.
     */
    public boolean isPublic() {
        return isPublic;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> thisMap = new LinkedHashMap<>();

        thisMap.put(KEY_OWNER, owner);
        thisMap.put(KEY_FOLDER, folder);

        if (!isPublic) {
            Map<String, Object> superContent = super.toMap();
            thisMap.put(KEY_CONTENT_KEYS, superContent.get(KEY_CONTENT_KEYS));
            thisMap.put(KEY_INTEGRITY_KEYS,
                    superContent.get(KEY_INTEGRITY_KEYS));
        }

        return thisMap;
    }

    /**
     * Parses the given group access bundle.
     * 
     * @param file
     *            the path to the file to parse.
     * @return the parsed group access bundle or <code>null</code>, if the
     *         bundle does not exist or is invalid.
     * @throws FileNotFoundException
     * @throws IOException
     * @throws ParseException
     */
    public static GroupAccessBundle parse(Path file)
            throws FileNotFoundException, IOException, ParseException {
        if (file == null) {
            throw new NullPointerException("file may not be null!");
        }

        if (Files.exists(file)) {
            return Parser.parse(file);
        } else {
            return null;
        }
    }

    /**
     * Store this group access bundle under the given path.
     * 
     * @param file
     *            the path where to store the group access bundle.
     * @throws IOException
     */
    public void store(Path file) throws IOException {
        if (file == null) {
            throw new NullPointerException("file may not be null!");
        }

        Parser.store(this, file);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        Writer writer = new JSONPrettyPrintWriter();
        try {
            JSONValue.writeJSONString(this.toMap(), writer);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return writer.toString();
    }

    /**
     * Parses and stores group access bundles.
     * 
     * @author Fabian Foerg
     */
    private static class Parser {
        /**
         * Parses the given group access bundle.
         * 
         * @param file
         *            the path to the file to parse.
         * @return the parsed group access bundle.
         * @throws FileNotFoundException
         * @throws IOException
         * @throws ParseException
         */
        public static GroupAccessBundle parse(Path file)
                throws FileNotFoundException, IOException, ParseException {
            if ((file == null) || !Files.isReadable(file)) {
                throw new NullPointerException("file must be readable!");
            }

            BufferedReader in = Files.newBufferedReader(file, Coder.CHARSET);
            StringBuilder sb = new StringBuilder();
            String read = null;
            String owner, folder;
            JSONObject object;
            JSONArray arrayContentKeys, arrayIntegrityKeys;
            Key[] contentKeys = null, integrityKeys = null;

            // load file
            do {
                read = in.readLine();

                if (read != null) {
                    sb.append(read);
                }
            } while (read != null);

            if (in != null) {
                in.close();
            }

            // parse file
            object = (JSONObject) JSONValue.parse(sb.toString());
            owner = (String) object.get(KEY_OWNER);
            folder = (String) object.get(KEY_FOLDER);

            arrayContentKeys = (JSONArray) object.get(KEY_CONTENT_KEYS);
            arrayIntegrityKeys = (JSONArray) object.get(KEY_INTEGRITY_KEYS);

            if (arrayContentKeys != null) {
                contentKeys = Key.parseKeys(arrayContentKeys);
            }
            if (arrayIntegrityKeys != null) {
                integrityKeys = Key.parseKeys(arrayIntegrityKeys);
            }

            if ((contentKeys != null) && (integrityKeys != null)) {
                return new GroupAccessBundle(owner, folder, contentKeys,
                        integrityKeys);
            } else if ((contentKeys == null) && (integrityKeys == null)) {
                return new GroupAccessBundle(owner, folder);
            } else {
                return null;
            }
        }

        /**
         * Store the given group access bundle under the given path.
         * 
         * @param ab
         *            the group access bundle to store.
         * @param file
         *            the path where to store the group access bundle.
         * @throws IOException
         */
        public static void store(GroupAccessBundle ab, Path file)
                throws IOException {
            if (file == null) {
                throw new NullPointerException("file may not be null!");
            }

            BufferedWriter out = Files.newBufferedWriter(file, Coder.CHARSET);

            if (out != null) {
                out.write(ab.toString());
                out.close();
            }
        }
    }
}
