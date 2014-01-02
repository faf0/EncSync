package configuration;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import misc.Coder;
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
 * Represents and manages owner access bundle files.
 * 
 * @author Fabian Foerg
 */
public final class OwnerAccessBundle extends AccessBundle {
    public static final String KEY_NAME_KEYS = "name_keys";

    /**
     * Creates a new owner access bundle with the given parameters.
     * 
     * @param contentKeys
     *            the keys to en- and decrypt files.
     * @param integrityKeys
     *            the keys to compute HMACs. Must have the same length as
     *            <code>contentKeys</code>.
     */
    public OwnerAccessBundle(Key[] contentKeys, Key[] integrityKeys) {
        super(contentKeys, integrityKeys);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> thisMap = new LinkedHashMap<>();
        Map<String, Object> superContent = super.toMap();

        thisMap.put(KEY_CONTENT_KEYS, superContent.get(KEY_CONTENT_KEYS));
        thisMap.put(KEY_INTEGRITY_KEYS, superContent.get(KEY_INTEGRITY_KEYS));

        return thisMap;
    }

    /**
     * Parses the given owner access bundle.
     * 
     * @param file
     *            the path to the file to parse.
     * @return the parsed owner access bundle or <code>null</code>, if the
     *         bundle does not exist or is invalid.
     * @throws FileNotFoundException
     * @throws IOException
     * @throws ParseException
     */
    public static OwnerAccessBundle parse(Path file)
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
     * Store this owner access bundle under the given path.
     * 
     * @param file
     *            the path where to store the owner access bundle.
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
     * Parses and stores owner access bundles.
     * 
     * @author Fabian Foerg
     */
    private static class Parser {
        public static OwnerAccessBundle parse(Path file)
                throws FileNotFoundException, IOException, ParseException {
            if ((file == null) || !Files.isReadable(file)) {
                throw new NullPointerException("file must be readable!");
            }

            BufferedReader in = Files.newBufferedReader(file, Coder.CHARSET);
            StringBuilder sb = new StringBuilder();
            String read = null;
            JSONObject object;
            JSONArray arrayContentKeys, arrayIntegrityKeys;
            Key[] contentKeys, integrityKeys;

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

            arrayContentKeys = (JSONArray) object.get(KEY_CONTENT_KEYS);
            arrayIntegrityKeys = (JSONArray) object.get(KEY_INTEGRITY_KEYS);

            if (arrayContentKeys != null) {
                contentKeys = Key.parseKeys(arrayContentKeys);
            } else {
                return null;
            }
            if (arrayIntegrityKeys != null) {
                integrityKeys = Key.parseKeys(arrayIntegrityKeys);
            } else {
                return null;
            }

            return new OwnerAccessBundle(contentKeys, integrityKeys);
        }

        /**
         * Store the given owner access bundle under the given path.
         * 
         * @param ab
         *            the owner access bundle to store.
         * @param file
         *            the path where to store the owner access bundle.
         * @throws IOException
         */
        public static void store(OwnerAccessBundle ab, Path file)
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
