package client.tools;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

import misc.Coder;

import org.json.simple.parser.ParseException;

import protocol.DataContainers.Pair;
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
 * Reads an owner or group access bundle and prompts the user for respective
 * updates. Also allows to create new owner and group access bundles.
 * 
 * @author Fabian Foerg
 */
public final class AccessBundleShell {
    private BufferedReader in;
    private static final String DEFAULT_CIPHER = "AES/CBC/PKCS5Padding";
    private static final String DEFAULT_MAC = "HmacSHA256";
    private static final int DEFAULT_CIPHER_KEY_LENGTH = 256;
    private static final int DEFAULT_MAC_KEY_LENGTH = 256;

    /**
     * Creates a new access bundle shell.
     */
    public AccessBundleShell() {
        in = new BufferedReader(new InputStreamReader(System.in, Coder.CHARSET));
    }

    /**
     * Starts the creation/update process for access bundles.
     */
    public void start() {
        try {
            boolean done = false;
            boolean overwrite = false;
            Path accessBundle = null;

            while (!done) {
                System.out
                        .println("In which folder do you want to store your access bundle?");
                String input = in.readLine();
                Path accessBundleFolderPath = Paths.get(input.trim());

                if ((accessBundleFolderPath != null)
                        && Files.exists(accessBundleFolderPath)
                        && Files.isDirectory(accessBundleFolderPath)) {
                    accessBundle = Paths.get(accessBundleFolderPath.toString(),
                            AccessBundle.ACCESS_BUNDLE_FILENAME);

                    if (Files.exists(accessBundle)) {
                        System.out
                                .println("Do you want to update (u) or overwrite (overwrite) your existing access bundle? [u] ");
                        input = in.readLine();

                        if ((input != null)
                                && "overwrite".equals(input.trim()
                                        .toLowerCase())) {
                            overwrite = true;
                        }
                    }

                    done = true;
                } else {
                    System.out
                            .println("The folder does not exist or is a file. Please enter a valid folder name.");
                }
            }

            System.out
                    .println("Do you want to build an owner (o) or a group access bundle (g)? [o]");
            String input = in.readLine();

            if ("g".equals(input.trim().toLowerCase())) {
                GroupAccessBundle bundle = null;

                if (!overwrite) {
                    bundle = GroupAccessBundle.parse(accessBundle);
                }

                GroupAccessBundle newBundle = createGroupAccessBundle(bundle);
                newBundle.store(accessBundle);
            } else {
                OwnerAccessBundle bundle = null;

                if (!overwrite) {
                    bundle = OwnerAccessBundle.parse(accessBundle);
                }

                OwnerAccessBundle newBundle = createOwnerAccessBundle(bundle);
                newBundle.store(accessBundle);
            }

            System.out.format("Successfully stored the bundle at %s\n",
                    accessBundle.toString());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Creates a (content, integrity) key pair.
     * 
     * @param version
     *            the version of the key
     * @return a pair of new random (content, integrity) keys with the user
     *         specified properties.
     * @throws IOException
     */
    private Pair<Key, Key> createKeys(int version) throws IOException {
        String input;
        String cipherString = null;
        String macString = null;
        int cipherKeyLength = DEFAULT_CIPHER_KEY_LENGTH;
        int macKeyLength = DEFAULT_MAC_KEY_LENGTH;
        boolean done = false;

        // Cipher key generation
        while (!done) {
            System.out.format("Specify the cipher [%s]: ", DEFAULT_CIPHER);
            input = in.readLine();
            cipherString = input;

            if ((cipherString == null) || "".equals(cipherString.trim())) {
                cipherString = DEFAULT_CIPHER;
            }
            try {
                Cipher.getInstance(cipherString.trim());
                done = true;
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                System.out.println("Algorithm or padding not available.");
            }
        }

        done = false;

        while (!done) {
            System.out.format(
                    "Specify the length of the cipher key in bits [%d]: ",
                    DEFAULT_CIPHER_KEY_LENGTH);
            input = in.readLine();

            if ((input == null) || "".equals(input.trim())) {
                cipherKeyLength = DEFAULT_CIPHER_KEY_LENGTH;
                done = true;
            } else {
                try {
                    cipherKeyLength = Integer.valueOf(input);

                    if (cipherKeyLength < 1) {
                        System.out.println("Invalid key length.");
                    } else {
                        done = true;
                    }
                } catch (NumberFormatException e) {
                    System.out.println("Please enter a positive integer.");
                }
            }
        }

        // MAC key generation
        done = false;

        while (!done) {
            System.out.format("Specify the MAC algorithm [%s]: ", DEFAULT_MAC);
            input = in.readLine();
            macString = input;

            if ((macString == null) || "".equals(macString.trim())) {
                macString = DEFAULT_MAC;
            }
            try {
                Mac.getInstance(macString.trim());
                done = true;
            } catch (NoSuchAlgorithmException e) {
                System.out.println("Algorithm not available.");
            }
        }

        done = false;

        while (!done) {
            System.out.format(
                    "Specify the length of the MAC key in bits [%d]: ",
                    DEFAULT_MAC_KEY_LENGTH);
            input = in.readLine();

            if ((input == null) || "".equals(input.trim())) {
                macKeyLength = DEFAULT_MAC_KEY_LENGTH;
                done = true;
            } else {
                try {
                    macKeyLength = Integer.valueOf(input);

                    if (macKeyLength < 1) {
                        System.out.println("Invalid key length.");
                    } else {
                        done = true;
                    }
                } catch (NumberFormatException e) {
                    System.out.println("Please enter a positive integer.");
                }
            }
        }

        return new Pair<Key, Key>(Key.randomKey(cipherKeyLength, version,
                cipherString), Key.randomKey(macKeyLength, version, macString));
    }

    /**
     * Allows to create a new keys and allows to append them to already existing
     * arrays.
     * 
     * @param contentKeys
     *            an already existing content key array or <code>null</code>.
     * @param integrityKeys
     *            an already existing integrity key array or <code>null</code>.
     * @param currentKeyVersion
     *            the version of the to be created key.
     * @param question
     *            the question to ask the user.
     * @return a (content keys, integrity keys) pair keys where the created keys
     *         are appended.
     * @throws IOException
     */
    private Pair<Key[], Key[]> createKeys(Key[] contentKeys,
            Key[] integrityKeys, int currentKeyVersion, String question)
            throws IOException {
        boolean done = false;
        List<Key> contentKeyList = new LinkedList<Key>();
        List<Key> integrityKeyList = new LinkedList<Key>();

        if ((contentKeys != null) && (integrityKeys != null)
                && (contentKeys.length == integrityKeys.length)) {
            for (Key key : contentKeys) {
                contentKeyList.add(key);
            }

            for (Key key : integrityKeys) {
                integrityKeyList.add(key);
            }
        }

        while (!done) {
            System.out.println(question + " y/n [n] ");
            String input = in.readLine();

            if ((input != null) && "y".equals(input.trim().toLowerCase())) {
                Pair<Key, Key> keys = createKeys(currentKeyVersion);

                if (keys != null) {
                    contentKeyList.add(keys.getFirst());
                    integrityKeyList.add(keys.getSecond());
                    done = true;
                } else {
                    System.out.println("Key creation failed.");
                }
            } else {
                done = true;
            }
        }

        return new Pair<Key[], Key[]>(contentKeyList.toArray(new Key[0]),
                integrityKeyList.toArray(new Key[0]));
    }

    /**
     * Updates or creates an owner access bundle from scratch.
     * 
     * @param bundle
     *            may be <code>null</code>, when a new bundle should be created.
     * @throws IOException
     */
    private OwnerAccessBundle createOwnerAccessBundle(OwnerAccessBundle bundle)
            throws IOException {
        int keyVersion = 0;
        Key[] contentKeys = null;
        Key[] integrityKeys = null;
        Pair<Key[], Key[]> keys;

        if (bundle != null) {
            keyVersion = bundle.getHighestKeyVersion();
            contentKeys = bundle.getContentKeys();
            integrityKeys = bundle.getIntegrityKeys();
        }

        keys = createKeys(contentKeys, integrityKeys, keyVersion + 1,
                "Do you want to add a new file content and metadata integrity key?");

        return new OwnerAccessBundle(keys.getFirst(), keys.getSecond());
    }

    /**
     * Allows to create a non-<code>null</code> string which has at least length
     * one.
     * 
     * @param question
     *            the question to pose.
     * @return a non-<code>null</code> string which has at least length one.
     * @throws IOException
     */
    private String createSetString(String question) throws IOException {
        boolean done = false;
        String result = null;

        while (!done) {
            System.out.println(question);
            String input = in.readLine();

            if ((input != null) && (input.length() > 0)) {
                result = input;
                done = true;
            } else {
                System.out
                        .println("The entered string must have at least length one.");
            }
        }

        return result;
    }

    /**
     * Allows the user to decide whether she wants to do something.
     * 
     * @param question
     *            the question to pose.
     * @return <code>true</code>, if the answer was yes. Otherwise,
     *         <code>false</code> is returned.
     * @throws IOException
     */
    private boolean askChange(String question) throws IOException {
        System.out.println(question + " y/n [n]: ");
        String input = in.readLine();

        return (input != null) && "y".equals(input.trim().toLowerCase());
    }

    /**
     * Updates or creates a group access bundle from scratch.
     * 
     * @param bundle
     *            may be null, when a new bundle should be created.
     * @throws IOException
     */
    private GroupAccessBundle createGroupAccessBundle(GroupAccessBundle bundle)
            throws IOException {
        String owner = null;
        String folder = null;
        int keyVersion = 0;
        Key[] contentKeys = null;
        Key[] integrityKeys = null;
        Pair<Key[], Key[]> keys;

        if (bundle != null) {
            owner = bundle.getOwner();
            folder = bundle.getFolder();
            keyVersion = bundle.getHighestKeyVersion();
            contentKeys = bundle.getContentKeys();
            integrityKeys = bundle.getIntegrityKeys();
        }

        if ((owner == null) || askChange("Do you want to change the owner?")) {
            owner = createSetString("Please enter the name of the owner: ");
        }

        if ((folder == null)
                || askChange("Do you want to change the name of the shared folder?")) {
            folder = createSetString("Please enter the name of the shared folder: ");
        }

        keys = createKeys(contentKeys, integrityKeys, keyVersion + 1,
                "Do you want to add a new file content and metadata integrity key?");

        return new GroupAccessBundle(owner, folder, keys.getFirst(),
                keys.getSecond());
    }

    /**
     * Starts the shell which allows the user to specify owner and group access
     * bundles.
     * 
     * @param args
     *            not evaluated.
     */
    public static void main(String[] args) {
        AccessBundleShell shell = new AccessBundleShell();
        shell.start();
    }
}
