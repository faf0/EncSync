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
import java.util.regex.Pattern;

import misc.Coder;
import misc.FileHandler;
import misc.JSONPrettyPrintWriter;

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
 * Allows to parse and store client configuration files.
 * 
 * @author Fabian Foerg
 */
public final class ClientConfiguration {
    public static final String KEY_ROOT_PATH = "root_path";
    public static final String KEY_USER = "user";
    public static final String KEY_PASSWORD = "password";
    public static final String KEY_SERVER_HOST = "server_host";
    public static final String KEY_SERVER_PORT = "server_port";
    public static final String KEY_SERVER_CERT = "server_cert";
    public static final String KEY_SERVER_CERT_PASSWORD = "server_cert_password";
    public static final String KEY_SYNC_PATH = "sync_path";
    public static final String KEY_DIFF = "diff";
    public static final String KEY_DIFF_THRESHOLD = "diff_threshold";
    public static final String KEY_SYNC_INTERVAL = "sync_interval";
    public static final String KEY_LOG_FILE = "log_file";
    public static final String KEY_LOG_ERROR_FILE = "log_error_file";

    /**
     * The pattern for user names on the server.
     */
    private static final Pattern USER_NAME_PATTERN = Pattern
            .compile("[a-z]{1}[a-z0-9]{0,9}");

    /**
     * The pattern for password on the server.
     */
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(".{6,32}");

    private final String rootPath;
    private final String user;
    private final String password;
    private final String serverHost;
    private final long serverPort;
    private final String serverCert;
    private final String serverCertPassword;
    private final String syncPath;
    private final boolean diff;
    private final double diffThreshold;
    private final long syncInterval;
    private final String logFile;
    private final String logErrorFile;

    /**
     * Creates a new client configuration.
     * 
     * @param rootPath
     *            the path to the client root directory which contains the files
     *            to synchronize.
     * @param user
     *            the user name used for authenticating the client towards the
     *            server.
     * @param password
     *            the password used for authenticating the client towards the
     *            server.
     * @param serverHost
     *            the host name of the server.
     * @param serverPort
     *            the server port.
     * @param serverCert
     *            the path to the key store which contains the server
     *            certificate.
     * @param serverCertPassword
     *            the password for accessing the key store which contains the
     *            server certificate.
     * @param syncPath
     *            the path to the file copies and information necessary for
     *            syncing.
     * @param diff
     *            <code>true</code>, if diffs should be made. Otherwise,
     *            complete files are transmitted.
     * @param diffThreshold
     *            consider the fraction of the size of the diff and the original
     *            file size. If this fraction is greater or equal to the
     *            threshold, then the original files is transmitted completely.
     * @param syncInterval
     *            the time interval in seconds after which to synchronize all
     *            local directories periodically.
     * @param logFile
     *            the path to the log file.
     * @param logErrorFile
     *            the path to the error log file.
     */
    public ClientConfiguration(String rootPath, String user, String password,
            String serverHost, long serverPort, String serverCert,
            String serverCertPassword, String syncPath, boolean diff,
            double diffThreshold, long syncInterval, String logFile,
            String logErrorFile) {
        if ((rootPath == null) || !Files.isDirectory(Paths.get(rootPath))) {
            throw new IllegalArgumentException("rootPath must be valid!");
        }
        if (!isValidUserName(user)) {
            throw new IllegalArgumentException("user must be valid!");
        }
        if (!isValidPassword(password)) {
            throw new IllegalArgumentException("password must be valid!");
        }
        if ((serverHost == null) || serverHost.isEmpty()) {
            throw new IllegalArgumentException("serverHost must be valid!");
        }
        if ((serverPort < 1) || (serverPort > 65535)) {
            throw new IllegalArgumentException("serverPort must be valid!");
        }
        if ((serverCert == null) || !Files.exists(Paths.get(serverCert))) {
            throw new IllegalArgumentException("serverCert must be valid!");
        }
        if ((serverCertPassword == null) || serverCertPassword.isEmpty()) {
            throw new IllegalArgumentException(
                    "serverCertPassword must be valid!");
        }
        if (syncPath == null) {
            throw new IllegalArgumentException("syncPath must be valid!");
        }
        if ((diffThreshold < 0.0)) {
            throw new IllegalArgumentException(
                    "diffThreshold must be at least zero!");
        }
        if (syncInterval < 0) {
            throw new IllegalArgumentException(
                    "syncInterval must be at least zero!");
        }
        if (logFile == null) {
            throw new IllegalArgumentException("logFile may not be null!");
        }
        if (logErrorFile == null) {
            throw new IllegalArgumentException("logErrorFile may not be null!");
        }

        this.rootPath = rootPath;
        this.user = user;
        this.password = password;
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.serverCert = serverCert;
        this.serverCertPassword = serverCertPassword;
        this.syncPath = syncPath;
        this.diff = diff;
        this.diffThreshold = diffThreshold;
        this.syncInterval = syncInterval;
        this.logFile = logFile;
        this.logErrorFile = logErrorFile;

        if (!Files.isDirectory(Paths.get(syncPath))) {
            FileHandler.makeParentDirs(Paths.get(syncPath, "arbitrary"));
        }
    }

    /**
     * Returns the root path which contains the files to synchronize.
     * 
     * @return the root path with the files to synchronize.
     */
    public String getRootPath() {
        return rootPath;
    }

    /**
     * Returns the user name used to authenticate towards the server.
     * 
     * @return the user name used to authenticate towards the server.
     */
    public String getUser() {
        return user;
    }

    public static boolean isValidUserName(String user) {
        // white list check
        return (user != null) && USER_NAME_PATTERN.matcher(user).matches();
    }

    public static boolean isValidPassword(String password) {
        // white list check
        return (password != null)
                && PASSWORD_PATTERN.matcher(password).matches();
    }

    /**
     * Returns the password to authenticate towards the server.
     * 
     * @return the password to authenticate towards the server.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Returns the server's host name.
     * 
     * @return the server's host name.
     */
    public String getServerHost() {
        return serverHost;
    }

    /**
     * Returns the server's port.
     * 
     * @return the server's port.
     */
    public long getServerPort() {
        return serverPort;
    }

    /**
     * Returns the path to the key store which contains the server certificate.
     * 
     * @return the path to the key store which contains the server certificate.
     */
    public String getServerCert() {
        return serverCert;
    }

    /**
     * Returns the password used to access the key store with the server
     * certificate.
     * 
     * @return the password used to access the key store with the server
     *         certificate.
     */
    public String getServerCertPassword() {
        return serverCertPassword;
    }

    /**
     * Returns the synchronization path holding file copies and information
     * required for synchronization.
     * 
     * @return the synchronization path.
     */
    public String getSyncPath() {
        return syncPath;
    }

    /**
     * Returns whether diffs are used or files are transmitted completely each
     * time.
     * 
     * @return <code>true</code> if diffs are used. <code>false</code>,
     *         otherwise.
     */
    public boolean isDiff() {
        return diff;
    }

    /**
     * Returns the threshold which determines when complete files are
     * transmitted instead of diffs.
     * 
     * @return the threshold which determines when complete files are
     *         transmitted instead of diffs.
     */
    public double getDiffThreshold() {
        return diffThreshold;
    }

    /**
     * Returns the time interval in seconds after which to synchronize all local
     * directories periodically.
     * 
     * @return the time interval in seconds after which to synchronize all local
     *         directories periodically.
     */
    public long getSyncInterval() {
        return syncInterval;
    }

    /**
     * Returns the path to the log file.
     * 
     * @return the path to the log file.
     */
    public String getLogFile() {
        return logFile;
    }

    /**
     * Returns the path to the error log file.
     * 
     * @return the path to the error log file.
     */
    public String getLogErrorFile() {
        return logErrorFile;
    }

    /**
     * Returns a map representation of this object.
     * 
     * @return a map representation of this object.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> thisMap = new LinkedHashMap<>();
        thisMap.put(KEY_ROOT_PATH, rootPath);
        thisMap.put(KEY_USER, user);
        thisMap.put(KEY_PASSWORD, password);
        thisMap.put(KEY_SERVER_HOST, serverHost);
        thisMap.put(KEY_SERVER_PORT, new Long(serverPort));
        thisMap.put(KEY_SERVER_CERT, serverCert);
        thisMap.put(KEY_SERVER_CERT_PASSWORD, serverCertPassword);
        thisMap.put(KEY_SYNC_PATH, syncPath);
        thisMap.put(KEY_DIFF, new Boolean(diff));
        thisMap.put(KEY_DIFF_THRESHOLD, new Double(diffThreshold));
        thisMap.put(KEY_SYNC_INTERVAL, new Long(syncInterval));
        thisMap.put(KEY_LOG_FILE, logFile);
        thisMap.put(KEY_LOG_ERROR_FILE, logErrorFile);

        return thisMap;
    }

    /**
     * Parses the given configuration file.
     * 
     * @param file
     *            the path to the configuration file.
     * @return the parsed configuration.
     * @throws FileNotFoundException
     * @throws IOException
     * @throws ParseException
     */
    public static ClientConfiguration parse(Path file)
            throws FileNotFoundException, IOException, ParseException {
        if (file == null) {
            throw new NullPointerException("file may not be null!");
        }

        return Parser.parse(file);
    }

    /**
     * Stores this configuration under the given path.
     * 
     * @param file
     *            the path where this configuration is to be stored.
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
            JSONValue.writeJSONString(toMap(), writer);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return writer.toString();
    }

    /**
     * Parses and stores client configuration files.
     * 
     * @author Fabian Foerg
     */
    private static class Parser {
        public static ClientConfiguration parse(Path file)
                throws FileNotFoundException, IOException, ParseException {
            if ((file == null) || !Files.isReadable(file)) {
                throw new NullPointerException("file must be readable!");
            }

            BufferedReader in = Files.newBufferedReader(file, Coder.CHARSET);
            StringBuilder sb = new StringBuilder();
            String read = null;
            JSONObject object;
            String rootPath;
            String user;
            String password;
            String serverHost;
            long serverPort;
            String serverCert;
            String serverCertPassword;
            String syncPath;
            boolean diff;
            double diffThreshold;
            long syncInterval;
            String logFile;
            String logErrorFile;

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
            rootPath = (String) object.get(KEY_ROOT_PATH);
            user = (String) object.get(KEY_USER);
            password = (String) object.get(KEY_PASSWORD);
            serverHost = (String) object.get(KEY_SERVER_HOST);
            serverPort = (Long) object.get(KEY_SERVER_PORT);
            serverCert = (String) object.get(KEY_SERVER_CERT);
            serverCertPassword = (String) object.get(KEY_SERVER_CERT_PASSWORD);
            syncPath = (String) object.get(KEY_SYNC_PATH);
            diff = (Boolean) object.get(KEY_DIFF);
            diffThreshold = (Double) object.get(KEY_DIFF_THRESHOLD);
            syncInterval = (Long) object.get(KEY_SYNC_INTERVAL);
            logFile = (String) object.get(KEY_LOG_FILE);
            logErrorFile = (String) object.get(KEY_LOG_ERROR_FILE);

            return new ClientConfiguration(rootPath, user, password,
                    serverHost, serverPort, serverCert, serverCertPassword,
                    syncPath, diff, diffThreshold, syncInterval, logFile,
                    logErrorFile);
        }

        /**
         * Stores this configuration under the given path.
         * 
         * @param config
         *            the configuration to store.
         * @param file
         *            the path where this configuration is to be stored.
         * @throws IOException
         */
        public static void store(ClientConfiguration config, Path file)
                throws IOException {
            if ((file == null) || !Files.isWritable(file)) {
                throw new NullPointerException("file must be writable!");
            }

            BufferedWriter out = Files.newBufferedWriter(file, Coder.CHARSET);

            if (out != null) {
                out.write(config.toString());
                out.close();
            }
        }
    }
}
