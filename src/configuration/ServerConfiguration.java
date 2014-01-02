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
 * Allows to parse and store server configuration files.
 * 
 * @author Fabian Foerg
 */
public final class ServerConfiguration {
    public static final String KEY_HOST = "host";
    public static final String KEY_PORT = "port";
    public static final String KEY_ROOT_PATH = "root_path";
    public static final String KEY_DATABASE_PATH = "database_path";
    public static final String KEY_KEYSTORE_PATH = "keystore_path";
    public static final String KEY_KEYSTORE_PASSWORD = "keystore_password";
    public static final String KEY_MAX_CONNECTIONS = "max_connections";
    public static final String KEY_MAX_CONNECTIONS_PER_ADDRESS = "max_connections_per_address";
    public static final String KEY_CONNECTION_TIMEOUT = "connection_timeout";
    public static final String KEY_MAX_FAILED_REQUESTS = "max_failed_requests";
    public static final String KEY_BLOCK_TIMEOUT = "block_timeout";
    public static final String KEY_LOG_FILE = "log_file";
    public static final String KEY_LOG_ERROR_FILE = "log_error_file";

    private final String host;
    private final long port;
    private final String rootPath;
    private final String databasePath;
    private final String keyStorePath;
    private final String keyStorePassword;
    private final long maxConnections;
    private final long maxConnectionsPerAddress;
    private final long connectionTimeout;
    private final long maxFailedRequests;
    private final long blockTimeout;
    private final String logFile;
    private final String logErrorFile;

    /**
     * Creates a new server configuration with the given parameters.
     * 
     * @param host
     *            the host name of the server.
     * @param port
     *            the port of the server.
     * @param rootPath
     *            the root directory where the server and client files are
     *            stored.
     * @param databasePath
     *            the path to the database.
     * @param keyStorePath
     *            the path to the key store.
     * @param keyStorePassword
     *            the password for the key store.
     * @param maxConnections
     *            the number of maximum allowed connections.
     * @param maxConnectionsPerAddress
     *            the maximum number of connections per address.
     * @param connectionTimeout
     *            the timeout for client connections.
     * @param maxFailedRequests
     *            the maximum number of failed requests.
     * @param blockTimeout
     *            the time to block clients which unsuccessfully reached the
     *            maximum number of allowed login attempts.
     * @param logFile
     *            the path to the log file.
     * @param logErrorFile
     *            the path to the error log file.
     */
    public ServerConfiguration(String host, long port, String rootPath,
            String databasePath, String keyStorePath, String keyStorePassword,
            long maxConnections, long maxConnectionsPerAddress,
            long connectionTimeout, long maxFailedRequests, long blockTimeout,
            String logFile, String logErrorFile) {
        if ((host == null) || host.isEmpty()) {
            throw new IllegalArgumentException("host must be valid!");
        }
        if ((port < 1) || (port > 65535)) {
            throw new IllegalArgumentException("port must be valid!");
        }
        if ((rootPath == null) || !Files.isDirectory(Paths.get(rootPath))) {
            throw new IllegalArgumentException("rootPath must be valid!");
        }
        if (databasePath == null) {
            throw new IllegalArgumentException("databasePath must be valid!");
        }
        if ((keyStorePath == null) || !Files.exists(Paths.get(keyStorePath))) {
            throw new IllegalArgumentException("keyStorePath must be valid!");
        }
        if ((keyStorePassword == null) || keyStorePassword.isEmpty()) {
            throw new IllegalArgumentException(
                    "keyStorePassword must be valid!");
        }
        if (maxConnections < 1) {
            throw new IllegalArgumentException("maxConnections must be valid!");
        }
        if (maxConnectionsPerAddress < 1) {
            throw new IllegalArgumentException(
                    "maxConnectionsPerAddress must be valid!");
        }
        if (connectionTimeout < 0) {
            throw new IllegalArgumentException(
                    "connectionTimeout must be valid!");
        }
        if (maxFailedRequests < 0) {
            throw new IllegalArgumentException(
                    "maxFailedAttempts must be valid!");
        }
        if (blockTimeout < 0) {
            throw new IllegalArgumentException("blockTimeout must be valid!");
        }
        if (logFile == null) {
            throw new IllegalArgumentException("logFile may not be null!");
        }
        if (logErrorFile == null) {
            throw new IllegalArgumentException("logErrorFile may not be null!");
        }

        this.host = host;
        this.port = port;
        this.rootPath = rootPath;
        this.databasePath = databasePath;
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.maxConnections = maxConnections;
        this.maxConnectionsPerAddress = maxConnectionsPerAddress;
        this.connectionTimeout = connectionTimeout;
        this.maxFailedRequests = maxFailedRequests;
        this.blockTimeout = blockTimeout;
        this.logFile = logFile;
        this.logErrorFile = logErrorFile;
    }

    /**
     * Returns the host name of the server.
     * 
     * @return the host name of the server.
     */
    public String getHost() {
        return host;
    }

    /**
     * Returns the port of the server.
     * 
     * @return the port of the server.
     */
    public long getPort() {
        return port;
    }

    /**
     * Returns the root directory of the server where the server and client
     * files are stored.
     * 
     * @return the root path of the server.
     */
    public String getRootPath() {
        return rootPath;
    }

    /**
     * Returns the location of the server database.
     * 
     * @return the location of the server database.
     */
    public String getDatabasePath() {
        return databasePath;
    }

    /**
     * Returns the location of the key store.
     * 
     * @return the location of the key store.
     */
    public String getKeyStorePath() {
        return keyStorePath;
    }

    /**
     * Returns the password for the key store.
     * 
     * @return the password for the key store.
     */
    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    /**
     * Returns the maximum number of allowed client connections.
     * 
     * @return the maximum number of allowed client connections.
     */
    public long getMaxConnections() {
        return maxConnections;
    }

    /**
     * Returns the maximum number of connections per address.
     * 
     * @return the maximum number of connections per address.
     */
    public long getMaxConnectionsPerAddress() {
        return maxConnectionsPerAddress;
    }

    /**
     * Returns the timeout for client connections in milliseconds.
     * 
     * @return the timeout for client connections in milliseconds.
     */
    public long getConnectionTimeout() {
        return connectionTimeout;
    }

    /**
     * Returns the maximum number of failed requests.
     * 
     * @return the maximum number of failed requests.
     */
    public long getMaxFailedRequests() {
        return maxFailedRequests;
    }

    /**
     * Returns the amount of time which clients are blocked after the maximum
     * number of allowed login attempts was reached.
     * 
     * @return the amount of time which clients are blocked after the maximum
     *         number of allowed login attempts was reached.
     */
    public long getBlockTimeout() {
        return blockTimeout;
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
        thisMap.put(KEY_HOST, host);
        thisMap.put(KEY_PORT, new Long(port));
        thisMap.put(KEY_ROOT_PATH, rootPath);
        thisMap.put(KEY_DATABASE_PATH, databasePath);
        thisMap.put(KEY_KEYSTORE_PATH, keyStorePath);
        thisMap.put(KEY_KEYSTORE_PASSWORD, keyStorePassword);
        thisMap.put(KEY_MAX_CONNECTIONS, new Long(maxConnections));
        thisMap.put(KEY_MAX_CONNECTIONS_PER_ADDRESS, new Long(
                maxConnectionsPerAddress));
        thisMap.put(KEY_CONNECTION_TIMEOUT, new Long(connectionTimeout));
        thisMap.put(KEY_MAX_FAILED_REQUESTS, new Long(maxFailedRequests));
        thisMap.put(KEY_BLOCK_TIMEOUT, new Long(blockTimeout));
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
    public static ServerConfiguration parse(Path file)
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
     * Parses and stores server configuration files.
     * 
     * @author Fabian Foerg
     */
    private static class Parser {
        public static ServerConfiguration parse(Path file)
                throws FileNotFoundException, IOException, ParseException {
            if ((file == null) || !Files.isReadable(file)) {
                throw new NullPointerException("file must be readable!");
            }

            BufferedReader in = Files.newBufferedReader(file, Coder.CHARSET);
            StringBuilder sb = new StringBuilder();
            String read = null;
            JSONObject object;
            String host;
            long port;
            String rootPath;
            String databasePath;
            String keystorePath;
            String keystorePassword;
            long maxConnections;
            long maxConnectionsPerAddress;
            long connectionTimeout;
            long maxFailedRequests;
            long blockTimeout;
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
            host = (String) object.get(KEY_HOST);
            port = (Long) object.get(KEY_PORT);
            rootPath = (String) object.get(KEY_ROOT_PATH);
            databasePath = (String) object.get(KEY_DATABASE_PATH);
            keystorePath = (String) object.get(KEY_KEYSTORE_PATH);
            keystorePassword = (String) object.get(KEY_KEYSTORE_PASSWORD);
            maxConnections = (Long) object.get(KEY_MAX_CONNECTIONS);
            maxConnectionsPerAddress = (Long) object
                    .get(KEY_MAX_CONNECTIONS_PER_ADDRESS);
            connectionTimeout = (Long) object.get(KEY_CONNECTION_TIMEOUT);
            maxFailedRequests = (Long) object.get(KEY_MAX_FAILED_REQUESTS);
            blockTimeout = (Long) object.get(KEY_BLOCK_TIMEOUT);
            logFile = (String) object.get(KEY_LOG_FILE);
            logErrorFile = (String) object.get(KEY_LOG_ERROR_FILE);

            return new ServerConfiguration(host, port, rootPath, databasePath,
                    keystorePath, keystorePassword, maxConnections,
                    maxConnectionsPerAddress, connectionTimeout,
                    maxFailedRequests, blockTimeout, logFile, logErrorFile);
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
        public static void store(ServerConfiguration config, Path file)
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
