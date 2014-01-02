package server;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import misc.Logger;
import misc.network.SecureFinalSocket;
import misc.network.SecureSocket;

import org.json.simple.parser.ParseException;

import protocol.DataContainers.Pair;
import server.database.DatabaseConnection;
import configuration.ServerConfiguration;

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
 * This class manages the server along with its client connections. The server
 * listens on an SSL socket. For each connected client a thread is created. A
 * key store with an RSA key pair has to be present. A certificate should be
 * exported and be handed to the clients in order to enable them to check the
 * identity of the server. An RSA key-pair and a certificate on the command-line
 * with: keytool -genkeypair -keystore SSLKeyStore -alias SSLCertificateWithRSA
 * -keyalg RSA Export the certificate with: keytool -exportcert -alias
 * SSLCertificateWithRSA -file .cert -keystore SSLKeyStore
 * 
 * @author Fabian Foerg
 */
public final class Server {
    private static final String DEFAULT_CONFIG_PATH = ".conf";
    private static final int BACKLOG = 20;

    private final ServerConfiguration config;
    private final Path clientDirectory;
    private final int connectionTimeout;
    private final SSLServerSocket serverSocket;
    private final Thread serverThread;
    private final ExecutorService pool;
    private boolean serverStopped;

    /**
     * Initializes the server with the given configuration.
     * 
     * @param serverConfigurationPath
     *            the path to the server configuration file.
     * @throws FileNotFoundException
     * @throws IOException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws KeyStoreException
     * @throws KeyManagementException
     * @throws UnrecoverableKeyException
     */
    public Server(String serverConfigurationPath) throws FileNotFoundException,
            IOException, ParseException, ClassNotFoundException, SQLException,
            NoSuchAlgorithmException, CertificateException, KeyStoreException,
            KeyManagementException, UnrecoverableKeyException {
        SSLServerSocketFactory sslFact;
        KeyStore keystore = KeyStore.getInstance("JKS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        SSLContext context = SSLContext.getInstance("TLS");
        FileInputStream keystoreFile;
        int backLog;

        if (serverConfigurationPath == null) {
            serverConfigurationPath = DEFAULT_CONFIG_PATH;
        }

        /*
         * Code adapted from
         * http://download.oracle.com/javase/7/docs/technotes/guides
         * /security/jsse/JSSERefGuide.html#SSLSocketFactory
         */
        config = ServerConfiguration.parse(Paths.get(serverConfigurationPath));

        // initialize the logger
        Logger.setLogs(Paths.get(config.getLogFile()),
                Paths.get(config.getLogErrorFile()));

        clientDirectory = Paths.get(config.getRootPath());
        connectionTimeout = (int) config.getConnectionTimeout();

        // initialize the database connection, before any socket is created
        DatabaseConnection.init(config.getDatabasePath());

        keystoreFile = new FileInputStream(config.getKeyStorePath());
        keystore.load(keystoreFile, config.getKeyStorePassword().toCharArray());
        keystoreFile.close();
        kmf.init(keystore, config.getKeyStorePassword().toCharArray());
        tmf.init(keystore);
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        sslFact = context.getServerSocketFactory();
        backLog = Math.min(BACKLOG, (int) config.getMaxConnections());
        serverSocket = (SSLServerSocket) sslFact.createServerSocket(
                (int) config.getPort(), backLog,
                InetAddress.getByName(config.getHost()));
        serverSocket.setNeedClientAuth(false);
        serverSocket.setWantClientAuth(false);

        pool = Executors.newFixedThreadPool((int) config.getMaxConnections());
        serverStopped = false;
        serverThread = new Thread(new ServerThread());
    }

    /**
     * Closes open sockets and the shared database connection when the garbage
     * collector prunes the object.
     */
    @Override
    protected void finalize() throws Throwable {
        stop();
        DatabaseConnection.close();
        super.finalize();
    }

    /**
     * Starts this server thread.
     */
    public void start() {
        if (serverThread != null) {
            serverThread.start();
        }
    }

    /**
     * Waits for the server thread to die.
     */
    public void join() {
        try {
            serverThread.join();
        } catch (InterruptedException e) {
            Logger.logError(e);
        }
    }

    /**
     * Stops this server thread. This means that no new connections are
     * established. Already existing client connections are not aborted.
     */
    public void stop() {
        if (!serverStopped) {
            if (pool != null) {
                synchronized (pool) {
                    pool.shutdown();
                }
            }

            try {
                if (serverSocket != null) {
                    serverSocket.close();
                }
            } catch (IOException e) {
                // empty
            } finally {
                Logger.log("No more clients will be accepted!");
                serverStopped = true;
            }
        }
    }

    /**
     * Represents the single server thread which waits for connections and
     * starts another thread for managing client connections.
     * 
     * @author Fabian Foerg
     */
    private class ServerThread implements Runnable {
        // needs to be synchronized, as multiple connection threads access it.
        private final Set<LockPair> locks;
        private final Map<InetAddress, Integer> connections;
        private final Set<InetAddress> blocked;

        /**
         * Creates a new server thread.
         */
        public ServerThread() {
            locks = new HashSet<LockPair>();
            connections = new HashMap<InetAddress, Integer>();
            blocked = new HashSet<InetAddress>();
        }

        /**
         * Returns the given lock, if lock was acquired or <code>null</code>, if
         * the lock could not be acquired, as the lock is already present.
         * 
         * @param lock
         *            the (owner, path) pair to lock.
         * @return the given lock, if lock was acquired or <code>null</code>, if
         *         the lock could not be acquired.
         */
        public LockPair acquireLock(LockPair lock) {
            if (lock == null) {
                throw new NullPointerException("lock may not be null!");
            }

            boolean added;
            synchronized (locks) {
                added = locks.add(lock);
            }

            if (added) {
                Logger.log(String.format("Acquired lock (%s, %s)",
                        lock.getOwner(), lock.getPath().toString()));
            } else {
                Logger.logError(String.format("Acquiring lock (%s, %s) FAILED",
                        lock.getOwner(), lock.getPath().toString()));
            }

            return added ? lock : null;
        }

        /**
         * Returns <code>true</code>, if lock was released or <code>false</code>
         * , if the lock was not present.
         * 
         * @param lock
         *            the (owner, path) pair lock to release.
         * @return <code>true</code>, if lock was released or <code>false</code>
         *         , if the lock was not present.
         */
        public boolean releaseLock(LockPair lock) {
            if (lock == null) {
                throw new NullPointerException("lock may not be null!");
            }

            boolean removed;
            synchronized (locks) {
                removed = locks.remove(lock);
            }

            if (removed) {
                Logger.log(String.format("Released lock (%s, %s)",
                        lock.getOwner(), lock.getPath().toString()));
            } else {
                Logger.log(String.format("Lock (%s, %s) not present",
                        lock.getOwner(), lock.getPath().toString()));
            }

            return removed;
        }

        /**
         * Is called to notify the server when a connection is closed.
         * 
         * @param connection
         *            the address of the remote end which connection was closed.
         */
        public void closedConnection(InetAddress connection) {
            if (connection == null) {
                throw new NullPointerException("toBlack may not be null!");
            }

            synchronized (connections) {
                Integer openConnections = connections.get(connection);

                if (openConnections != null) {
                    openConnections--;

                    if (openConnections > 0) {
                        connections.put(connection, openConnections);
                    } else {
                        connections.remove(connection);
                    }
                }
            }
        }

        /**
         * Blocks the given address for the configured amount of time.
         * 
         * @param toBlock
         *            the address to block.
         */
        public void block(InetAddress toBlock) {
            if (toBlock == null) {
                throw new NullPointerException("toBlack may not be null!");
            }

            boolean added;
            synchronized (blocked) {
                added = blocked.add(toBlock);
            }

            if (added) {
                Logger.log(String.format("Blocking client %s",
                        toBlock.toString()));
                // wait for the block timeout and then remove the entry
                Timer timer = new Timer();
                timer.schedule(new BlockTimer(blocked, toBlock),
                        config.getBlockTimeout());
            }
        }

        /**
         * Main method of the server thread. Should not be called directly, as
         * the operating system does not create a new thread in that case. Call
         * {@link #start()} instead.
         */
        @Override
        public void run() {
            try {
                while (!serverStopped) {
                    SSLSocket socket = (SSLSocket) serverSocket.accept();
                    InetAddress clientAddress = socket.getInetAddress();
                    Integer openConnections;
                    boolean blocked;

                    synchronized (this.blocked) {
                        blocked = this.blocked.contains(clientAddress);
                    }
                    synchronized (connections) {
                        openConnections = connections.get(clientAddress);
                    }

                    if (!blocked
                            && ((openConnections == null) || (openConnections < config
                                    .getMaxConnectionsPerAddress()))) {
                        synchronized (connections) {
                            openConnections = connections.get(clientAddress);
                            openConnections = (openConnections != null) ? (openConnections + 1)
                                    : 1;

                            connections.put(clientAddress, openConnections);
                        }
                        socket.setSoTimeout(connectionTimeout);
                        ConnectionThread connectionThread = new ConnectionThread(
                                this, new SecureFinalSocket(socket),
                                clientAddress, clientDirectory,
                                config.getMaxFailedRequests());
                        synchronized (pool) {
                            if (!pool.isShutdown()) {
                                pool.execute(connectionThread);
                            }
                        }
                    } else {
                        if (blocked) {
                            Logger.log(String.format("Client %s is blocked.",
                                    clientAddress.toString()));
                        } else {
                            Logger.log(String
                                    .format("Client %s has reached the maximum number of connections per address (%d).",
                                            clientAddress.toString(),
                                            config.getMaxConnectionsPerAddress()));
                        }
                    }
                }
            } catch (IOException e) {
                Logger.log("Server stopped running. Running tasks are still executed.");
            } finally {
                stop();
            }
        }
    }

    /**
     * Removes a given address from the given set when executed.
     * 
     * @author Fabian Foerg
     */
    private static final class BlockTimer extends TimerTask {
        Set<InetAddress> blocked;
        InetAddress toBlock;

        public BlockTimer(Set<InetAddress> blocked, InetAddress toBlock) {
            super();

            if (blocked == null) {
                throw new NullPointerException("blocked may not be null!");
            }
            if (toBlock == null) {
                throw new NullPointerException("toBlack may not be null!");
            }

            this.blocked = blocked;
            this.toBlock = toBlock;
        }

        @Override
        public void run() {
            boolean removed;

            synchronized (blocked) {
                removed = blocked.remove(toBlock);
            }

            if (removed) {
                Logger.log(String.format("Unblocked client %s",
                        toBlock.toString()));
            }
        }
    }

    /**
     * A ConnectionThread is started each time a client connects. Client
     * communication is handled only in this thread. Only one lock per
     * connection is allowed.
     * 
     * @author Fabian Foerg
     */
    public static final class ConnectionThread implements Runnable {
        private final ServerThread serverThread;
        private final SecureSocket secureSocket;
        private final InetAddress clientAddress;
        private final Path clientDirectory;
        private final long maxFailedRequests;
        private boolean connectionStopped;
        private LockPair lock;

        /**
         * Creates a new connection thread.
         * 
         * @param serverThread
         *            the server thread managing the locks.
         * @param socket
         *            the socket of the server.
         * @param clientAddress
         *            the address of the connected client.
         * @param clientDirectory
         *            the client's root path.
         * @param maxFailedRequests
         *            the maximum number of failed requests.
         */
        public ConnectionThread(ServerThread serverThread, SecureSocket socket,
                InetAddress clientAddress, Path clientDirectory,
                long maxFailedRequests) {
            if (serverThread == null) {
                throw new NullPointerException("serverThread may not be null!");
            }
            if (socket == null) {
                throw new NullPointerException("socket may not be null!");
            }
            if (clientAddress == null) {
                throw new NullPointerException("clientAddress may not be null!");
            }
            if (clientDirectory == null) {
                throw new NullPointerException(
                        "clientDirectory may not be null!");
            }
            if (maxFailedRequests < 0) {
                throw new IllegalArgumentException(
                        "maxFailedRequests must be at least zero!");
            }

            this.serverThread = serverThread;
            this.secureSocket = socket;
            this.clientAddress = clientAddress;
            this.clientDirectory = clientDirectory.normalize();
            this.maxFailedRequests = maxFailedRequests;
            connectionStopped = false;
            lock = null;
        }

        /**
         * Main method of this client thread. Should not be called directly, as
         * the operating system does not create a new thread in this case. Call
         * {@link #start()} instead.
         */
        @Override
        public void run() {
            SSLSocket socket = secureSocket.getSocket();
            SSLSession session = socket.getSession();
            Logger.log(String.format("Server initiated session %s with %s",
                    session.getCipherSuite().toString(), socket
                            .getRemoteSocketAddress().toString()));

            try (ServerConnectionHandler handler = new ServerConnectionHandler(
                    secureSocket, this, clientDirectory, maxFailedRequests);) {
                /*
                 * Listen for requests until the server or the client close the
                 * connection or a timeout is reached.
                 */
                while (!connectionStopped) {
                    Logger.log(String.format("Connected %s", handler.toString()));
                    boolean done = handler.next();

                    if (done) {
                        finish();
                    }
                }
            } catch (IOException e) {
                Logger.logError(e);
            } finally {
                Logger.log(String.format("Closing connection to %s", socket
                        .getRemoteSocketAddress().toString()));
                closeConnections();
            }
        }

        /**
         * Returns the given lock, if lock was acquired or <code>null</code>, if
         * the lock could not be acquired, as the lock is already present.
         * 
         * @param lock
         *            the (owner, path) pair to lock.
         * @return the given lock, if lock was acquired or <code>null</code>, if
         *         the lock could not be acquired.
         */
        public LockPair acquireLock(LockPair lock) {
            if (lock == null) {
                throw new NullPointerException("lock may not be null!");
            }

            if (this.lock == null) {
                this.lock = serverThread.acquireLock(lock);
                return this.lock;
            } else {
                return null;
            }
        }

        /**
         * Returns whether this connection holds any lock.
         * 
         * @return <code>true</code>, if a lock is held by this connection.
         *         Otherwise, <code>false</code>.
         */
        public boolean holdsLock() {
            return (lock != null);
        }

        /**
         * Returns whether this connection holds the given lock.
         * 
         * @param lock
         *            the (owner, path) lock pair to check.
         * @return <code>true</code>, if the lock is held by this connection.
         *         Otherwise, <code>false</code>.
         */
        public boolean holdsLock(LockPair lock) {
            if (lock == null) {
                throw new NullPointerException("lock may not be null!");
            }

            return (lock.equals(this.lock));
        }

        /**
         * Returns <code>true</code>, if the lock was released or
         * <code>false</code> , if no lock was present.
         * 
         * @return <code>true</code>, if lock was released or <code>false</code>
         *         , if no lock was present.
         */
        public boolean releaseLock() {
            boolean released = false;

            if (lock != null) {
                serverThread.releaseLock(lock);
                this.lock = null;
                released = true;
            }

            return released;
        }

        /**
         * Blocks the connected client for the configured amount of time and
         * closes the connection.
         */
        public void block() {
            SSLSocket socket = secureSocket.getSocket();
            if (socket != null) {
                serverThread.block(socket.getInetAddress());
            }
            closeConnections();
        }

        /**
         * Stops this client thread, after ongoing actions are completed.
         */
        public void finish() {
            connectionStopped = true;
        }

        /**
         * Closes all open streams and connections and release any present
         * locks.
         */
        private void closeConnections() {
            try {
                secureSocket.close();
            } catch (Exception e) {
                Logger.logError(e);
            } finally {
                releaseLock();
                serverThread.closedConnection(clientAddress);
            }
        }

        /**
         * Closes the client connection and releases any present locks when the
         * garbage collector prunes this object.
         */
        @Override
        protected void finalize() throws Throwable {
            finish();
            super.finalize();
        }
    }

    /**
     * Represents an (owner, path) lock pair.
     * 
     * @author Fabian Foerg
     */
    public static final class LockPair extends Pair<String, Path> {
        public LockPair(String owner, Path path) {
            super(owner, path);

            if (owner == null) {
                throw new NullPointerException("owner may not be null!");
            }
            if (path == null) {
                throw new NullPointerException("path may not be null!");
            }
        }

        public String getOwner() {
            return getFirst();
        }

        public Path getPath() {
            return getSecond();
        }

        @Override
        public String toString() {
            return String.format("(owner, path) = (%s, %s)", getOwner(),
                    getPath().toString());
        }
    }
}
