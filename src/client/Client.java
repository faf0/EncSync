package client;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import misc.Logger;
import misc.network.SecureSelfHealSocket;

import org.json.simple.parser.ParseException;

import client.executors.ClientExecutor;
import client.executors.ClientExecutor.ClientExecutorType;
import client.executors.ClientExecutorFactory;
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
 * This class takes care of the SSL connection to the server. Import the
 * server's certificate into the client's keystore with the command-line tool
 * keytool: keytool -importcert -alias servercert -file ../../server/.cert
 * -trustcacerts -keystore .servercert
 * 
 * @author Fabian Foerg
 */
public final class Client {
    private static final String DEFAULT_CONFIG_PATH = ".conf";

    private final ClientConfiguration config;
    private final SecureSelfHealSocket socket;
    private final ClientThread clientThread;

    /**
     * Creates a new client with the given parameters. Already initiates the
     * handshake and waits until the handshake has completed.
     * 
     * @param clientConfigurationPath
     *            the path to the configuration file.
     * @param executor
     *            the type of this client. May not be <code>null</code>.
     * @param data
     *            wrapped data that is stored in this client. May be
     *            <code>null</code>.
     * @throws FileNotFoundException
     * @throws IOException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws KeyManagementException
     */
    public Client(String clientConfigurationPath, ClientExecutorType type,
            Object data) throws FileNotFoundException, IOException,
            ParseException, NoSuchAlgorithmException, KeyStoreException,
            CertificateException, KeyManagementException {
        if (type == null) {
            throw new NullPointerException("type may not be null!");
        }

        SocketFactory sslFact;
        KeyStore keystore = KeyStore.getInstance("JKS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        SSLContext context = SSLContext.getInstance("TLS");
        FileInputStream keystoreFile;

        if (clientConfigurationPath == null) {
            clientConfigurationPath = DEFAULT_CONFIG_PATH;
        }

        config = ClientConfiguration.parse(Paths.get(clientConfigurationPath));

        // initialize the logger
        Logger.setLogs(Paths.get(config.getLogFile()),
                Paths.get(config.getLogErrorFile()));

        keystoreFile = new FileInputStream(config.getServerCert());
        keystore.load(keystoreFile, config.getServerCertPassword()
                .toCharArray());
        keystoreFile.close();
        tmf.init(keystore);
        context.init(null, tmf.getTrustManagers(), null);
        sslFact = context.getSocketFactory();
        socket = new SecureSelfHealSocket(sslFact, config.getServerHost(),
                (int) config.getServerPort());
        clientThread = new ClientThread(socket, config, type, data);
    }

    /**
     * Starts this client.
     */
    public void start() {
        clientThread.start();
    }

    /**
     * Executes the running tasks and stops.
     */
    public void stop() {
        clientThread.stopExecutor();
    }

    /**
     * Waits for the client thread to die.
     */
    public void join() {
        try {
            clientThread.join();
        } catch (InterruptedException e) {
            Logger.logError(e);
        }
    }

    /**
     * This class handles the connection to the server.
     * 
     * @author Fabian Foerg
     */
    private static class ClientThread extends Thread {
        private final SecureSelfHealSocket secureSocket;
        private final ClientConfiguration config;
        private final Object data;
        private final ClientExecutorType executorType;
        private ClientExecutor executor;

        public ClientThread(SecureSelfHealSocket secureSocket,
                ClientConfiguration config, ClientExecutorType type, Object data) {
            if (secureSocket == null) {
                throw new NullPointerException("secureSocket may not be null!");
            }
            if (config == null) {
                throw new NullPointerException("config may not be null!");
            }
            if (type == null) {
                throw new NullPointerException("type may not be null!");
            }

            this.secureSocket = secureSocket;
            this.config = config;
            executorType = type;
            executor = null;
            this.data = data;
        }

        /**
         * Main method of this client thread. Should not be called directly, as
         * the operating system does not create a new thread in this case. Call
         * {@link #start()} instead.
         */
        @Override
        public void run() {
            // initialize the session
            SSLSocket socket = secureSocket.getSocket();
            SSLSession session = socket.getSession();
            Logger.log(String.format(
                    "Client path %s, session %s, client port %s",
                    config.getRootPath(), session.getCipherSuite().toString(),
                    String.valueOf(socket.getLocalPort())));

            try (ClientConnectionHandler handler = new ClientConnectionHandler(
                    secureSocket, config);) {
                synchronized (this) {
                    executor = ClientExecutorFactory.getInstance(executorType,
                            handler, config, data);
                    notify();
                }

                /*
                 * First authenticate our client towards the server.
                 */
                boolean authenticated = handler.postAuth(config.getUser(),
                        config.getPassword());

                if (authenticated) {
                    boolean continueExecution;

                    do {
                        continueExecution = executor.execute();
                    } while (continueExecution);
                }
            } catch (IOException e) {
                Logger.logError(e);
            }
        }

        /**
         * Tells the executor to execute the running tasks and to stop
         * afterwards.
         */
        public void stopExecutor() {
            synchronized (this) {
                while (executor == null) {
                    try {
                        wait();
                    } catch (InterruptedException e) {
                        Logger.logError(e);
                    }
                }
            }

            executor.stop();
        }
    }
}
