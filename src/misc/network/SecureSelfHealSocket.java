package misc.network;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;

import javax.net.SocketFactory;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;

import misc.Logger;

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
 * This class defines an SSL/TLS socket which can automatically re-connect to
 * the original source, after it was closed. It is appropriate for client
 * connections.
 * 
 * @author Fabian Foerg
 */
public final class SecureSelfHealSocket implements SecureSocket {
    private final SocketFactory fact;
    private final String host;
    private final int port;
    private SSLSocket socket;
    private boolean handshakeCompleted;
    private BufferedInputStream in;
    private BufferedOutputStream out;

    /**
     * Creates and initializes a secure socket. The socket is then connected to
     * the given port on the given host.
     * 
     * @param fact
     *            the socket factory used to create the sockets.
     * @param host
     *            the host to connect to. May be <code>null</code> for the
     *            loopback address.
     * @param port
     *            the port on the host to connect to.
     * @throws IOException
     *             if the socket cannot be created.
     */
    public SecureSelfHealSocket(SocketFactory fact, String host, int port)
            throws IOException {
        if (fact == null) {
            throw new NullPointerException("fact may not be null!");
        }
        if ((port < 1) || (port > 65535)) {
            throw new IllegalArgumentException(
                    "port not within range 1 through 65535!");
        }

        this.fact = fact;
        this.host = host;
        this.port = port;
        socket = null;
        handshakeCompleted = false;
        in = null;
        out = null;
        if (!rebuild(false)) {
            throw new IOException("SecureSocket cannot be created!");
        }
    }

    /**
     * Returns whether this socket needs to be rebuilt.
     * 
     * @return <code>true</code>, if this socket needs to be rebuilt. Otherwise,
     *         <code>false</code>.
     */
    public boolean needsRebuild() {
        return ((socket == null) || socket.isClosed()
                || socket.isInputShutdown() || socket.isOutputShutdown());
    }

    /**
     * Tries to re-establish the connection, if it is closed.
     * 
     * @param force
     *            if <code>true</code>, the socket is closed and re-connected,
     *            independent of its state. Otherwise, the socket is only
     *            re-connected, if the socket is shutdown.
     * @return <code>true</code>, if this socket is not closed and usable.
     *         Otherwise, <code>false</code>.
     */
    public boolean rebuild(boolean force) {
        boolean success = true;

        if (force || needsRebuild()) {
            try {
                if (socket != null) {
                    socket.close();
                }

                // create new socket and initiate handshake
                socket = (SSLSocket) fact.createSocket(host, port);
                handshakeCompleted = false;
                socket.addHandshakeCompletedListener(new HandshakeListener());
                socket.startHandshake();
                synchronized (this) {
                    while (!handshakeCompleted) {
                        try {
                            wait();
                        } catch (InterruptedException e) {
                            Logger.logError(e);
                        }
                    }
                }
                in = new BufferedInputStream(socket.getInputStream());
                out = new BufferedOutputStream(socket.getOutputStream());
            } catch (IOException e) {
                Logger.logError(e);
                success = false;
            }
        }

        return success;
    }

    /**
     * Tries to re-establish a connection, if the connection is closed.
     * 
     * @return the socket or <code>null</code>, if a connection cannot be
     *         established.
     */
    public SSLSocket getSocket() {
        if (rebuild(false)) {
            return socket;
        } else {
            return null;
        }
    }

    /**
     * Returns the input stream, if it already exists and tries to obtain one,
     * if there is none.
     * 
     * @return the input stream, if one is present or can be obtained.
     *         Otherwise, <code>null</code>.
     */
    public BufferedInputStream getInputStream() {
        if (rebuild(false)) {
            return in;
        } else {
            return null;
        }
    }

    /**
     * Returns the output stream, if it already exists and tries to obtain one,
     * if there is none.
     * 
     * @return the output stream, if one is present or can be obtained.
     *         Otherwise, <code>null</code>.
     */
    public BufferedOutputStream getOutputStream() {
        if (rebuild(false)) {
            return out;
        } else {
            return null;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException {
        if (socket != null) {
            socket.close();
        }
    }

    /**
     * Closes all connections when the garbage collector purges this object.
     */
    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        if (socket != null) {
            socket.close();
        }
    }

    /**
     * Hides the handshaking process for the outer class.
     * 
     * @author Fabian Foerg
     */
    private final class HandshakeListener implements HandshakeCompletedListener {
        /**
         * Hidden constructor.
         */
        private HandshakeListener() {
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void handshakeCompleted(HandshakeCompletedEvent event) {
            synchronized (SecureSelfHealSocket.this) {
                handshakeCompleted = true;
                SecureSelfHealSocket.this.notify();
            }
        }
    }
}
