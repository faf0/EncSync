package misc.network;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;

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
 * This class wraps an SSL/TLS socket. Handshaking is done here. This socket is
 * appropriate for client connections on a server.
 * 
 * @author Fabian Foerg
 */
public final class SecureFinalSocket implements SecureSocket {
    private final BufferedInputStream in;
    private final BufferedOutputStream out;
    private final SSLSocket socket;
    private boolean handshakeCompleted;

    /**
     * Creates a new SecureFinalSocket with the given SSLSocket.
     * 
     * @param socket
     *            the SSLSocket for this socket. Handshake is started on this
     *            socket.
     */
    public SecureFinalSocket(SSLSocket socket) {
        if (socket == null) {
            throw new NullPointerException("socket may not be null!");
        }

        BufferedInputStream localIn = null;
        BufferedOutputStream localOut = null;

        this.socket = socket;

        try {
            localIn = new BufferedInputStream(socket.getInputStream());
            localOut = new BufferedOutputStream(socket.getOutputStream());
            handshakeCompleted = false;
            this.socket.addHandshakeCompletedListener(new HandshakeListener());
            this.socket.startHandshake();
            synchronized (this) {
                while (!handshakeCompleted) {
                    try {
                        wait();
                    } catch (InterruptedException e) {
                        Logger.logError(e);
                    }
                }
            }
        } catch (IOException e) {
            Logger.logError(e);
        } finally {
            in = localIn;
            out = localOut;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public BufferedInputStream getInputStream() {
        return in;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public BufferedOutputStream getOutputStream() {
        return out;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SSLSocket getSocket() {
        return socket;
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
            synchronized (SecureFinalSocket.this) {
                handshakeCompleted = true;
                SecureFinalSocket.this.notify();
            }
        }
    }
}
