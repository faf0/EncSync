package misc.network;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.net.ssl.SSLSocket;

import misc.Coder;
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
 * Handles peer socket connections and streams. Can be initialized with a
 * <code>SecureSocket</code> in which case socket connections are
 * re-established, if necessary. This type is appropriate for clients. As an
 * alternative a connection handler can be created from an
 * <code>SSLSocket</code> in which case connections are not re-established. This
 * type is appropriate for client connections on the server.
 * 
 * @author Fabian Foerg
 */
public class ConnectionHandler implements AutoCloseable {
    private final byte[] buffer;
    private final byte[] delimiter;
    private final SecureSocket secureSocket;

    /**
     * Creates a new connection handler.
     * 
     * @param bufferSize
     *            the size of the underlying byte buffer in bytes.
     * @param secureSocket
     *            the associated socket.
     * @param delimiter
     *            the message delimiter for incoming messages.
     */
    public ConnectionHandler(int bufferSize, SecureSocket secureSocket,
            byte[] delimiter) {
        if (bufferSize < 1) {
            throw new IllegalArgumentException(
                    "bufferSize has to be at least one!");
        }
        if (secureSocket == null) {
            throw new NullPointerException("socket must not be null!");
        }
        if (delimiter == null) {
            throw new NullPointerException("delimiter may not be null!");
        }

        buffer = new byte[bufferSize];
        this.delimiter = delimiter;
        this.secureSocket = secureSocket;
    }

    /**
     * Reads the next message from the input stream until a delimiter is found,
     * the buffer is full or the stream is closed.
     * 
     * @return the length of the message or <code>-1</code>, if the stream is
     *         closed or an error occurs.
     */
    public int readNextMessage() {
        BufferedInputStream in = getInputStream();
        int length = -1;
        int offset = 0;
        int read;

        if (in == null) {
            return -1;
        }

        try {
            while ((read = in.read(buffer, offset, buffer.length - offset)) != -1) {
                int delimiterIndex = Coder.matches(buffer, delimiter,
                        Math.max(0, offset - (delimiter.length - 1)), offset
                                + read);
                offset += read;

                if (delimiterIndex != -1) {
                    length = delimiterIndex;
                    break;
                } else if (offset == buffer.length) {
                    length = buffer.length;
                    break;
                }
            }
        } catch (IOException e) {
            Logger.logError(e);
        }

        return length;
    }

    /**
     * Sends the given message.
     * 
     * @param message
     *            the message to send.
     * @throws IOException
     */
    public void send(byte[] message) throws IOException {
        BufferedOutputStream out = getOutputStream();

        if (out != null) {
            out.flush();
            out.write(message);
            out.flush();
        }
    }

    /**
     * Transmits the given file over the associated output stream.
     * 
     * @param source
     *            the file to transmit.
     * @return the number of bytes read or written.
     * @throws IOException
     */
    public long transmitFile(Path source) throws IOException {
        long bytesWritten = 0;
        BufferedOutputStream out = getOutputStream();

        if (out != null) {
            out.flush();
            bytesWritten = Files.copy(source, out);
            out.flush();
        }

        return bytesWritten;
    }

    /**
     * Returns the associated buffer.
     * 
     * @return the associated buffer.
     */
    public byte[] getBuffer() {
        return buffer;
    }

    /**
     * Returns the associated input stream.
     * 
     * @return the associated input stream.
     */
    public BufferedInputStream getInputStream() {
        return secureSocket.getInputStream();
    }

    /**
     * Returns the associated output stream.
     * 
     * @return the associated output stream.
     */
    public BufferedOutputStream getOutputStream() {
        return secureSocket.getOutputStream();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        SSLSocket socket = secureSocket.getSocket();
        return (socket != null) ? String.format("local %s:%s remote %s", socket
                .getLocalAddress().toString(), String.valueOf(socket
                .getLocalPort()), socket.getRemoteSocketAddress().toString())
                : null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException {
        secureSocket.close();
    }
}
