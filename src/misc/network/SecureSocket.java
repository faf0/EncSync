package misc.network;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;

import javax.net.ssl.SSLSocket;

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
 * Interface for secure sockets.
 * 
 * @author Fabian Foerg
 */
public interface SecureSocket extends AutoCloseable {
    /**
     * Returns an input stream.
     * 
     * @return an input stream or <code>null</code>, if no input stream exists.
     */
    public BufferedInputStream getInputStream();

    /**
     * Returns an output stream.
     * 
     * @return an output stream or <code>null</code>, if no output stream
     *         exists.
     */
    public BufferedOutputStream getOutputStream();

    /**
     * Returns a socket.
     * 
     * @return a socket or <code>null</code>, if no socket exists.
     */
    public SSLSocket getSocket();

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException;
}
