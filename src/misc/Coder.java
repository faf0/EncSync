package misc;

import java.io.IOException;
import java.nio.charset.Charset;

import org.apache.commons.codec.binary.Base64;

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
 * Methods for coding and decoding Strings and byte arrays using URL and
 * filename safe Base 64. Other conversion methods for strings and bytes is
 * provided, as well as the default character set @see CHARSET.
 * 
 * @author Fabian Foerg
 */
public final class Coder {
    public static final Charset CHARSET = java.nio.charset.StandardCharsets.US_ASCII;

    private static final Charset CHARSET_8_BIT = java.nio.charset.StandardCharsets.ISO_8859_1;
    private static final Base64 CODER = new Base64(0,
            new byte[] { '\r', '\n' }, true);

    /**
     * Converts a byte array to a string using the default character set of this
     * class.
     * 
     * @param buffer
     *            the buffer to convert.
     * @return the string representation of the given buffer according to the
     *         default character set of this class.
     */
    public static String byteToString(byte[] buffer) {
        return (buffer != null) ? new String(buffer, CHARSET) : null;
    }

    /**
     * Converts a byte array to a string using the default character set of this
     * class.
     * 
     * @param buffer
     *            the buffer to convert.
     * @param offset
     *            <code>0</code>-based offset in buffer.
     * @param length
     *            the number of bytes to consider from buffer, starting at
     *            offset.
     * @return the string representation of the desired buffer part according to
     *         the default character set of this class.
     */
    public static String byteToString(byte[] buffer, int offset, int length) {
        return ((buffer != null) && (offset >= 0) && (length <= buffer.length)) ? new String(
                buffer, offset, length, CHARSET) : null;
    }

    /**
     * Converts a byte array to a string.
     * 
     * @param buffer
     *            the buffer to convert.
     * @return the string representation of the given buffer according to an
     *         8-bit character set.
     */
    public static String byteToStringRaw(byte[] buffer) {
        return (buffer != null) ? new String(buffer, CHARSET_8_BIT) : null;
    }

    /**
     * Converts a byte array to a string.
     * 
     * @param buffer
     *            the buffer to convert.
     * @param offset
     *            <code>0</code>-based offset in buffer.
     * @param length
     *            the number of bytes to consider from buffer, starting at
     *            offset.
     * @return the string representation of the desired buffer part according to
     *         an 8-bit character set.
     */
    public static String byteToStringRaw(byte[] buffer, int offset, int length) {
        return ((buffer != null) && (offset >= 0) && (length <= buffer.length)) ? new String(
                buffer, offset, length, CHARSET_8_BIT) : null;
    }

    /**
     * Copies the specified buffer into a new buffer.
     * 
     * @param buffer
     *            the buffer to copy.
     * @param offset
     *            <code>0</code>-based offset. The lowest index from the buffer
     *            to copy.
     * @param length
     *            the number of bytes to copy, starting with offset.
     * @return a new buffer which contains the specified elements of the given
     *         buffer.
     */
    public static byte[] copyBytes(byte[] buffer, int offset, int length) {
        if (!((offset >= 0) && (length >= 0) && ((offset + length) <= buffer.length))) {
            throw new IllegalArgumentException(
                    "offset or length are not within permitted range!");
        }

        byte[] copy = new byte[length];

        for (int i = 0; i < length; i++) {
            copy[i] = buffer[offset + i];
        }

        return copy;
    }

    /**
     * Decodes the given URL and filename safe Base 64 encoded string.
     * 
     * @param encoded
     *            a URL and filename safe Base 64 encoded string.
     * @return a decoded URL and filename safe Base 64 byte buffer.
     * @throws IOException
     */
    public static byte[] decodeBASE64(String encoded) throws IOException {
        if (encoded == null) {
            return null;
        }

        synchronized (CODER) {
            return CODER.decode(encoded);
        }
    }

    /**
     * Decodes the given URL and filename safe Base 64 encoded string.
     * 
     * @param encoded
     *            a URL and filename safe Base 64 encoded string.
     * @return a decoded URL and filename safe Base 64 string.
     * @throws IOException
     */
    public static String decodeBASE64asString(String encoded)
            throws IOException {
        if (encoded == null) {
            return null;
        }

        synchronized (CODER) {
            return Coder.byteToStringRaw(CODER.decode(encoded));
        }
    }

    /**
     * Encodes the given byte buffer using URL and filename safe Base 64.
     * 
     * @param unencoded
     *            the string to encode.
     * @return a URL and filename safe Base 64 encoded string.
     */
    public static String encodeBASE64(byte[] buffer) {
        if ((buffer == null) || (buffer.length <= 0)) {
            return null;
        }

        synchronized (CODER) {
            return CODER.encodeAsString(buffer);
        }
    }

    /**
     * Encodes the given unencoded string using URL and filename safe Base 64.
     * 
     * @param unencoded
     *            the string to encode.
     * @return a URL and filename safe Base 64 encoded string.
     */
    public static String encodeBASE64(String unencoded) {
        if (unencoded == null) {
            return null;
        }

        synchronized (CODER) {
            return CODER.encodeAsString(Coder.stringToByteRaw(unencoded));
        }
    }

    /**
     * Returns the offset at which the given delimiter starts. If the delimiter
     * is not part of the input string <code>-1</code> is returned.
     * 
     * @param input
     *            the input string to look through.
     * @param delimiter
     *            the sequence of bytes to look for.
     * @param offset
     *            the <code>0</code>-based index of the byte in input where the
     *            search is started.
     * @param length
     *            the number of bytes to consider, starting at offset. May be
     *            larger than the input length, but has to be at least zero.
     * @return the <code>0</code>-based index of input where delimiter is found
     *         for the first time. <code>-1</code>, if delimiter is not present
     *         in input.
     */
    public static int matches(byte[] input, byte[] delimiter, int offset,
            int length) {
        if ((input == null) || (delimiter == null)) {
            throw new IllegalArgumentException(
                    "input and delimiter may not be null!");
        }
        if (offset < 0) {
            throw new IllegalArgumentException("offset may not be negative!");
        }
        if (delimiter.length < 1) {
            throw new IllegalArgumentException(
                    "delimiter must have at least length one!");
        }
        if (length < 0) {
            throw new IllegalArgumentException("length may not be negative.");
        }

        for (int i = offset; (i < input.length) && (i < (length + offset)); i++) {
            if (input[i] == delimiter[0]) {
                // check whether the next bytes match, too.
                int j;

                for (j = 1; (j < delimiter.length) && ((i + j) < input.length)
                        && ((i + j) < (length + offset)); j++) {
                    if (input[i + j] != delimiter[j]) {
                        break;
                    }
                }

                if (j == delimiter.length) {
                    return i;
                }
            }
            // keep on searching and do NOT skip bytes which have been already
            // compared in the inner loop
        }

        return -1;
    }

    /**
     * Returns whether the given text starts with the given string.
     * 
     * @param text
     *            the text to look through.
     * @param match
     *            the string to look for.
     * @return <code>true</code>, if text starts with match. Otherwise,
     *         <code>false</code> is returned.
     */
    public static boolean startsWith(byte[] text, String match) {
        if (text == null) {
            throw new IllegalArgumentException("text may not be null!");
        }
        if (match == null) {
            throw new IllegalArgumentException("match may not be null!");
        }

        if (text.length < match.length()) {
            return false;
        }

        for (int i = 0; i < match.length(); i++) {
            if (text[i] != match.charAt(i)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Converts a string to a byte array using the default character set of this
     * class.
     * 
     * @param input
     *            the string to convert which is encoded with the default
     *            character set of this class.
     * @return the byte representation of this string according to the default
     *         character set of this class.
     */
    public static byte[] stringToByte(String input) {
        if (input == null) {
            throw new IllegalArgumentException("input may not be null!");
        }

        return input.getBytes(CHARSET);
    }

    /**
     * Converts a string to a byte array.
     * 
     * @param input
     *            the string to convert which is encoded with an 8-bit character
     *            set or just represents bytes.
     * @return the byte representation of this string according to an 8-bit
     *         character set.
     */
    public static byte[] stringToByteRaw(String input) {
        if (input == null) {
            throw new IllegalArgumentException("input may not be null!");
        }

        return input.getBytes(CHARSET_8_BIT);
    }

    /**
     * Converts a string to a character array.
     * 
     * @param input
     *            the string to convert.
     * @return the character array associated with this string.
     */
    public static char[] stringToChar(String input) {
        return (input != null) ? input.toCharArray() : null;
    }

    /**
     * Hidden constructor.
     */
    private Coder() {
    }
}
