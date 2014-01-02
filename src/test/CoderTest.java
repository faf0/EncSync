package test;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Random;

import misc.Coder;

import org.junit.Test;

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

public final class CoderTest {
    @Test
    public void codingASCII() throws IOException {
        byte[] byteArray = new byte[128];
        String unencoded, encoded, decoded;

        new Random().nextBytes(byteArray);
        /*
         * Clamp signed bytes to 7-bit as we use US-ASCII
         */
        for (int i = 0; i < byteArray.length; i++) {
            byteArray[i] = (byte) (byteArray[i] & 0x0000007F);
        }

        unencoded = Coder.byteToString(byteArray);
        encoded = Coder.encodeBASE64(unencoded);
        decoded = Coder.decodeBASE64asString(encoded);
        assertTrue(unencoded.equals(decoded));
    }

    @Test
    public void codingRaw() throws IOException {
        byte[] byteArray = new byte[128];
        String unencoded, encoded, decoded;

        new Random().nextBytes(byteArray);
        unencoded = Coder.byteToStringRaw(byteArray);
        encoded = Coder.encodeBASE64(unencoded);
        decoded = Coder.decodeBASE64asString(encoded);
        assertTrue(unencoded.equals(decoded));
    }

    @Test
    public void matches() {
        byte[] input = Coder.stringToByte("1234asdf1234");
        byte[] delimiter = Coder.stringToByte("asdf");
        assertTrue(Coder.matches(input, delimiter, 0, input.length) == 4);
        assertTrue(Coder.matches(input, delimiter, 4, input.length) == 4);
        assertTrue(Coder.matches(input, delimiter, 5, input.length) == -1);
        assertTrue(Coder.matches(Coder.stringToByte("aasdfa"), delimiter, 0,
                input.length) == 1);
        assertTrue(Coder.matches(input, delimiter, 4, 4) == 4);
    }

    @Test
    public void startsWith() {
        assertTrue(Coder.startsWith(Coder.stringToByte("asdf1234"), "asdf"));
        assertTrue(!Coder.startsWith(Coder.stringToByte("asdxxx"), "asdf"));
    }
}
