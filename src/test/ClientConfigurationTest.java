package test;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

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

public final class ClientConfigurationTest {
    @Test
    public void isValidUserName() {
        assertTrue(ClientConfiguration.isValidUserName("asdf"));
        assertTrue(!ClientConfiguration.isValidUserName("asdf@asdf.com"));
        assertTrue(!ClientConfiguration.isValidUserName("ASDF_asdf."));
        assertTrue(!ClientConfiguration.isValidUserName(".ASDF_asdf."));
        assertTrue(!ClientConfiguration.isValidUserName(null));
        assertTrue(!ClientConfiguration.isValidUserName(""));
        assertTrue(!ClientConfiguration.isValidUserName(" "));
        assertTrue(!ClientConfiguration.isValidUserName("0-9+#"));
    }
}
