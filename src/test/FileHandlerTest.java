package test;

import static org.junit.Assert.assertTrue;

import java.nio.file.Paths;

import misc.FileHandler;

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

public final class FileHandlerTest {
    @Test
    public void isFolderName() {
        assertTrue(!FileHandler.isFolderName(Paths.get("")));
        assertTrue(!FileHandler.isFolderName(Paths.get("../asdf/asdf")));
        assertTrue(!FileHandler.isFolderName(Paths.get("asdf/asdf")));
        assertTrue(!FileHandler.isFolderName(Paths.get("././")));
        assertTrue(FileHandler.isFolderName(Paths.get(".")));
        assertTrue(FileHandler.isFolderName(Paths.get("./")));
        assertTrue(FileHandler.isFolderName(Paths.get("asdf")));
        assertTrue(FileHandler.isFolderName(Paths.get("asdf/")));
        assertTrue(FileHandler.isFolderName(Paths.get("/asdf/")));
        assertTrue(FileHandler.isFolderName(Paths.get("asdf/asdf/../")));
    }

    @Test
    public void isFileName() {
        assertTrue(!FileHandler.isFileName(Paths.get("")));
        assertTrue(!FileHandler.isFileName(Paths.get(" ")));
        assertTrue(!FileHandler.isFileName(Paths.get(".")));
        assertTrue(!FileHandler.isFileName(Paths.get("./")));
        assertTrue(!FileHandler.isFileName(Paths.get("../master_thesis/src")));
        assertTrue(!FileHandler.isFileName(Paths
                .get("../master_thesis/../master_thesis/src")));
        assertTrue(!FileHandler.isFileName(Paths.get("inexistent/../../x")));
        assertTrue(FileHandler.isFileName(Paths.get("src")));
        assertTrue(FileHandler.isFileName(Paths.get("./src")));
        assertTrue(FileHandler.isFileName(Paths.get("nothing/myfile")));
        assertTrue(FileHandler.isFileName(Paths.get("notthereyet")));
        assertTrue(FileHandler.isFileName(Paths.get(".notthereyet")));
        assertTrue(FileHandler.isFileName(Paths.get("files/myfile")));
        assertTrue(FileHandler.isFileName(Paths.get("files/server/myfile")));
    }

    @Test
    public void getUpperMostDirecectory() {
        assertTrue(FileHandler.getUpperMostDirectory(Paths.get("asdf"))
                .compareTo(Paths.get(".")) == 0);
        assertTrue(FileHandler.getUpperMostDirectory(Paths.get("./asdf"))
                .compareTo(Paths.get(".")) == 0);
        assertTrue(FileHandler.getUpperMostDirectory(Paths.get("././asdf"))
                .compareTo(Paths.get(".")) == 0);
        assertTrue(FileHandler.getUpperMostDirectory(Paths.get("files/asdf"))
                .compareTo(Paths.get("files")) == 0);
        assertTrue(FileHandler.getUpperMostDirectory(
                Paths.get("files/server/asdf")).compareTo(Paths.get("files")) == 0);
    }
}
