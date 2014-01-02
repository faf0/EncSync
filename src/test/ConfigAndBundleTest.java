package test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;

import org.json.simple.parser.ParseException;

import configuration.ClientConfiguration;
import configuration.GroupAccessBundle;
import configuration.OwnerAccessBundle;
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
 * Allows to test whether configuration and bundle files are parsed and stored
 * as desired.
 * 
 * @author Fabian Foerg
 */
public final class ConfigAndBundleTest {
    /**
     * Runs a couple of tests.
     * 
     * @param args
     *            ignored.
     */
    public static void main(String[] args) {
        OwnerAccessBundle oab;
        GroupAccessBundle gab;
        ServerConfiguration sc;
        ClientConfiguration cc;

        try {
            oab = OwnerAccessBundle.parse(Paths.get("files", "clients", "joe1",
                    ".access"));
            System.out.println(oab.toString());
            oab.store(Paths.get("files", "clients", "joe1", ".access.out"));
            gab = GroupAccessBundle.parse(Paths.get("files", "clients", "joe1",
                    "shared1", ".access"));
            System.out.println(gab.toString());
            gab.store(Paths.get("files", "clients", "joe1", "shared1",
                    ".access.out"));
            sc = ServerConfiguration.parse(Paths
                    .get("files", "server", ".conf"));
            System.out.println(sc.toString());
            sc.store(Paths.get("files", "server", ".conf.out"));
            cc = ClientConfiguration.parse(Paths.get("files", "clients",
                    "joe1", ".conf"));
            System.out.println(cc.toString());
            cc.store(Paths.get("files", "clients", "joe1", ".conf.out"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }
}
