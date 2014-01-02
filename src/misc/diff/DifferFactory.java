package misc.diff;

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
 * Factory class for <code>Differ</code> instances.
 * 
 * @author Fabian Foerg
 */
public final class DifferFactory {
    public static enum DifferImplementation {
        XDELTA
    };

    /**
     * Hidden constructor.
     */
    private DifferFactory() {
    }

    /**
     * Returns a differ instance for the given implementation.
     * 
     * @param implementation
     *            the implementation to use.
     * @return a differ instance for the given implementation.
     */
    public static Differ getInstance(DifferImplementation implementation) {
        if (implementation == null) {
            throw new NullPointerException("implementation may not be null!");
        }

        Differ result;

        switch (implementation) {
        case XDELTA:
        default:
            result = new DifferXdelta();
            break;
        }

        return result;
    }
}
