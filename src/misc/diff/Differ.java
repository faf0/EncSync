package misc.diff;

import java.nio.file.Path;

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
 * Interface for creating and applying difference files (diffs; deltas) between
 * a source and a target file.
 * 
 * @author Fabian Foerg
 */
public interface Differ {
    /**
     * Creates the diff file between the source and the target in a temporary
     * directory. Locks the source and the target file, but not the diff file.
     * 
     * @param source
     *            the complete path to the source.
     * @param target
     *            the complete path to the target.
     * @return the path to the temporary file with the diff or <code>null</code>
     *         , if the file cannot be created.
     */
    public Path diff(Path source, Path target);

    /**
     * Applies a patch to a source file and writes the existing output to a
     * file.
     * 
     * @param source
     *            the file to apply the patch to.
     * @param delta
     *            the patch.
     * @param output
     *            the patched source file output.
     * @return <code>true</code>, if patching was successful. <code>false</code>
     *         , otherwise.
     */
    public boolean patch(Path source, Path delta, Path output);
}
