package misc.diff;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import misc.FileHandler;
import misc.Logger;

import com.nothome.delta.Delta;
import com.nothome.delta.DeltaException;
import com.nothome.delta.GDiffPatcher;
import com.nothome.delta.GDiffWriter;
import com.nothome.delta.PatchException;

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
 * Differ implementation using Xdelta algorithm and GDIFF format.
 * 
 * @author Fabian Foerg
 */
public final class DifferXdelta implements Differ {
    /**
     * Default constructor.
     */
    public DifferXdelta() {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Path diff(Path source, Path target) {
        if ((source == null) || !Files.isReadable(source)) {
            throw new IllegalArgumentException(
                    "source must exist and be readable!");
        }
        if ((target == null) || !Files.isReadable(target)) {
            throw new IllegalArgumentException(
                    "target must exist and be readable!");
        }

        Path delta = null;
        GDiffWriter output = null;

        try (DataOutputStream outputStream = new DataOutputStream(
                new BufferedOutputStream(Files.newOutputStream(delta = Files
                        .createTempFile(null, FileHandler.TEMP_FILE_SUFFIX))));) {
            output = new GDiffWriter(outputStream);
            Delta.computeDelta(source.toFile(), target.toFile(), output);
        } catch (IOException | DeltaException e) {
            Logger.logError(e);

            if (delta != null) {
                try {
                    Files.deleteIfExists(delta);
                } catch (IOException eDelete) {
                    Logger.logError(eDelete);
                } finally {
                    delta = null;
                }
            }
        }

        return delta;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean patch(Path source, Path delta, Path output) {
        if ((source == null) || !Files.isReadable(source)) {
            throw new NullPointerException("source must exist and be readable!");
        }
        if ((delta == null) || !Files.isReadable(delta)) {
            throw new NullPointerException("delta must exist and be readable!");
        }
        if (output == null) {
            throw new NullPointerException("output may not be null!");
        }
        if (source.normalize().equals(output.normalize())) {
            throw new IllegalArgumentException("source and output must differ!");
        }

        boolean result = false;

        try {
            new GDiffPatcher(source.toFile(), delta.toFile(), output.toFile());
            result = true;
        } catch (IOException | PatchException e) {
            Logger.logError(e);
        }

        return result;
    }
}
