package test;

import static org.junit.Assert.assertTrue;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Random;

import org.junit.Test;

import com.nothome.delta.Delta;
import com.nothome.delta.DeltaException;
import com.nothome.delta.DiffWriter;
import com.nothome.delta.GDiffPatcher;
import com.nothome.delta.GDiffWriter;
import com.nothome.delta.PatchException;
import com.nothome.delta.RandomAccessFileSeekableSource;

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
 * Test class for the differ.
 * 
 * @author Fabian Foerg
 */
public final class DiffTest {
    private static final int CONTENT_LENGTH = 16 * 1024;

    /**
     * Delta encodes two local random, binary files (the source and the target)
     * and applies the resulting patch to the source file afterwards. The
     * patched file content must match the target file content.
     * 
     * @throws IOException
     * @throws DeltaException
     * @throws PatchException
     */
    @Test
    public void diffTest() throws IOException, DeltaException, PatchException {
        Path source = Files.createTempFile("source", "");
        Path target = Files.createTempFile("target", "");
        Path delta = Files.createTempFile("delta", ".patch");
        Random random = new Random();
        byte[] buffer = new byte[CONTENT_LENGTH];

        // write source
        OutputStream os = new BufferedOutputStream(
                Files.newOutputStream(source));
        random.nextBytes(buffer);
        os.write(buffer);
        os.close();

        // write target
        os = new BufferedOutputStream(Files.newOutputStream(target));
        random.nextBytes(buffer);
        os.write(buffer);
        os.close();

        // write delta
        DiffWriter output = new GDiffWriter(new DataOutputStream(
                new BufferedOutputStream(Files.newOutputStream(delta))));
        Delta.computeDelta(source.toFile(), target.toFile(), output);
        output.flush();
        output.close();

        System.out.format("Sizes in byte. Source: %d Target: %d Delta: %d%n",
                Files.size(source), Files.size(target), Files.size(delta));

        // apply the delta
        RandomAccessFileSeekableSource sourceIn = new RandomAccessFileSeekableSource(
                new RandomAccessFile(source.toString(), "r"));
        ByteArrayOutputStream patchedSource = new ByteArrayOutputStream();
        InputStream deltaIn = new BufferedInputStream(
                Files.newInputStream(delta));
        OutputStream patchedSourceOut = new BufferedOutputStream(patchedSource);
        new GDiffPatcher(sourceIn, deltaIn, patchedSourceOut);

        sourceIn.close();
        deltaIn.close();
        patchedSourceOut.close();

        // remove temporary files
        Files.deleteIfExists(source);
        Files.deleteIfExists(target);
        Files.deleteIfExists(delta);

        // compare the target data to the patchedSource data
        assertTrue(MessageDigest.isEqual(buffer, patchedSource.toByteArray()));
    }
}
