package test;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random;

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
 * Generates random files with random content.
 */
public final class RandomFileGenerator {
    /**
     * The buffer size in bytes of the file writer buffer.
     */
    private static final int BUFFER_SIZE = 128 * 1024;
    /**
     * The random number generator to use.
     */
    private static final Random RANDOM = new Random();

    /**
     * Generates random file with random content.
     * 
     * @param args
     *            the path where the file is to be stored and the size of the
     *            random file to generate in bytes.
     */
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: program path size");
        } else {
            String path = args[0];
            long size;

            try {
                size = Long.parseLong(args[1]);

                if (size < 0) {
                    throw new IllegalArgumentException(
                            "size must not be smaller than zero!");
                } else {
                    writeFile(Paths.get(path), size);
                }
            } catch (NumberFormatException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Writes a file with random content.
     * 
     * @param file
     *            the path where the file is to be written.
     * @param size
     *            the size of the file in bytes.
     * @return <code>true</code>, if the file was successfully written.
     *         <code>false</code>, otherwise.
     */
    private static boolean writeFile(Path file, long size) {
        assert ((file != null) && (size >= 0));
        boolean success = false;

        try (FileOutputStream fileWriter = new FileOutputStream(file.toFile(),
                false);) {
            long written = 0;
            byte[] buffer = new byte[BUFFER_SIZE];

            while (written < size) {
                int toWrite = (int) Math.min(buffer.length, size - written);
                // fill buffer with random bytes
                RANDOM.nextBytes(buffer);
                fileWriter.write(buffer, 0, toWrite);
                written += toWrite;
            }

            fileWriter.close();
            success = true;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return success;
    }
}
