package misc;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileLock;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.Date;

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
 * Utility class for message logging. The way messages are logged can be
 * directly implemented here. The interface distinguishes between common log and
 * error messages. This class is thread-safe. Supports only one log file per
 * virtual machine, as the interface methods are all static.
 * 
 * @author Fabian Foerg
 */
public final class Logger {
    private static final Object STD_OUT_LOCK = new Object();
    private static final Object STD_ERROR_LOCK = new Object();
    private static Object LOG_FILE_LOCK = null;
    private static Object LOG_ERROR_FILE_LOCK = null;
    private static Path LOG_FILE = null;
    private static Path LOG_ERROR_FILE = null;
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat(
            "yyyy-MM-dd HH:mm:ss");

    /**
     * Appends the given message to the common message log.
     * 
     * @param message
     *            the message to log. May not be <code>null</code>.
     */
    public static void log(String message) {
        if (message == null) {
            throw new NullPointerException("message may not be null!");
        }

        Date date = new Date();
        String dateString;

        synchronized (DATE_FORMAT) {
            dateString = DATE_FORMAT.format(date);
        }

        String loggedMessage = String.format("%s - %s\n", dateString, message);

        synchronized (STD_OUT_LOCK) {
            System.out.print(loggedMessage);
        }

        if (LOG_FILE != null) {
            synchronized (LOG_FILE_LOCK) {
                try (FileOutputStream out = new FileOutputStream(
                        LOG_FILE.toFile(), true);) {
                    FileLock lock = out.getChannel().lock(0, Long.MAX_VALUE,
                            false);
                    out.write(Coder.stringToByte(loggedMessage));
                    out.flush();
                    lock.release();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Appends the given exception to the error log.
     * 
     * @param exception
     *            the exception to log. May not be <code>null</code>.
     */
    public static void logError(Exception exception) {
        if (exception == null) {
            throw new NullPointerException("exception may not be null!");
        }

        String message = exception.getMessage();

        if (message == null) {
            message = "An unspecified exception occured!";
        }

        logError(message);
    }

    /**
     * Appends the given message to the error log.
     * 
     * @param message
     *            the error message to log. May not be <code>null</code>.
     */
    public static void logError(String message) {
        if (message == null) {
            throw new NullPointerException("message may not be null!");
        }

        Date date = new Date();
        String dateString;

        synchronized (DATE_FORMAT) {
            dateString = DATE_FORMAT.format(date);
        }

        String loggedMessage = String.format("%s - %s\n", dateString, message);

        synchronized (STD_ERROR_LOCK) {
            System.err.print(loggedMessage);
        }

        if (LOG_ERROR_FILE != null) {
            synchronized (LOG_ERROR_FILE_LOCK) {
                try (FileOutputStream out = new FileOutputStream(
                        LOG_ERROR_FILE.toFile(), true);) {
                    FileLock lock = out.getChannel().lock(0, Long.MAX_VALUE,
                            false);
                    out.write(Coder.stringToByte(loggedMessage));
                    out.flush();
                    lock.release();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Sets the log files to the given paths. Log paths can only be set once.
     * 
     * @param logFile
     * @param logErrorFile
     * @return <code>true</code>, if the log files were set successfully.
     *         Otherwise, <code>false</code>.
     */
    public static boolean setLogs(Path logFile, Path logErrorFile) {
        if (logFile == null) {
            throw new IllegalArgumentException("logFile may not be null!");
        }
        if (logErrorFile == null) {
            throw new IllegalArgumentException("logErrorFile may not be null!");
        }

        boolean set = false;

        synchronized (Logger.class) {
            if ((LOG_FILE == null) && (LOG_ERROR_FILE == null)) {
                // Set the lock objects
                LOG_FILE_LOCK = new Object();

                if (logFile.normalize().toAbsolutePath()
                        .equals(logErrorFile.normalize().toAbsolutePath())) {
                    LOG_ERROR_FILE_LOCK = LOG_FILE_LOCK;
                } else {
                    LOG_ERROR_FILE_LOCK = new Object();
                }

                // Set the log file paths
                LOG_FILE = logFile.normalize();
                LOG_ERROR_FILE = logErrorFile.normalize();
                set = true;
            }
        }

        return set;
    }

    /**
     * Hidden constructor.
     */
    private Logger() {
    }
}
