package client.executors;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;
import static java.nio.file.StandardWatchEventKinds.OVERFLOW;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Observable;
import java.util.Observer;
import java.util.Timer;
import java.util.TimerTask;

import client.ClientConnectionHandler;

import misc.FileHandler;
import misc.Logger;
import protocol.DataContainers.ActionData;
import protocol.DataContainers.ActionType;
import protocol.DataContainers.GetSyncData;
import protocol.ServerProtocol;
import configuration.AccessBundle;
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

/**
 * Standard executor for the client. Synchronizes all files in the client's root
 * directory and all sub-directories. Watches the client's root directory
 * including all sub-folders after the first synchronization, if desired.
 * Synchronizes all local folders periodically after the synchronization time
 * interval as well.
 * 
 * @author Fabian Foerg
 */
public final class SynchronizationExecutor implements ClientExecutor, Observer {
    /**
     * File name of the file which contains the current synchronization point
     * version number.
     */
    public static final String VERSION_FILE = ".version";

    private final ClientConfiguration config;
    private final ClientConnectionHandler handler;
    private final boolean liveWatch;
    private Boolean syncing;
    private final Syncer syncer;
    private boolean stopped;
    private boolean synced;

    /**
     * Creates a new instance with the given parameters.
     * 
     * @param handler
     *            the client connection handler.
     * @param config
     *            the client configuration file.
     * @param sync
     *            <code>true</code>, if synchronization should be run when
     *            started and on a periodic basis. Otherwise, <code>false</code>
     *            .
     * @param liveWatch
     *            <code>true</code>, if the live watcher should be started.
     *            Otherwise, <code>false</code>.
     */
    public SynchronizationExecutor(ClientConnectionHandler handler,
            ClientConfiguration config, boolean sync, boolean liveWatch) {
        if (handler == null) {
            throw new NullPointerException("handler may not be null!");
        }
        if (config == null) {
            throw new NullPointerException("config may not be null!");
        }

        this.handler = handler;
        this.config = config;
        this.liveWatch = liveWatch;
        syncing = new Boolean(false);
        syncer = sync ? new Syncer(handler, config, syncing) : null;
        stopped = false;
        synced = false;

        if (syncer != null) {
            syncer.addObserver(this);
        }
    }

    /**
     * Registers an observer to receive synchronization events.
     * 
     * @param o
     *            the observer to register. May not be <code>null</code>.
     */
    public void register(Observer o) {
        if (o == null) {
            throw new NullPointerException("o may not be null!");
        }

        if (syncer != null) {
            syncer.addObserver(o);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean execute() {
        Timer timer = null;
        SynchronizationTimerTask syncTimer = null;

        // Start the periodic timer, if desired.
        if (syncer != null) {
            timer = new Timer();
            syncTimer = new SynchronizationTimerTask(syncer);
            long intervalLength = config.getSyncInterval() * 1000;
            timer.schedule(syncTimer, 0, intervalLength);
        }

        // Start the live watcher, if desired
        if (liveWatch) {
            Logger.log("Starting live watcher!");

            try {
                Path fileFolder = Paths.get(config.getRootPath()).normalize()
                        .toAbsolutePath();
                Path syncFolder = Paths.get(config.getSyncPath()).normalize()
                        .toAbsolutePath();
                Path logFile = Paths.get(config.getLogFile()).normalize()
                        .toAbsolutePath();
                Path logErrorFile = Paths.get(config.getLogErrorFile())
                        .normalize().toAbsolutePath();
                LiveWatcher watcher = new LiveWatcher(handler, fileFolder,
                        syncFolder, logFile, logErrorFile, syncing);
                watcher.execute();
            } catch (IOException e) {
                Logger.logError(e);
            }
        }

        /*
         * Wait until the program is stopped and the synchronization timer was
         * executed at least once, if synchronization is desired.
         */
        if (syncer != null) {
            synchronized (this) {
                try {
                    while (!(stopped && synced)) {
                        wait();
                    }
                } catch (InterruptedException e) {
                    Logger.logError(e);
                }
            }

            assert ((timer != null) && (syncTimer != null));
            synchronized (syncTimer) {
                timer.cancel();
            }
        }

        return false;
    }

    /**
     * Stops the period synchronization timer. Does not stop the live watcher.
     */
    @Override
    public void stop() {
        synchronized (this) {
            stopped = true;
            notify();
        }
    }

    /**
     * Is called by the synchronizer (<code>Syncer</code>) when the
     * synchronization state changes.
     * 
     * @param o
     *            the synchronizer which caused the event.
     * @param event
     *            the event update.
     */
    @Override
    public void update(Observable o, Object event) {
        if (SYNCHRONIZATION_EVENT.SYNC_SUCCESS.equals(event)
                || SYNCHRONIZATION_EVENT.SYNC_FAIL.equals(event)) {
            synchronized (this) {
                synced = true;
                notify();
            }
        }
    }

    /**
     * The synchronization events.
     * 
     * @author Fabian Foerg
     */
    public static enum SYNCHRONIZATION_EVENT {
        SYNC_START, SYNC_SUCCESS, SYNC_FAIL;
    }

    /**
     * Walk the client's root directory and synchronize every found folder with
     * an access bundle, one after the other.
     * 
     * @author Fabian Foerg
     */
    private static final class Syncer extends Observable {
        private final ClientConnectionHandler handler;
        private final Path fileFolder;
        private final Path syncFolder;
        private Boolean syncing;

        /**
         * Creates a new Syncer.
         * 
         * @param handler
         *            the client connection handler.
         * @param config
         *            the client configuration.
         * @param syncing
         *            the synchronization status variable.
         */
        public Syncer(ClientConnectionHandler handler,
                ClientConfiguration config, Boolean syncing) {
            super();

            if (handler == null) {
                throw new NullPointerException("handler may not be null!");
            }
            if (config == null) {
                throw new NullPointerException("config may not be null!");
            }
            if (syncing == null) {
                throw new NullPointerException("syncing may not be null!");
            }

            this.handler = handler;
            fileFolder = Paths.get(config.getRootPath()).normalize()
                    .toAbsolutePath();
            syncFolder = Paths.get(config.getSyncPath()).normalize()
                    .toAbsolutePath();
            this.syncing = syncing;
        }

        /**
         * Synchronizes every found directory with an access bundle, one after
         * the other. Closes the handler's socket after all folders had been
         * synchronized. Informs observers about the synchronization success or
         * failure, respectively.
         * 
         * @return <code>true</code>, if the client's root directory and all
         *         sub-folders were walked successfully. Otherwise,
         *         <code>false</code>.
         */
        public boolean execute() {
            boolean success;
            SyncFinder syncFinder;

            synchronized (handler) {
                setChanged();
                notifyObservers(SYNCHRONIZATION_EVENT.SYNC_START);

                syncFinder = new SyncFinder(fileFolder);
                success = syncFinder.execute();

                try {
                    handler.close();
                } catch (IOException e) {
                    Logger.logError(e);
                }

                setChanged();
                if (success) {
                    notifyObservers(SYNCHRONIZATION_EVENT.SYNC_SUCCESS);
                } else {
                    notifyObservers(SYNCHRONIZATION_EVENT.SYNC_FAIL);
                }
            }

            return success;
        }

        private final class SyncFinder extends SimpleFileVisitor<Path> {
            private final Path fileFolder;
            private boolean success;

            /**
             * Creates a new sync finder which walks through the given file
             * folder and synchronizes each found directory.
             * 
             * @param fileFolder
             *            the complete path to the file folder to walk through.
             */
            public SyncFinder(Path fileFolder) {
                if ((fileFolder == null) || !Files.isDirectory(fileFolder)) {
                    throw new IllegalArgumentException(
                            "fileFolder may not be null!");
                }

                this.fileFolder = fileFolder;
                success = true;
            }

            /**
             * Walks the file tree provided in the constructor and synchronizes
             * each found directory.
             * 
             * @return <code>true</code>, if the each directory was synchronized
             *         successfully. Otherwise, <code>false</code>.
             */
            public boolean execute() {
                try {
                    Files.walkFileTree(fileFolder, this);
                } catch (IOException e) {
                    success = false;
                    Logger.logError(e);
                }

                return success;
            }

            @Override
            public FileVisitResult visitFile(Path file,
                    BasicFileAttributes attrs) {
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult preVisitDirectory(Path dir,
                    BasicFileAttributes attrs) {
                try {
                    /*
                     * Ignore hidden directories and the synchronization
                     * directory. Ignore directories which do not contain an
                     * access bundle. Ignore directories which are not
                     * sub-directories of fileFolder or the fileFolder.
                     */
                    Path dirAbsolute = dir.toAbsolutePath();
                    Path relativeDir = fileFolder.relativize(dirAbsolute);

                    if (fileFolder.equals(dirAbsolute)
                            || ((relativeDir.getNameCount() == 1)
                                    && !Files.isHidden(dir)
                                    && !dir.getFileName().toString()
                                            .startsWith(".")
                                    && !dirAbsolute.equals(syncFolder) && FileHandler
                                        .isShared(fileFolder, relativeDir))) {
                        Path fileName = Paths.get(relativeDir.toString(),
                                "arbitrary");
                        Integer syncVersion = SynchronizationExecutor.sync(
                                handler, fileFolder, syncFolder,
                                new ActionData[0], fileName, syncing);

                        if (syncVersion == null) {
                            success = false;
                        }

                        if (fileFolder.equals(dirAbsolute)) {
                            // fileFolder may contain shared children
                            return FileVisitResult.CONTINUE;
                        }
                    }
                } catch (IOException e) {
                    Logger.logError(e);
                }

                // shared folders have to be children of fileFolder
                return FileVisitResult.SKIP_SUBTREE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                Logger.logError(exc);
                return FileVisitResult.CONTINUE;
            }
        }
    }

    /**
     * Synchronizes the given actions with the given path and writes the version
     * file, if necessary. Logs the outcome of the synchronization. This method
     * is thread-safe.
     * 
     * @param handler
     *            the handler of the connection.
     * @param fileFolder
     *            the complete path to the client's root directory.
     * @param syncFolder
     *            the complete path to the synchronization directory.
     * @param actions
     *            the actions to sync. May be empty, but not <code>null</code>.
     * @param fileName
     *            the file name relative to the client's root directory which
     *            caused the sync action.
     * @return the version number up to which all changes have been
     *         synchronized. If an error occurred, <code>null</code> is
     *         returned.
     */
    private static Integer sync(ClientConnectionHandler handler,
            Path fileFolder, Path syncFolder, ActionData[] actions,
            Path fileName, Boolean syncing) {
        assert ((handler != null) && (fileFolder != null)
                && (syncFolder != null) && (actions != null)
                && (fileName != null) && (syncing != null));

        Integer result = null;
        Path pathLocal = FileHandler.getAccessBundleDirectory(fileFolder,
                fileName);

        if (pathLocal != null) {
            synchronized (handler) {
                GetSyncData syncData = FileHandler.getSyncData(fileFolder,
                        syncFolder, fileName);

                if (syncData != null) {
                    synchronized (syncing) {
                        syncing = true;
                    }

                    result = handler
                            .getSync(syncData, actions, pathLocal, true);

                    synchronized (syncing) {
                        syncing = false;
                    }

                    if (result != null) {
                        Logger.log(String.format(
                                "Sync SUCCESS: folder %s version %d",
                                pathLocal, result));
                    } else {
                        Logger.logError(String.format("Sync FAIL: folder %s",
                                pathLocal));
                    }
                } else {
                    Logger.logError(String.format(
                            "syncData cannot be created for %s", fileName));
                }
            }
        } else {
            Logger.logError(String
                    .format("Cannot find access bundle for path %s and relative file name %s",
                            fileFolder.toString(), fileName.toString()));
        }

        return result;
    }

    /**
     * Watches a given local file tree with all sub-folders, including shared
     * sub-folders and synchronizes changes of the tree immediately. The code
     * was inspired by http://docs.oracle.com/javase/tutorial
     * /essential/io/examples/WatchDir.java Redistribution and use in source and
     * binary forms, with or without modification, are permitted provided that
     * the following conditions are met: - Redistributions of source code must
     * retain the above copyright notice, this list of conditions and the
     * following disclaimer. - Redistributions in binary form must reproduce the
     * above copyright notice, this list of conditions and the following
     * disclaimer in the documentation and/or other materials provided with the
     * distribution. - Neither the name of Oracle nor the names of its
     * contributors may be used to endorse or promote products derived from this
     * software without specific prior written permission. THIS SOFTWARE IS
     * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
     * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
     * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
     * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
     * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
     * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
     * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
     * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
     * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
     * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
     * THE POSSIBILITY OF SUCH DAMAGE.
     * 
     * @author Fabian Foerg
     */
    private static final class LiveWatcher {
        private final ClientConnectionHandler handler;
        private final WatchService watcher;
        private final Map<WatchKey, Path> keys;
        private final Path fileFolder;
        private final Path syncFolder;
        private final Path logFile;
        private final Path logErrorFile;
        private Boolean syncing;

        /**
         * Creates a LiveWatcher.
         * 
         * @param handler
         *            the client connection handler which connects to the
         *            server.May not be <code>null</code>.
         * @param fileFolder
         *            the complete path to the client's root directory or a
         *            different local directory to watch for changes. All
         *            changes in unhidden sub-directories, including shared
         *            folders are also watched. May not be <code>null</code>.
         * @param syncFolder
         *            the synchronization folder. This folder is not watched.
         *            May not be <code>null</code>.
         * @param logFile
         *            the complete path to the log file.
         * @param logErrorFile
         *            the complete path to the error log file.
         * @param syncing
         *            the synchronization status variable.
         * @throws IOException
         */
        public LiveWatcher(ClientConnectionHandler handler, Path fileFolder,
                Path syncFolder, Path logFile, Path logErrorFile,
                Boolean syncing) throws IOException {
            if (handler == null) {
                throw new NullPointerException("handler may not be null!");
            }
            if (fileFolder == null) {
                throw new NullPointerException("toWatch may not be null!");
            }
            if (syncFolder == null) {
                throw new NullPointerException("syncFolder may not be null!");
            }
            if (logFile == null) {
                throw new NullPointerException("logFile may not be null!");
            }
            if (logErrorFile == null) {
                throw new NullPointerException("logErrorFile may not be null!");
            }
            if (syncing == null) {
                throw new NullPointerException("syncing may not be null!");
            }

            this.handler = handler;
            this.fileFolder = fileFolder.normalize().toAbsolutePath();
            this.syncFolder = syncFolder.normalize().toAbsolutePath();
            this.logFile = logFile.normalize().toAbsolutePath();
            this.logErrorFile = logErrorFile.normalize().toAbsolutePath();
            this.syncing = syncing;
            watcher = FileSystems.getDefault().newWatchService();
            keys = new HashMap<WatchKey, Path>();
            register(fileFolder);
        }

        @SuppressWarnings("unchecked")
        private static <T> WatchEvent<T> cast(WatchEvent<?> event) {
            return (WatchEvent<T>) event;
        }

        /**
         * Register the given directory, and all its sub-directories, with the
         * WatchService.
         * 
         * @param start
         *            the root of the file tree to watch.
         */
        private void register(Path start) throws IOException {
            // register directory and sub-directories
            Files.walkFileTree(start, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir,
                        BasicFileAttributes attrs) throws IOException {
                    /*
                     * Ignore hidden sub-folders. Ignore the synchronization
                     * folder.
                     */
                    Path dirAbsolute = dir.normalize().toAbsolutePath();

                    if (Files.isHidden(dirAbsolute)
                            || dirAbsolute.getFileName().toString()
                                    .startsWith(".")
                            || syncFolder.equals(dirAbsolute)) {
                        return FileVisitResult.SKIP_SUBTREE;
                    } else {
                        WatchKey key = dirAbsolute.register(watcher,
                                ENTRY_CREATE, ENTRY_DELETE, ENTRY_MODIFY);
                        keys.put(key, dirAbsolute);
                        return FileVisitResult.CONTINUE;
                    }
                }
            });
        }

        /**
         * Begin listening for changes in the registered directories.
         * Synchronize changes when an event is encountered.
         */
        public void execute() {
            while (true) {
                // Wait for the next event
                WatchKey key;

                try {
                    key = watcher.take();
                } catch (InterruptedException e) {
                    Logger.logError(e);
                    return;
                }

                // Ignore events caused by synchronization
                synchronized (syncing) {
                    if (syncing) {
                        continue;
                    }
                }

                Path dir = keys.get(key);

                if (dir == null) {
                    Logger.logError("WatchKey not recognized!");
                    continue;
                }

                List<WatchEvent<?>> events = key.pollEvents();

                for (int i = 0; i < events.size(); i++) {
                    WatchEvent<?> event = events.get(i);

                    @SuppressWarnings("rawtypes")
                    WatchEvent.Kind kind = event.kind();

                    if (kind == OVERFLOW) {
                        /*
                         * There have probably been unspecified changes. Sync
                         * them.
                         */
                        Path relativeDir = fileFolder.relativize(dir
                                .toAbsolutePath());
                        Path arbitraryFileName = Paths.get(
                                relativeDir.toString(), "arbitrary");
                        SynchronizationExecutor.sync(handler, fileFolder,
                                syncFolder, new ActionData[0],
                                arbitraryFileName, syncing);
                        // Ignore events caused by synchronization
                        watcher.poll();
                        continue;
                    }

                    /*
                     * Context for the directory entry event is the file name of
                     * entry.
                     */
                    WatchEvent<Path> ev = cast(event);
                    Path name = ev.context();
                    Path child = dir.resolve(name);
                    Path relativeToFileFolderName = fileFolder
                            .relativize(child);
                    Path pathLocal = FileHandler.getAccessBundleDirectory(
                            fileFolder, relativeToFileFolderName);
                    Path relativeName = FileHandler.ROOT_PATH.equals(pathLocal) ? relativeToFileFolderName
                            : pathLocal.normalize()
                                    .relativize(relativeToFileFolderName)
                                    .normalize();

                    if (Files.isDirectory(child)
                            || child.getFileName().toString().startsWith(".")
                            || AccessBundle.ACCESS_BUNDLE_FILENAME.equals(child
                                    .getFileName().toString())) {
                        /*
                         * Do not log ignored changes of log files, as doing so
                         * would cause a change to the log file. In turn, the
                         * live watcher would detect this change of the log file
                         * and log the change. This would continue infinitely.
                         */
                        if (!logFile.equals(child)
                                && !logErrorFile.equals(child)) {
                            Logger.log(String.format("Ignored change of %s",
                                    child.toString()));
                        }
                        continue;
                    }

                    /*
                     * If directory is created, then register it and its
                     * sub-directories. If a file is created, synchronize it.
                     */
                    if (kind == ENTRY_CREATE) {
                        if (Files.isDirectory(child)) {
                            try {
                                register(child);
                            } catch (IOException e) {
                                Logger.logError(e);
                            }
                        } else {
                            ActionData action = new ActionData(0,
                                    ActionType.ADD, relativeName.toString());
                            SynchronizationExecutor.sync(handler, fileFolder,
                                    syncFolder, new ActionData[] { action },
                                    relativeToFileFolderName, syncing);
                            // Ignore events caused by synchronization
                            watcher.poll();
                        }
                    } else if (kind == ENTRY_MODIFY) {
                        ActionData action = new ActionData(0,
                                ActionType.MODIFY, relativeName.toString());
                        SynchronizationExecutor.sync(handler, fileFolder,
                                syncFolder, new ActionData[] { action },
                                relativeToFileFolderName, syncing);
                        // Ignore events caused by synchronization
                        watcher.poll();
                    } else if (kind == ENTRY_DELETE) {
                        if ((i == (events.size() - 1))
                                || (events.get(i + 1).kind() != ENTRY_CREATE)) {
                            /*
                             * Deleted file/directory is not present anymore in
                             * the client directory. It is only present in the
                             * sync directory. Use the resource in the sync
                             * folder to check whether it was a file or a
                             * directory.
                             */
                            Path syncResource = Paths.get(
                                    syncFolder.toString(),
                                    relativeToFileFolderName.toString());

                            if (Files.exists(syncResource)
                                    && !Files.isDirectory(syncResource)) {
                                /*
                                 * File was deleted and not renamed, as neither
                                 * a next entry exists nor is a create event.
                                 */
                                ActionData action = new ActionData(0,
                                        ActionType.DELETE,
                                        relativeName.toString());
                                SynchronizationExecutor.sync(handler,
                                        fileFolder, syncFolder,
                                        new ActionData[] { action },
                                        relativeToFileFolderName, syncing);
                                // Ignore events caused by synchronization
                                watcher.poll();
                            }
                        } else {
                            // File or directory was renamed.
                            WatchEvent<Path> moveTo = cast(events.get(i + 1));
                            Path moveToName = moveTo.context();
                            Path completeMoveToName = dir.resolve(moveToName)
                                    .normalize();

                            if (!Files.isDirectory(completeMoveToName)) {
                                // File was renamed.

                                Path relativeMoveToName = Paths
                                        .get(fileFolder.toString(),
                                                pathLocal.toString())
                                        .normalize()
                                        .relativize(completeMoveToName)
                                        .normalize();
                                String object = String
                                        .format("%s%s%s",
                                                relativeName.toString(),
                                                ServerProtocol.Messages.HISTORY_OBJECT_DELIMITER,
                                                relativeMoveToName.toString());
                                ActionData action = new ActionData(0,
                                        ActionType.RENAME, object);
                                SynchronizationExecutor.sync(handler,
                                        fileFolder, syncFolder,
                                        new ActionData[] { action },
                                        relativeToFileFolderName, syncing);
                                // Ignore events caused by synchronization
                                watcher.poll();
                            } else {
                                // Directory was renamed. Sync possibly renamed
                                // files in the renamed directory. Watch the new
                                // directory.

                                Path fileName = Paths.get(
                                        completeMoveToName.toString(),
                                        "arbitrary");
                                SynchronizationExecutor.sync(handler,
                                        fileFolder, syncFolder,
                                        new ActionData[0], fileName, syncing);
                                // Ignore events caused by synchronization
                                watcher.poll();

                                try {
                                    register(completeMoveToName);
                                } catch (IOException e) {
                                    Logger.logError(e);
                                }
                            }

                            /*
                             * Skip next entry which is the corresponding create
                             * event of the rename event. A rename event is
                             * split into a delete and create event by the
                             * watcher. We already handled the create event.
                             */
                            i++;
                        }
                    }
                    // Other kind types are neither available nor supported.
                }

                /*
                 * Reset key and remove from the map, if the directory is no
                 * longer accessible.
                 */
                boolean valid = key.reset();

                if (!valid) {
                    keys.remove(key);

                    // all directories are inaccessible
                    if (keys.isEmpty()) {
                        break;
                    }
                }
            }
        }
    }

    /**
     * Synchronizes all directories when executed. Obtain the lock of this
     * timer, before you call <code>cancel()</code>.
     * 
     * @author Fabian Foerg
     */
    private static final class SynchronizationTimerTask extends TimerTask {
        private final Syncer syncer;

        /**
         * Creates a new synchronization timer task.
         * 
         * @param syner
         *            the syncer to take care of synchronizations.
         */
        public SynchronizationTimerTask(Syncer syncer) {
            if (syncer == null) {
                throw new NullPointerException("syncer may not be null!");
            }

            this.syncer = syncer;
        }

        /**
         * Synchronizes all directories.
         */
        @Override
        public void run() {
            synchronized (this) {
                syncer.execute();
            }
        }
    }
}
