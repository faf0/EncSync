package client.executors;

import view.SystemTrayDisplay;
import client.ClientConnectionHandler;
import client.executors.ClientExecutor.ClientExecutorType;
import client.executors.TestPerformanceCommitter.CommitterType;
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
 * Factory class for <code>ClientExecutor</code> instances.
 * 
 * @author Fabian Foerg
 */
public final class ClientExecutorFactory {
    /**
     * Hidden constructor.
     */
    private ClientExecutorFactory() {
    }

    /**
     * Returns the respective executor for the given type.
     * 
     * @param type
     *            the type of the executor. May not be <code>null</code>.
     * @param handler
     *            the client connection handler associated with the executor.
     *            May not be <code>null</code>.
     * @param config
     *            the client configuration. May be <code>null</code>, if the
     *            executor type does not need the configuration.
     * @param data
     *            wrapped data that may be passed to the executor
     *            implementation. May be <code>null</code>.
     * @return the desired executor.
     */
    public static ClientExecutor getInstance(ClientExecutorType type,
            ClientConnectionHandler handler, ClientConfiguration config,
            Object data) {
        if (type == null) {
            throw new NullPointerException("type may not be null!");
        }
        if (handler == null) {
            throw new NullPointerException("handler may not be null!");
        }
        if ((config == null) && !ClientExecutorType.PUT_FOLDER.equals(type)) {
            throw new IllegalArgumentException(
                    "config may not be null for the given type!");
        }

        final ClientExecutor executor;

        switch (type) {
        default:
        case SYNCHRONIZATION_AND_LIVE_WATCH:
            executor = new SynchronizationExecutor(handler, config, true, true);
            displaySystemTrayIcon((SynchronizationExecutor) executor);
            break;

        case SYNCHRONIZATION_ONLY:
            executor = new SynchronizationExecutor(handler, config, true, false);
            displaySystemTrayIcon((SynchronizationExecutor) executor);
            break;

        case LIVE_WATCH_ONLY:
            executor = new SynchronizationExecutor(handler, config, false, true);
            break;

        case PUT_AUTH:
            executor = new PutAuthExecutor(handler);
            break;

        case PUT_FOLDER:
            executor = new PutFolderExecutor(handler);
            break;

        case TEST_COMMIT:
            executor = new TestExecutor(handler, config, true);
            break;

        case TEST_LIVE_WATCHER:
            executor = new TestExecutor(handler, config, false);
            break;

        case TEST_PERFORMANCE_COMMITTER_NEW:
            executor = new TestPerformanceCommitter(handler, config,
                    CommitterType.NEW, data);
            break;

        case TEST_PERFORMANCE_COMMITTER_NEW_AND_MODIFIED:
            executor = new TestPerformanceCommitter(handler, config,
                    CommitterType.NEW_AND_MODIFIED, data);
            break;

        case TEST_PERFORMANCE_SYNCER:
            executor = new TestPerformanceSyncer(handler, config);
            break;
        }

        return executor;
    }

    /**
     * Creates a system tray icon which is updated according to the status of
     * the given synchronization executor.
     * 
     * @param executor
     *            the synchronization executor which delivers status changes for
     *            the system tray icon.
     */
    private static void displaySystemTrayIcon(
            final SynchronizationExecutor executor) {
        assert (executor != null);

        new SystemTrayDisplay(executor);
    }
}
