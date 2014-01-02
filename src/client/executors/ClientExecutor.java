package client.executors;

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
 * Interface for the client main method. The <code>execute</code> method can be
 * executed in a loop, until <code>execute</code> returns <code>false</code>.
 * 
 * @author Fabian Foerg
 */
public interface ClientExecutor {
    /**
     * Collects all existing ClientExecutor types.
     * 
     * @author Fabian Foerg
     */
    public static enum ClientExecutorType {
        SYNCHRONIZATION_AND_LIVE_WATCH,
        SYNCHRONIZATION_ONLY,
        LIVE_WATCH_ONLY,
        PUT_AUTH,
        PUT_FOLDER,
        TEST_COMMIT,
        TEST_LIVE_WATCHER,
        TEST_PERFORMANCE_COMMITTER_NEW,
        TEST_PERFORMANCE_COMMITTER_NEW_AND_MODIFIED,
        TEST_PERFORMANCE_SYNCER;
    }

    /**
     * Executes the given statements.
     * 
     * @return <code>true</code>, if this method should be called again.
     *         Otherwise, <code>false</code>.
     */
    public boolean execute();

    /**
     * Executes currently running tasks and then stops.
     */
    public void stop();
}
