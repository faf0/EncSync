package view;

import java.awt.AWTException;
import java.awt.Image;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.util.Observable;
import java.util.Observer;

import javax.swing.ImageIcon;
import javax.swing.SwingUtilities;

import misc.Logger;
import client.executors.SynchronizationExecutor;
import client.executors.SynchronizationExecutor.SYNCHRONIZATION_EVENT;

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
 * Shows a different system tray icon, depending on the synchronization status.
 * The images referenced are from the http://openiconlibrary.sourceforge.net/
 * and are all released under the LGPL-2.1 (see
 * http://www.gnu.org/licenses/lgpl-2.1.txt or the icon folder to get a copy).
 * 
 * @author Fabian Foerg
 */
public final class SystemTrayDisplay implements Observer {
    private static final Image SYNC_START_IMAGE = new ImageIcon(
            "icons/view-refresh-6.png", "synchronization start").getImage();
    private static final Image SYNC_SUCCESS_IMAGE = new ImageIcon(
            "icons/dialog-accept.png", "synchronization success").getImage();
    private static final Image SYNC_FAIL_IMAGE = new ImageIcon(
            "icons/dialog-cancel-4.png", "synchronization fail").getImage();
    private static final String SYNC_START_TOOLTIP = "Synchronizing local folders.";
    private static final String SYNC_SUCCESS_TOOLTIP = "Synchronization finished successfully.";
    private static final String SYNC_FAIL_TOOLTIP = "Synchronization failed.";
    private TrayIcon icon;

    /**
     * Default constructor. Registers this system tray display for the events of
     * the given SynchronizationExecutor.
     * 
     * @param syncer
     *            the synchronization executor from which to receive events.
     */
    public SystemTrayDisplay(SynchronizationExecutor syncer) {
        if (syncer == null) {
            throw new NullPointerException("syncer may not be null!");
        }

        icon = null;
        syncer.register(this);
    }

    /**
     * Is called by the synchronization executor when the synchronization status
     * changes. Changes the system tray icon according to the status.
     * 
     * @param o
     *            the observable which caused the update.
     * @param event
     *            the received event.
     */
    @Override
    public void update(final Observable o, final Object event) {
        if (SystemTray.isSupported() && (event != null)
                && (event instanceof SYNCHRONIZATION_EVENT)) {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    SYNCHRONIZATION_EVENT syncEvent = (SYNCHRONIZATION_EVENT) event;

                    if (icon == null) {
                        switch (syncEvent) {
                        case SYNC_START:
                            icon = new TrayIcon(SYNC_START_IMAGE,
                                    SYNC_START_TOOLTIP);
                            break;

                        case SYNC_SUCCESS:
                            icon = new TrayIcon(SYNC_SUCCESS_IMAGE,
                                    SYNC_SUCCESS_TOOLTIP);
                            break;

                        default:
                        case SYNC_FAIL:
                            icon = new TrayIcon(SYNC_FAIL_IMAGE,
                                    SYNC_FAIL_TOOLTIP);
                            break;
                        }

                        icon.setImageAutoSize(true);

                        try {
                            SystemTray.getSystemTray().add(icon);
                        } catch (AWTException e) {
                            Logger.logError(e);
                        }
                    } else {
                        switch (syncEvent) {
                        case SYNC_START:
                            icon.setImage(SYNC_START_IMAGE);
                            icon.setToolTip(SYNC_START_TOOLTIP);
                            break;

                        case SYNC_SUCCESS:
                            icon.setImage(SYNC_SUCCESS_IMAGE);
                            icon.setToolTip(SYNC_SUCCESS_TOOLTIP);
                            break;

                        default:
                        case SYNC_FAIL:
                            icon.setImage(SYNC_FAIL_IMAGE);
                            icon.setToolTip(SYNC_FAIL_TOOLTIP);
                            break;
                        }

                        icon.setImageAutoSize(true);
                    }
                }
            });
        }
    }
}
