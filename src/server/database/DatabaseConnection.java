package server.database;

import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.SQLClientInfoException;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Struct;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executor;

import org.sqlite.SQLiteConfig;

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
 * Allows to get connections to the server's database. The connection can be
 * shared, i.e. an already open connection can be shared among the callers. A
 * shared connection is not closed by calling <code>close</code> on the
 * connection. Instead the <code>close</code> method of this class must be
 * called to close the database connection.
 * 
 * @author Fabian Foerg
 */
public final class DatabaseConnection {
    public static final String DRIVER_CLASS = "org.sqlite.JDBC";
    private static final SQLiteConfig config = new SQLiteConfig();

    private static String DATABASE_URL;
    private static SharedConnection sharedConnection;
    private static Boolean initialized = new Boolean(false);

    /**
     * Hidden constructor.
     */
    private DatabaseConnection() {
    }

    /**
     * Initializes the shared connection with the given database.
     * 
     * @param databasePath
     *            the path to the SQLite database file.
     * @return <code>true</code>, if the connection was initialized with the
     *         given path. Otherwise, <code>false</code>.
     * @throws ClassNotFoundException
     * @throws SQLException
     */
    public static boolean init(String databasePath)
            throws ClassNotFoundException, SQLException {
        if (databasePath == null) {
            throw new IllegalArgumentException("databasePath may not be null!");
        }

        synchronized (initialized) {
            if (!initialized) {
                DATABASE_URL = String.format("jdbc:sqlite:%s", databasePath);
                Class.forName(DRIVER_CLASS);
                sharedConnection = new SharedConnection(
                        DriverManager.getConnection(DATABASE_URL,
                                config.toProperties()));
                initialized = true;
                return true;
            } else {
                return false;
            }
        }
    }

    /**
     * Returns the shared database connection. The caller should only close the
     * returned connection, when no more connections are needed. Calling
     * <code>close</code> on this connection has no effect. Instead the
     * <code>close</code> method of this class must be called to close the
     * shared database connection.
     * 
     * @return the shared connection.
     * @throws ClassNotFoundException
     * @throws SQLException
     */
    public static SharedConnection getConnection()
            throws ClassNotFoundException, SQLException {
        synchronized (initialized) {
            if (!initialized) {
                throw new IllegalStateException(
                        "connection was not initialized!");
            } else if (sharedConnection.isClosed()) {
                Class.forName(DRIVER_CLASS);
                sharedConnection = new SharedConnection(
                        DriverManager.getConnection(DATABASE_URL,
                                config.toProperties()));
            }
        }

        return sharedConnection;
    }

    /**
     * Returns a new, exclusive database connection. The caller should close the
     * connection.
     * 
     * @return a new, exclusive database connection.
     * @throws SQLException
     * @throws ClassNotFoundException
     */
    public static Connection getDedicatedConnection() throws SQLException,
            ClassNotFoundException {
        synchronized (initialized) {
            if (!initialized) {
                throw new IllegalStateException(
                        "init the connection first with the path to the database file!");
            }
        }

        Class.forName(DRIVER_CLASS);
        return DriverManager.getConnection(DATABASE_URL, config.toProperties());
    }

    /**
     * Closes the shared connection, if it exists.
     */
    public static void close() throws SQLException {
        synchronized (initialized) {
            if (initialized) {
                sharedConnection.closeSuper();
            }
        }
    }

    /**
     * This class wraps an existing database connection. The connection is
     * closed by <code>closeSuper</code> rather than <code>close</code>.
     * 
     * @author Fabian Foerg
     */
    public static final class SharedConnection implements Connection {
        private final Connection connection;

        /**
         * Creates a shared connection which wraps the given connection.
         * 
         * @param connection
         *            the connection to share.
         */
        public SharedConnection(Connection connection) {
            if (connection == null) {
                throw new IllegalArgumentException(
                        "connection may not be null!");
            }

            this.connection = connection;
        }

        /**
         * Does not close this shared connection. Does nothing.
         */
        @Override
        public void close() throws SQLException {
            // do nothing
            // FIXME Remove close here! Was needed as SQLite was using old
            // values otherwise (seems to be a cache issue of the driver).
            connection.close();
        }

        /**
         * Closes this shared connection.
         * 
         * @throws SQLException
         *             if an error occurs.
         */
        public void closeSuper() throws SQLException {
            connection.close();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isWrapperFor(Class<?> iface) throws SQLException {
            return connection.isWrapperFor(iface);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            return connection.unwrap(iface);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void abort(Executor executor) throws SQLException {
            connection.abort(executor);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void clearWarnings() throws SQLException {
            connection.clearWarnings();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void commit() throws SQLException {
            connection.commit();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Array createArrayOf(String typeName, Object[] elements)
                throws SQLException {
            return connection.createArrayOf(typeName, elements);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Blob createBlob() throws SQLException {
            return connection.createBlob();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Clob createClob() throws SQLException {
            return connection.createClob();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public NClob createNClob() throws SQLException {
            return connection.createNClob();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public SQLXML createSQLXML() throws SQLException {
            return connection.createSQLXML();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Statement createStatement() throws SQLException {
            return connection.createStatement();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Statement createStatement(int resultSetType,
                int resultSetConcurrency) throws SQLException {
            return connection.createStatement(resultSetType,
                    resultSetConcurrency);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Statement createStatement(int resultSetType,
                int resultSetConcurrency, int resultSetHoldability)
                throws SQLException {
            return connection.createStatement(resultSetType,
                    resultSetConcurrency, resultSetHoldability);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Struct createStruct(String typeName, Object[] attributes)
                throws SQLException {
            return connection.createStruct(typeName, attributes);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean getAutoCommit() throws SQLException {
            return connection.getAutoCommit();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getCatalog() throws SQLException {
            return connection.getCatalog();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Properties getClientInfo() throws SQLException {
            return connection.getClientInfo();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getClientInfo(String name) throws SQLException {
            return connection.getClientInfo(name);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int getHoldability() throws SQLException {
            return connection.getHoldability();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public DatabaseMetaData getMetaData() throws SQLException {
            return connection.getMetaData();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int getNetworkTimeout() throws SQLException {
            return connection.getNetworkTimeout();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getSchema() throws SQLException {
            return connection.getSchema();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int getTransactionIsolation() throws SQLException {
            return connection.getTransactionIsolation();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Map<String, Class<?>> getTypeMap() throws SQLException {
            return connection.getTypeMap();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public SQLWarning getWarnings() throws SQLException {
            return connection.getWarnings();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isClosed() throws SQLException {
            return connection.isClosed();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isReadOnly() throws SQLException {
            return connection.isReadOnly();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isValid(int timeout) throws SQLException {
            return connection.isValid(timeout);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String nativeSQL(String sql) throws SQLException {
            return connection.nativeSQL(sql);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public CallableStatement prepareCall(String sql) throws SQLException {
            return connection.prepareCall(sql);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public CallableStatement prepareCall(String sql, int resultSetType,
                int resultSetConcurrency) throws SQLException {
            return connection.prepareCall(sql, resultSetType,
                    resultSetConcurrency);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public CallableStatement prepareCall(String sql, int resultSetType,
                int resultSetConcurrency, int resultSetHoldability)
                throws SQLException {
            return connection.prepareCall(sql, resultSetType,
                    resultSetConcurrency, resultSetHoldability);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public PreparedStatement prepareStatement(String sql)
                throws SQLException {
            return connection.prepareStatement(sql);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public PreparedStatement prepareStatement(String sql,
                int autoGeneratedKeys) throws SQLException {
            return connection.prepareStatement(sql, autoGeneratedKeys);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public PreparedStatement prepareStatement(String sql,
                int[] columnIndexes) throws SQLException {
            return connection.prepareStatement(sql, columnIndexes);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public PreparedStatement prepareStatement(String sql,
                String[] columnNames) throws SQLException {
            return connection.prepareStatement(sql, columnNames);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public PreparedStatement prepareStatement(String sql,
                int resultSetType, int resultSetConcurrency)
                throws SQLException {
            return connection.prepareStatement(sql, resultSetType,
                    resultSetConcurrency);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public PreparedStatement prepareStatement(String sql,
                int resultSetType, int resultSetConcurrency,
                int resultSetHoldability) throws SQLException {
            return connection.prepareStatement(sql, resultSetType,
                    resultSetConcurrency, resultSetHoldability);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void releaseSavepoint(Savepoint savepoint) throws SQLException {
            connection.releaseSavepoint(savepoint);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void rollback() throws SQLException {
            connection.rollback();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void rollback(Savepoint savepoint) throws SQLException {
            connection.rollback(savepoint);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void setAutoCommit(boolean autoCommit) throws SQLException {
            connection.setAutoCommit(autoCommit);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void setCatalog(String catalog) throws SQLException {
            connection.setCatalog(catalog);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void setClientInfo(Properties properties)
                throws SQLClientInfoException {
            connection.setClientInfo(properties);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void setClientInfo(String name, String value)
                throws SQLClientInfoException {
            connection.setClientInfo(name, value);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void setHoldability(int holdability) throws SQLException {
            connection.setHoldability(holdability);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void setNetworkTimeout(Executor executor, int milliseconds)
                throws SQLException {
            connection.setNetworkTimeout(executor, milliseconds);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void setReadOnly(boolean readOnly) throws SQLException {
            connection.setReadOnly(readOnly);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Savepoint setSavepoint() throws SQLException {
            return connection.setSavepoint();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Savepoint setSavepoint(String name) throws SQLException {
            return connection.setSavepoint(name);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void setSchema(String schema) throws SQLException {
            connection.setSchema(schema);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void setTransactionIsolation(int level) throws SQLException {
            connection.setTransactionIsolation(level);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void setTypeMap(Map<String, Class<?>> map) throws SQLException {
            connection.setTypeMap(map);
        }
    }
}
