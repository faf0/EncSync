package configuration;

import java.util.LinkedList;
import java.util.List;

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
 * Represents and manages permissions of a folder.
 * 
 * @author Fabian Foerg
 */
public final class Permission {
    /**
     * Permission "readable by public".
     */
    public static final Permission PUBLIC = new Permission("public",
            PermissionValue.READ_HISTORY);

    /**
     * Delimits (member, permission) pairs in a permission string.
     */
    public static final String MEMBER_DELIMITER = "/";
    /**
     * Delimits the member name from the member permissions in a (member,
     * permission) pair.
     */
    public static final String MEMBER_PERMISSION_DELIMITER = ":";

    /**
     * Represents a permission value.
     * 
     * @author Fabian Foerg
     */
    public static enum PermissionValue {
        READ_ONLY("r"),
        READ_HISTORY("rh"),
        READ_WRITE_HISTORY("rwh");

        private final String permission;

        private PermissionValue(String permission) {
            this.permission = permission;
        }

        @Override
        public String toString() {
            return permission;
        }

        public static PermissionValue fromString(String permission) {
            if (permission == null) {
                return null;
            } else if (READ_ONLY.toString().equals(permission)) {
                return READ_ONLY;
            } else if (READ_HISTORY.toString().equals(permission)) {
                return READ_HISTORY;
            } else if (READ_WRITE_HISTORY.toString().equals(permission)) {
                return READ_WRITE_HISTORY;
            } else {
                return null;
            }
        }
    }

    private final String member;
    private final PermissionValue permissions;

    /**
     * Creates a new permission with the given parameters.
     * 
     * @param member
     *            the corresponding member.
     * @param permissions
     *            the permissions for the member.
     */
    public Permission(String member, PermissionValue permissions) {
        if (!ClientConfiguration.isValidUserName(member)) {
            throw new IllegalArgumentException("member must be valid!");
        }
        if (permissions == null) {
            throw new NullPointerException("permissions may not be null!");
        }

        this.member = member;
        this.permissions = permissions;
    }

    /**
     * Returns the corresponding member.
     * 
     * @return the corresponding member.
     */
    public String getMember() {
        return member;
    }

    /**
     * Returns the permission values.
     * 
     * @return the permission values.
     */
    public PermissionValue getPermissions() {
        return permissions;
    }

    /**
     * Returns whether this user is allowed to write data.
     * 
     * @return <code>true</code>, if the user has write access.
     *         <code>false</code>, otherwise.
     */
    public boolean mayWrite() {
        return PermissionValue.READ_WRITE_HISTORY.equals(permissions);
    }

    /**
     * Returns whether this user is allowed to access the history.
     * 
     * @return <code>true</code>, if the user has history access.
     *         <code>false</code>, otherwise.
     */
    public boolean mayReadHistory() {
        return PermissionValue.READ_HISTORY.equals(permissions)
                || PermissionValue.READ_WRITE_HISTORY.equals(permissions);
    }

    /**
     * Parses the given permission string for permissions.
     * 
     * @param permissionsString
     *            the permission string to parse.
     * @return an array containing the parsed permissions or an empty array. If
     *         a permission cannot be parsed, <code>null</code> is returned.
     */
    public static Permission[] parsePermissions(String permissionsString) {
        List<Permission> permissionList = new LinkedList<Permission>();
        boolean permissionsValid = true;

        if ((permissionsString != null) && !"".equals(permissionsString.trim())) {
            // try to parse the permissionsString
            String[] membersAndPermission = permissionsString
                    .split(MEMBER_DELIMITER);

            for (String memberAndPermission : membersAndPermission) {
                String[] splitted = memberAndPermission
                        .split(MEMBER_PERMISSION_DELIMITER);

                if ((splitted != null) && (splitted.length == 2)
                        && ClientConfiguration.isValidUserName(splitted[0])) {
                    PermissionValue permissionValue = PermissionValue
                            .fromString(splitted[1]);

                    if (permissionValue != null) {
                        Permission current = new Permission(splitted[0],
                                permissionValue);
                        permissionList.add(current);
                    } else {
                        permissionsValid = false;
                        break;
                    }
                } else {
                    permissionsValid = false;
                    break;
                }
            }
        }

        return (permissionsValid) ? permissionList.toArray(new Permission[0])
                : null;
    }

    /**
     * Creates a permission string from the given permissions.
     * 
     * @param permissions
     *            the permissions for which the permission string should be
     *            created.
     * @return <code>null</code>, if the given permissions are <code>null</code>
     *         or empty. Otherwise, a permission string is returned.
     */
    public static String toPermissionString(Permission[] permissions) {
        if ((permissions != null) && (permissions.length >= 1)) {
            StringBuilder builder = new StringBuilder();

            for (int i = 0; i < permissions.length; i++) {
                builder.append(permissions[i].getMember());
                builder.append(MEMBER_PERMISSION_DELIMITER);
                builder.append(permissions[i].getPermissions());

                if (i < (permissions.length - 1)) {
                    builder.append(MEMBER_DELIMITER);
                }
            }

            return builder.toString();
        } else {
            return null;
        }
    }

    /**
     * Returns whether the given Permission is equal to this Permission.
     * 
     * @return <code>true</code>, if the Permission instances are equal.
     *         Otherwise, <code>false</code>.
     */
    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        } else if (o instanceof Permission) {
            return ((Permission) o).getMember().equals(member)
                    && ((Permission) o).getPermissions().equals(permissions);
        } else {
            return false;
        }
    }
}
