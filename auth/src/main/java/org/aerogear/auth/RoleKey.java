package org.aerogear.auth;

/**
 * Created by rachael on 25/01/2018.
 */

public class RoleKey {

    private String roleName;
    private RoleType roleType;

    public RoleKey(final IRole role) {
        roleName = role.getRoleName();
        roleType = role.getRoleType();
    }

    @Override
    public boolean equals(final Object roleKey) {
        if (this == roleKey) return true;
        if (roleKey == null || roleKey.getClass() != getClass()) return false;
        return ((RoleKey) roleKey).roleName.equals(roleName) && ((RoleKey) roleKey).roleType == roleType;
    }

}
