package org.aerogear.auth;

/**
 * Created by rachael on 25/01/2018.
 */

public class RoleKey {

    private String roleName;
    private RoleType roleType;

    public RoleKey(IRole role) {
        roleName = role.getRoleName();
        roleType = role instanceof RealmRole ? RoleType.REALM : RoleType.CLIENT;
    }

    @Override
    public boolean equals(Object roleKey) {
        if (this == roleKey) return true;
        if (roleKey == null || roleKey.getClass() != getClass()) return false;
        return ((RoleKey) roleKey).roleName == roleName && ((RoleKey) roleKey).roleType == roleType;
    }

}
