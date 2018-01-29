package org.aerogear.auth;

/**
 * Created by rachael on 25/01/2018.
 */

public class RoleKey {

    private String roleName;
    private RoleType roleType;
    private String clientID;

    public RoleKey(final IRole role, final String clientID) {
        roleName = role.getRoleName();
        roleType = role.getRoleType();
        this.clientID = clientID;
    }

    @Override
    public boolean equals(final Object roleKey) {
        if (this == roleKey) return true;
        if (roleKey == null || roleKey.getClass() != getClass()) return false;
        if (((RoleKey) roleKey).roleType == RoleType.CLIENT) { //do a check on clientID
            return ((RoleKey) roleKey).roleName.equals(roleName) && ((RoleKey) roleKey).roleType == roleType &&
                ((RoleKey) roleKey).clientID == clientID;
        } else {
            return ((RoleKey) roleKey).roleName.equals(roleName) && ((RoleKey) roleKey).roleType == roleType;
        }
    }
}
