package org.aerogear.auth;

public final class RealmRole extends AbstractRole {
    public RealmRole(final String roleName) {
        super(roleName);
    }

    @Override
    public RoleType getRoleType() {
        return RoleType.REALM;
    }
}
