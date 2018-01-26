package org.aerogear.auth;

public final class ClientRole extends AbstractRole {
    public ClientRole(final String roleName) {
        super(roleName);
    }

    @Override
    public RoleType getRoleType() {
        return RoleType.CLIENT;
    }
}
