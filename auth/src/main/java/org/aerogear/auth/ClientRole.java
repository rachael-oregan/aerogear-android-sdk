package org.aerogear.auth;

public final class ClientRole extends AbstractRole {

    private final String clientID;

    public ClientRole(final String roleName, String clientID) {
        super(roleName);
        this.clientID = clientID;
    }

    @Override
    public RoleType getRoleType() {
        return RoleType.CLIENT;
    }

    @Override
    public String getClientID() {
        return clientID;
    }
}
