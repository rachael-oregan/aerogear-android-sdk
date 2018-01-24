package org.aerogear.auth.impl;

import org.aerogear.auth.AbstractAuthenticator;
import org.aerogear.auth.AuthenticationException;
import org.aerogear.auth.IRole;
import org.aerogear.auth.credentials.ICredential;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

/**
 * Simple authenticator to return 'guest' users.
 * No authentication is performed at all.
 */
public class GuestAuthenticatorImpl extends AbstractAuthenticator {

    /**
     * The 'guest' username to return.
     */
    private final String guestUser;

    /**
     * Roles to be assigned to the guest user
     */
    private final List<IRole> roles;

    /**
     * Builds a new guest authenticator object
     * @param guestUser the user to be returned after the 'authentication'
     * @param roles the roles to be assigned to the user
     */
    public GuestAuthenticatorImpl(final String guestUser, final List<IRole> roles) {
        super(null);
        this.guestUser = guestUser;
        this.roles = new ArrayList<>();
        if (roles != null) {
            this.roles.addAll(roles);
        }
    }

    /**
     * Simply returns a user with username {@link #guestUser}
     * @param credential user credential
     * @return a user with username {@link #guestUser}
     * @throws AuthenticationException
     */
    public Principal authenticate(final ICredential credential) {
        return UserPrincipalImpl
                .newUser()
                .withAuthenticator(this)
                .withUsername(guestUser)
                .withRoles(roles)
                .build();
    }

    @Override
    public void logout(Principal principal) {
        return;
    }
}
