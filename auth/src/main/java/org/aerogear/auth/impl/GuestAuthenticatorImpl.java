package org.aerogear.auth.impl;

import org.aerogear.auth.AbstractAuthenticator;
import org.aerogear.auth.AuthenticationException;
import org.aerogear.auth.IRole;
import org.aerogear.auth.RoleKey;
import org.aerogear.auth.credentials.ICredential;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
    private final Map<RoleKey, IRole> roles;

    /**
     * Builds a new guest authenticator object
     * @param guestUser the user to be returned after the 'authentication'
     * @param roles the roles to be assigned to the user
     */
    public GuestAuthenticatorImpl(final String guestUser, final Map<RoleKey, IRole> roles) {
        super(null);
        this.guestUser = guestUser;
        if (roles == null) {
            this.roles = new HashMap<RoleKey, IRole>();
        } else {
            this.roles = Collections.unmodifiableMap(new HashMap<RoleKey, IRole>(roles));
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
