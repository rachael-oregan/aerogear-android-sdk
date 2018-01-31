package org.aerogear.auth.impl;

import org.aerogear.auth.AbstractAuthenticator;
import org.aerogear.auth.AuthServiceConfig;
import org.aerogear.auth.AuthenticationException;
import org.aerogear.auth.credentials.ICredential;
import org.aerogear.auth.credentials.OIDCCredentials;

import java.security.Principal;

/**
 * Authenticates token credentials
 */
public class OIDCTokenAuthenticatorImpl extends AbstractAuthenticator {
    public OIDCTokenAuthenticatorImpl(final AuthServiceConfig config) {
        super(config);
    }

    @Override
    public Principal authenticate(ICredential credential) throws AuthenticationException {
        if (credential instanceof OIDCCredentials) {
            // Authenticate the credential
            throw new IllegalStateException("Not implemented");
        }
        // This authenticator can't manage this type of credential
        throw new IllegalArgumentException("Invalid Credential");

    }
}
