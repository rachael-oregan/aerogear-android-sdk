package org.aerogear.auth.impl;

import android.util.Base64;

import org.aerogear.auth.AuthServiceConfig;
import org.aerogear.auth.AuthenticationException;
import org.aerogear.auth.ClientRole;
import org.aerogear.auth.IRole;
import org.aerogear.auth.RealmRole;
import org.aerogear.auth.RoleKey;
import org.aerogear.auth.credentials.ICredential;
import org.aerogear.auth.credentials.OIDCCredentials;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;


/**
 * Authenticates the user by using OpenID Connect.
 */
public class OIDCAuthCodeImpl extends OIDCTokenAuthenticatorImpl {

    private static final String USERNAME = "username";
    private static final String EMAIL = "email";
    private static final String REALM = "realm_access";
    private static final String CLIENT = "resource_access";
    private static final String ROLES = "roles";
    private static final String RESOURCE = "resource";
    private static final String COMMA = ",";

    private JSONObject userIdentity = new JSONObject();

    public OIDCAuthCodeImpl(final AuthServiceConfig config) {
        super(config);
    }

    /**
     * @param credential Ignored.
     * @return authenticated Principal
     */
    @Override
    public Principal authenticate(final ICredential credential) throws AuthenticationException {
        OIDCUserPrincipalImpl user;
        try {
            userIdentity = getIdentityInformation(credential);
           user = (OIDCUserPrincipalImpl) OIDCUserPrincipalImpl
                    .newUser()
                    .withAuthenticator(this)
                    .withUsername(parseUsername())
                    .withCredentials(credential)
                    .withEmail(parseEmail())
                    .withRoles(parseRoles())
                    .build();
        } catch (JSONException e) {
            throw new AuthenticationException(e.getMessage(), e.getCause());
        }
    return user;
    }

    private String parseUsername() throws JSONException {
        String username = "Unknown Username";
        if (userIdentity != null) {
            // get the users username
            if (userIdentity.has(USERNAME) && userIdentity.getString(USERNAME).length() > 0) {
                username = userIdentity.getString(USERNAME);
            }
        }
        return username;
    }

    private String parseEmail() throws JSONException {
        String emailAddress = "Unknown Email";
        if (userIdentity != null) {
            // get the users email
            if (userIdentity.has(EMAIL) && userIdentity.getString(EMAIL).length() > 0) {
                emailAddress = userIdentity.getString(EMAIL);
            }
        }
        return emailAddress;
    }

    private Collection<IRole> parseRoles() throws JSONException {
        Collection<IRole> roles = null;
        if (userIdentity != null) {
            Map<RoleKey, IRole> realmRoles = parseRealmRoles();
            if (realmRoles != null) {
                roles.addAll(realmRoles.values());
            }
            Map<RoleKey, IRole> clientRoles = parseClientRoles();
            if (clientRoles != null) {
                roles.addAll(realmRoles.values());
            }
        }
        return roles;
    }

    private Map<RoleKey, IRole> parseRealmRoles() throws JSONException {
        Map<RoleKey, IRole> realmRoles = new HashMap<>();
        if (userIdentity.has(REALM) && userIdentity.getJSONObject(REALM).has(ROLES)) {
            String tokenRealmRolesJSON = userIdentity.getJSONObject(REALM).getString(ROLES);

            String realmRolesString = tokenRealmRolesJSON.substring(1, tokenRealmRolesJSON.length() - 1);
            String roles[] = realmRolesString.split(COMMA);

            for (String rolename : roles) {
                RealmRole realmRole = new RealmRole(rolename);
                realmRoles.put(new RoleKey(realmRole, null), realmRole);
            }
        }
        return realmRoles;
    }

    private Map<RoleKey, IRole> parseClientRoles() throws JSONException {
        Map<RoleKey, IRole> clientRoles = new HashMap<>();

        AuthServiceConfig authConfig = this.getConfig();
        JSONObject authJSON =  authConfig.toJSON();

        if (authJSON.has(RESOURCE)) {
            String initialClientID = authJSON.getJSONObject(RESOURCE).toString();  //immediate client role

            if (userIdentity.has(CLIENT) && userIdentity.getJSONObject(CLIENT).has(initialClientID)
                    && userIdentity.getJSONObject(CLIENT).getJSONObject(initialClientID).has(ROLES)) {
                String tokenClientRolesJSON = userIdentity.getJSONObject(CLIENT).getJSONObject(initialClientID).getString(ROLES);

                String clientRolesString = tokenClientRolesJSON.substring(1, tokenClientRolesJSON.length() - 1);
                String roles[] = clientRolesString.split(COMMA);

                for (String rolename : roles) {
                    ClientRole clientRole = new ClientRole(rolename, initialClientID);
                    clientRoles.put(new RoleKey(clientRole, initialClientID), clientRole);
                }
            }
        }
        return clientRoles;
    }

    private JSONObject getIdentityInformation(final ICredential credential) throws JSONException, AuthenticationException {
        String accessToken = ((OIDCCredentials) credential).getAccessToken();
        JSONObject decodedIdentityData = new JSONObject();

        try {
            // Decode the Access Token to Extract the Identity Information
            String[] splitToken = accessToken.split("\\.");
            byte[] decodedBytes = Base64.decode(splitToken[1], Base64.URL_SAFE);
            String decoded = new String(decodedBytes, "UTF-8");
            try {
                decodedIdentityData = new JSONObject(decoded);
            } catch (JSONException e) {
                throw new AuthenticationException(e.getMessage(), e.getCause());
            }

        } catch (UnsupportedEncodingException e) {
            throw new AuthenticationException(e.getMessage(), e.getCause());
        }
        return decodedIdentityData;

    }
}
