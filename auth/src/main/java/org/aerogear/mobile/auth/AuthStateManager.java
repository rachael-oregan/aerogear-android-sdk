package org.aerogear.mobile.auth;

import static org.aerogear.mobile.core.utils.SanityCheck.nonNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.NoSuchPaddingException;

import android.content.Context;
import android.content.SharedPreferences;

import org.aerogear.mobile.auth.credentials.OIDCCredentials;

import devliving.online.securedpreferencestore.DefaultRecoveryHandler;
import devliving.online.securedpreferencestore.SecuredPreferenceStore;

/**
 * Saves, retrieves and delete a token.
 */
public class AuthStateManager {

    private static AuthStateManager instance = null;
    private static final String KEY_STATE = "state";

    private SecuredPreferenceStore prefs;

    private AuthStateManager(final Context context) {
        try {
            SecuredPreferenceStore.init(context, new DefaultRecoveryHandler());
            prefs = SecuredPreferenceStore.getSharedInstance();
        } catch (IOException | CertificateException | NoSuchAlgorithmException
                        | UnrecoverableEntryException | KeyStoreException | NoSuchPaddingException
                        | InvalidAlgorithmParameterException | NoSuchProviderException
                        | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    /**
     * Reads credentials from storage.
     *
     * @return OIDCCredentials
     */
    public OIDCCredentials load() {
        final String currentState = prefs.getString(KEY_STATE, null);
        if (currentState == null) {
            return new OIDCCredentials();
        }
        return OIDCCredentials.deserialize(currentState);
    }

    /**
     * Saves a token
     *
     * @param authState token to be saved
     * @throws IllegalStateException if the state can not be saved
     */
    public synchronized void save(final OIDCCredentials authState) {
        if (authState == null) {
            clear();
        } else {
            SharedPreferences.Editor e = prefs.edit().putString(KEY_STATE, authState.serialize());
            if (!e.commit()) {
                throw new IllegalStateException("Failed to update state from shared preferences");
            }
        }
    }

    /**
     * Deletes a token
     *
     * @throws IllegalArgumentException if the state can not be cleared
     */
    public synchronized void clear() {
        if (!prefs.edit().remove(KEY_STATE).commit()) {
            throw new IllegalStateException("Failed to clear state from shared preferences");
        }
    }

    static AuthStateManager getInstance(final Context context) {
        if (instance == null) {
            instance = new AuthStateManager(nonNull(context, "context"));
        }
        return instance;
    }

    public static AuthStateManager getInstance() {
        if (instance == null) {
            throw new IllegalStateException(
                            "Context has not previously been provided. Cannot initialize without Context.");
        }
        return instance;
    }
}
