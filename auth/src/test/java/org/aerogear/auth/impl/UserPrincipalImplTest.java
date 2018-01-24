package org.aerogear.auth.impl;

import org.aerogear.auth.AbstractAuthenticator;
import org.aerogear.auth.AuthServiceConfig;
import org.aerogear.auth.ClientRole;
import org.aerogear.auth.IRole;
import org.aerogear.auth.RealmRole;
import org.aerogear.auth.RoleType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class UserPrincipalImplTest {
    private UserPrincipalImpl userPrincipalImpl;

    @Before
    public void setUp(){
        AuthServiceConfig authServiceConfig = new AuthServiceConfig();
        AbstractAuthenticator abstractAuthenticator = new AbstractAuthenticator(authServiceConfig);
        ClientRole cRole = new ClientRole("cRole");
        RealmRole rRole = new RealmRole("rRole");
        IRole[] roles = {cRole, rRole};
        userPrincipalImpl = UserPrincipalImpl.newUser().withRoles(roles).withAuthenticator(abstractAuthenticator).build();
    }

    @After
    public void tearDown(){
        userPrincipalImpl = null;
    }

    @Test
    public void testHasRoleFails(){
        assertEquals(userPrincipalImpl.hasRole("rRole", RoleType.CLIENT), false);
        assertEquals(userPrincipalImpl.hasRole("notRole", RoleType.REALM), false);
    }

    @Test
    public void testHasRoleSucceeds(){
        assertEquals(userPrincipalImpl.hasRole("cRole", RoleType.CLIENT), true);
       assertEquals(userPrincipalImpl.hasRole("rRole", RoleType.REALM), true);

    }
}
