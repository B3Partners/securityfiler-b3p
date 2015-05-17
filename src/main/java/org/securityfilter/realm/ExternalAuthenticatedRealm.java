/*
 * $Id$
 */

package org.securityfilter.realm;

import java.security.Principal;

public interface ExternalAuthenticatedRealm {
    /**
     * Get user that has been authenticated by external means (auth token cookie,
     * single sign on)
     */
    public Principal getAuthenticatedPrincipal(String username, String password);
}
