package org.securityfilter.authenticator;

import java.security.Principal;
import javax.security.auth.login.FailedLoginException;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.filter.URLPatternMatcher;
import org.securityfilter.realm.FlexibleRealmInterface;

/**
 * In addition to the standard form login, this ExtendedFormAuthenticator
 * puts into the HTTP session username (under the key j_username)
 * and the exception (under the key j_exception), when the login fails.
 * Thus, one can:
 * make the same page for the login and error page,
 * analyse, why the login has failed,
 * and prefill the username into the input field if the login has failed.
 */
public class ExtendedFormAuthenticator extends FormAuthenticator {

    public boolean processLogin(SecurityRequestWrapper request, HttpServletResponse response) throws Exception {

        // process any persistent login information, if user is not already logged in,
        // persistent logins are enabled, and the persistent login info is present in this request
        if (request.getRemoteUser() == null
                && persistentLoginManager != null
                && persistentLoginManager.rememberingLogin(request)) {
            String username = persistentLoginManager.getRememberedUsername(request, response);
            String password = persistentLoginManager.getRememberedPassword(request, response);
            Principal principal = realm.authenticate(username, password);
            if (principal != null) {
                request.setUserPrincipal(principal);
            } else {
                // failed authentication with remembered login, better forget login now
                persistentLoginManager.forgetLogin(request, response);
            }
        }

        // process login form submittal
        if (request.getMatchableURL().endsWith(loginSubmitPattern)) {

            HttpSession session = request.getSession();
            String username = request.getParameter(FORM_USERNAME);
            session.setAttribute("j_username", username);
            session.removeAttribute("j_exception");

            String password = request.getParameter(FORM_PASSWORD);

            try {
                Principal principal = realm instanceof FlexibleRealmInterface
                        ? ((FlexibleRealmInterface) realm).authenticate(request)
                        : realm.authenticate(username, password);
                if (principal == null) {
                    throw new FailedLoginException();
                }
                // login successful

                // invalidate old session if the user was already authenticated, and they logged in as a different user
                if (request.getUserPrincipal() != null
                        && false == request.getUserPrincipal().equals(principal)) {
                    request.getSession().invalidate();
                }

                // manage persistent login info, if persistent login management is enabled
                // and username/password are passed as part of logon
                if (persistentLoginManager != null
                        && username != null && password != null) {
                    String rememberme = request.getParameter(FORM_REMEMBERME);
                    // did the user request that their login be persistent?
                    if (rememberme != null) {
                        // remember login
                        persistentLoginManager.rememberLogin(request, response, username, password);
                    } else {
                        // forget login
                        persistentLoginManager.forgetLogin(request, response);
                    }
                }

                request.setUserPrincipal(principal);
                String continueToURL = getContinueToURL(request);
                // This is the url that the user was initially accessing before being prompted for login.
                response.sendRedirect(response.encodeRedirectURL(continueToURL));
            } catch (Exception e) {
                session.setAttribute("j_exception", e);
                // login failed - forward to error page
                request.getRequestDispatcher(errorPage).forward(request, response);
            }
            return true;
        }

        return false;
    }

    public boolean processLogout(
            SecurityRequestWrapper request,
            HttpServletResponse response,
            URLPatternMatcher patternMatcher) throws Exception {
        HttpSession session = request.getSession();
        session.removeAttribute("j_username");
        session.removeAttribute("j_exception");

        return super.processLogout(request, response, patternMatcher);
    }

    public String getAuthMethod() {
        return "EXTENDED_FORM";
    }
}
