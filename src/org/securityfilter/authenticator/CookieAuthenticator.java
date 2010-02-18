package org.securityfilter.authenticator;

import java.io.IOException;
import java.security.Principal;
import javax.servlet.FilterConfig;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.securityfilter.config.SecurityConfig;
import org.securityfilter.filter.SecurityFilter;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.filter.URLPattern;
import org.securityfilter.filter.URLPatternFactory;
import org.securityfilter.filter.URLPatternMatcher;
import org.securityfilter.realm.SecurityRealmInterface;

/**
 * The authenticator implemented for the configuration "COOKIE_WITH_ID".
 * This authenticator passes the information stored in a cookie (named "AuthInfo") and puts it in the username for authentication handled by the realm.
 * @author Meine Toonen
 */
public class CookieAuthenticator implements Authenticator {

    protected SecurityRealmInterface realm;
    protected String realmName;
    protected String loginPage;
    protected URLPattern loginPagePattern;
    protected URLPattern logoutPagePattern;
    protected URLPattern errorPagePattern;
    protected String errorPage;
    public static final String AUTH_METHOD = "COOKIE";

    /**
     * Process the login information stored in the cookie, named "AuthInfo". The value is stored in the username of the authenticate(user,password) method of the realm. The password is
     * kept empty. If the principal returned by the realm is null, the user is redirected to the errorpage.
     *  
     * @param request
     * @param response
     * @return true if the filter should return after this method ends, false otherwise
     */
    public boolean processLogin(SecurityRequestWrapper request, HttpServletResponse response) throws Exception {
        if (request.getUserPrincipal() == null) {
            // attempt to dig out authentication info only if the user has not yet been authenticated
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {

                Cookie authCookie = null;
                for (int i = 0; i < cookies.length; i++) {
                    Cookie cookie = cookies[i];
                    if (cookie.getName().equals("AuthInfo")) {
                        authCookie = cookie;
                        break;
                    }
                }
                if (authCookie != null) {
                    String username = authCookie.getValue();
                    Principal principal = realm.authenticate(username, "");
                    if (principal != null) {
                        // login successful
                        //request.getSession().removeAttribute(LOGIN_ATTEMPTS);
                        request.setUserPrincipal(principal);
                    } else {
                        //request.getRequestDispatcher(errorPage).forward(request, response);
                        showError(request,response);
                        return true;
                    }
                } else {
                    return false;
                }
            }
        }
        return false;
    }

    public boolean processLogout(SecurityRequestWrapper request, HttpServletResponse response, URLPatternMatcher patternMatcher) throws Exception {
        return false;
    }

    /**
     * Redirects to the login page.
     * @param request
     * @param response
     * @throws IOException
     */
    public void showLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // save this request
        SecurityFilter.saveRequestInformation(request);
        response.sendRedirect(response.encodeRedirectURL(loginPage));
    }

    private void showError(SecurityRequestWrapper request, HttpServletResponse response) throws IOException{
        response.sendRedirect(response.encodeRedirectURL(errorPage));
    }

    public String getAuthMethod() {
        return AUTH_METHOD;
    }

    /**
     * Initialises the parameters needed for this authenticator
     * @param filterConfig
     * @param securityConfig
     * @throws Exception
     */
    public void init(FilterConfig filterConfig, SecurityConfig securityConfig) throws Exception {
        realm = securityConfig.getRealm();
        realmName = securityConfig.getRealmName();

        URLPatternFactory patternFactory = new URLPatternFactory();
        loginPage = securityConfig.getLoginPage();
        loginPagePattern = patternFactory.createURLPattern(stripQueryString(loginPage), null, null, 0);

        // error page
        errorPage = securityConfig.getErrorPage();
        errorPagePattern = patternFactory.createURLPattern(stripQueryString(errorPage), null, null, 0);
    }

    /**
     * Controls which pages must be visible without authorisation (login, error and logout)
     * @param request
     * @param patternMatcher
     * @return
     * @throws Exception
     */
    public boolean bypassSecurityForThisRequest(
            SecurityRequestWrapper request,
            URLPatternMatcher patternMatcher) throws Exception {
        String requestURL = request.getMatchableURL();
        return (patternMatcher.match(requestURL, loginPagePattern) || patternMatcher.match(requestURL, errorPagePattern) || matchesLogoutPattern(requestURL, patternMatcher));
    }

    /**
     * Utility method to strip the query string from a uri.
     *
     * @param uri
     * @return uri with query string removed (if it had one)
     */
    private String stripQueryString(String uri) {
        if (uri != null) {
            int queryStart = uri.indexOf('?');
            if (queryStart != -1) {
                uri = uri.substring(0, queryStart);
            }
        }
        return uri;
    }

    /**
     * Returns true if the logout pattern is not null and the request URL string passed in matches it.
     *
     * @param requestURL
     * @param patternMatcher
     * @return true if the logout page is defined and the request URL matches it
     * @throws Exception
     */
    private boolean matchesLogoutPattern(String requestURL, URLPatternMatcher patternMatcher) throws Exception {
        if (logoutPagePattern != null) {
            return patternMatcher.match(requestURL, logoutPagePattern);
        }
        return false;
    }
}