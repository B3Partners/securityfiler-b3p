/*
 * $Header: /cvsroot/securityfilter/securityfilter/src/share/org/securityfilter/authenticator/FormAuthenticator.java,v 1.11 2005/02/22 11:02:16 maxcooper Exp $
 * $Revision$
 * $Date$
 *
 * ====================================================================
 * The SecurityFilter Software License, Version 1.1
 *
 * (this license is derived and fully compatible with the Apache Software
 * License - see http://www.apache.org/LICENSE.txt)
 *
 * Copyright (c) 2002 SecurityFilter.org. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by
 *        SecurityFilter.org (http://www.securityfilter.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The name "SecurityFilter" must not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *    For written permission, please contact license@securityfilter.org .
 *
 * 5. Products derived from this software may not be called "SecurityFilter",
 *    nor may "SecurityFilter" appear in their name, without prior written
 *    permission of SecurityFilter.org.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE SECURITY FILTER PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 */

package org.securityfilter.authenticator;

import org.securityfilter.authenticator.persistent.PersistentLoginManagerInterface;
import org.securityfilter.config.SecurityConfig;
import org.securityfilter.filter.*;
import org.securityfilter.realm.SecurityRealmInterface;
import org.securityfilter.realm.FlexibleRealmInterface;

import javax.servlet.FilterConfig;
import javax.servlet.http.*;
import java.io.IOException;
import java.security.Principal;

/**
 * FormAuthenticator - authenticator implementation for the FORM auth method.
 *
 * @author Max Cooper (max@maxcooper.com)
 * @version $Revision$ $Date$
 */
public class FormAuthenticator implements Authenticator {

   public static final String LOGIN_SUBMIT_PATTERN_KEY = "loginSubmitPattern";
   public static final String DEFAULT_LOGIN_SUBMIT_PATTERN = "/j_security_check";
   protected String loginSubmitPattern;

   protected static final String FORM_USERNAME = "j_username";
   protected static final String FORM_PASSWORD = "j_password";
   protected static final String FORM_REMEMBERME = "j_rememberme";

   protected String loginPage;
   protected URLPattern loginPagePattern;
   protected String errorPage;
   protected URLPattern errorPagePattern;
   protected String defaultPage;

   protected PersistentLoginManagerInterface persistentLoginManager;
   protected URLPattern logoutPagePattern;

   protected SecurityRealmInterface realm;

   /**
    * Initilize this Authenticator.
    *
    * @param filterConfig
    * @param securityConfig
    */
   public void init(FilterConfig filterConfig, SecurityConfig securityConfig) throws Exception {

      realm = securityConfig.getRealm();

      // login submit pattern
      loginSubmitPattern = filterConfig.getInitParameter(LOGIN_SUBMIT_PATTERN_KEY);
      if (loginSubmitPattern == null) {
         loginSubmitPattern = DEFAULT_LOGIN_SUBMIT_PATTERN;
      }

      // default page
      defaultPage = securityConfig.getDefaultPage();

      URLPatternFactory patternFactory = new URLPatternFactory();

      // login page
      loginPage = securityConfig.getLoginPage();
      loginPagePattern = patternFactory.createURLPattern(stripQueryString(loginPage), null, null, 0);

      // error page
      errorPage = securityConfig.getErrorPage();
      errorPagePattern = patternFactory.createURLPattern(stripQueryString(errorPage), null, null, 0);

      // -- Persistent Login Info --------------------------------------------------------------------------------------

      // logout page
      String logoutPage = securityConfig.getLogoutPage();
      if (logoutPage != null) {
         logoutPagePattern = patternFactory.createURLPattern(stripQueryString(logoutPage), null, null, 0);
      }

      // persistent login manager class
      persistentLoginManager = securityConfig.getPersistentLoginManager();
   }

   /**
    * Returns FORM as the authentication method.
    *
    * @return FORM
    */
   public String getAuthMethod() {
      return HttpServletRequest.FORM_AUTH;
   }

   /**
    * Process any login information that was included in the request, if any.
    * Returns true if SecurityFilter should abort further processing after the method completes (for example, if a
    * redirect was sent as part of the login processing).
    *
    * @param request
    * @param response
    * @return true if the filter should return after this method ends, false otherwise
    */
   public boolean processLogin(SecurityRequestWrapper request, HttpServletResponse response) throws Exception {

      // process any persistent login information, if user is not already logged in,
      // persistent logins are enabled, and the persistent login info is present in this request
      if (
         request.getRemoteUser() == null
         && persistentLoginManager != null
         && persistentLoginManager.rememberingLogin(request)
      ) {
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
         String username = request.getParameter(FORM_USERNAME);
         String password = request.getParameter(FORM_PASSWORD);
         Principal principal = realm instanceof FlexibleRealmInterface ?
            ((FlexibleRealmInterface) realm).authenticate(request)
            : realm.authenticate(username, password);
         if (principal != null) {
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
         } else {
            // login failed - forward to error page
            request.getRequestDispatcher(errorPage).forward(request, response);
         }
         return true;
      }

      return false;
   }

   /**
    * Show the login page.
    *
    * @param request the current request
    * @param response the current response
    */
   public void showLogin(
      HttpServletRequest request,
      HttpServletResponse response
   ) throws IOException {
      // save this request
      SecurityFilter.saveRequestInformation(request);

      // redirect to login page
      response.sendRedirect(response.encodeRedirectURL(request.getContextPath() + loginPage));
      return;
   }

   /**
    * Return true if this is a logout request.
    *
    * @param request
    * @param response
    * @param patternMatcher
    * @return true if this is a logout request, false otherwise
    */
   public boolean processLogout(
      SecurityRequestWrapper request,
      HttpServletResponse response,
      URLPatternMatcher patternMatcher
   ) throws Exception {
      String requestURL = request.getMatchableURL();
      // check if this is a logout request
      if (matchesLogoutPattern(requestURL, patternMatcher)) {
         // if remembering this login call forgetLogin() method to forget it
         if (persistentLoginManager != null && persistentLoginManager.rememberingLogin(request)) {
            persistentLoginManager.forgetLogin(request, response);
         }
         return true;
      }
      return false;
   }

   /**
    * The login and error pages should be viewable, even if they would otherwise be blocked by a security constraint.
    *
    * @param request
    * @return
    */
   public boolean bypassSecurityForThisRequest(
      SecurityRequestWrapper request,
      URLPatternMatcher patternMatcher
   ) throws Exception {
      String requestURL = request.getMatchableURL();
      return (
         patternMatcher.match(requestURL, loginPagePattern)
         || patternMatcher.match(requestURL, errorPagePattern)
         || matchesLogoutPattern(requestURL, patternMatcher)
      );
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

   /**
    * FormAuthenticator has a special case where the user should be sent to a default page if the user
    * spontaneously submits a login request.
    *
    * @param request
    * @return a URL to send the user to after logging in
    */
   private String getContinueToURL(HttpServletRequest request) {
      String savedURL = SecurityFilter.getContinueToURL(request);
      if (savedURL != null) {
         return savedURL;
      } else {
         return request.getContextPath() + defaultPage;
      }
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
}

// ------------------------------------------------------------------------
// EOF
