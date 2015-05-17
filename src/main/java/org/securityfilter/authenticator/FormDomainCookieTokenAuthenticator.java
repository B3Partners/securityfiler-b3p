/**
 * $Id$
 */

package org.securityfilter.authenticator;

import java.io.IOException;
import java.security.Principal;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterConfig;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.securityfilter.config.SecurityConfig;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.filter.URLPatternMatcher;
import org.securityfilter.realm.ExternalAuthenticatedRealm;

/**
 * Idem als FormAuthenticator, maar zet na de login een cookie voor andere webapps
 * op hetzelfde domein met login info. Deze login info kan door webapps met
 * een secret key worden gedecrypt en daarmee de gebruiker inloggen.
 */
public class FormDomainCookieTokenAuthenticator extends FormAuthenticator {
    private final static Log log = LogFactory.getLog(FormDomainCookieTokenAuthenticator.class);

    protected final static String AUTH_TOKEN_COOKIE_PRINCIPAL = FormDomainCookieTokenAuthenticator.class.getName() + ".AUTH_TOKEN_COOKIE_PRINCIPAL";
    protected final static String AUTHORIZED_BY_AUTH_TOKEN = FormDomainCookieTokenAuthenticator.class.getName() + ".AUTHORIZED_BY_AUTH_TOKEN";
    protected final static String COOKIE_NAME = "AuthToken";
    protected final static String CHARSET = "US-ASCII";

    protected final static String encryptionAlgorithm = "AES";

    /**
     * Key waarmee het cookie wordt encrypt/decrypt.
     */
    protected SecretKey secretKey;

    /**
     * String die wordt toegevoegd aan het cookie voor het hashen, dit om de
     * geldigheid van de gedecypte waardes te controleren.
     */
    protected String extraHashString;

    /**
     * Paden waarvoor cookies moeten worden gezet.
     */
    protected String[] cookiePaths;

    /**
     * Aantal seconden dat het auth token cookie geldig is
     */
    protected int cookieExpire;

    /**
     * Of na inloggen cookies moeten worden gemaakt.
     */
    protected boolean setCookies;

    /**
     * Of voor inloggen gechecked moet worden of er een geldig auth token cookie
     * aanwezig is.
     */
    protected boolean acceptCookie;

    public void init(FilterConfig filterConfig, SecurityConfig securityConfig) throws Exception {
        super.init(filterConfig, securityConfig);

        /* lees configuratie uit */

        setCookies = securityConfig.isSetCookies();
        acceptCookie = securityConfig.isAcceptCookie();

        if(acceptCookie && !(securityConfig.getRealm() instanceof ExternalAuthenticatedRealm)) {
            throw new IllegalArgumentException("Security realm must implement ExternalAuthenticatedRealm to accept auth token cookies");
        }

        String secretKeyHex = securityConfig.getSecretKey();
        log.info("secrey key hex length: " + secretKeyHex.length());
        setEncryptionKey(new Hex().decode(secretKeyHex.getBytes(CHARSET)));

        extraHashString = securityConfig.getExtraHashString();

        if(setCookies) {
            cookiePaths = securityConfig.getCookiePaths().split(";");
            for(int i = 0; i < cookiePaths.length; i++) {
                cookiePaths[i] = cookiePaths[i].trim();
            }

            cookieExpire = securityConfig.getCookieExpire();
        }
    }

    /** Wrapper voor HttpServletResponse die het response object voor het
     * aanroepen van de super-methode, omdat na het aanroepen van
     * response.sendRedirect() geen cookies meer kunnen worden toegevoegd.
     */
    private class DelayRedirectHttpServletResponseWrapper extends HttpServletResponseWrapper {
        private String redirectLocation = null;

        public DelayRedirectHttpServletResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        public void sendRedirect(String location) {
            /* sla alleen het argument van de eerste aanroep op */
            if(this.redirectLocation == null) {
                this.redirectLocation = location;
            }
        }

        /**
         * Geeft null indien geen sendRedirect() op de wrapper is aangeroepen,
         * of het location argument voor de sendRedirect() aanroep indien
         * wel.
         */
        public String getRedirectLocation() {
            return this.redirectLocation;
        }

        public void sendDelayedRedirect() throws IOException {
            if(this.redirectLocation != null) {
                super.sendRedirect(getRedirectLocation());
            }
        }
    }

    public boolean processLogin(SecurityRequestWrapper request, HttpServletResponse response) throws Exception {

        /* Indien acceptCookies en er is nog geen principal, check of er een
         * geldig auth token cookie aanwezig is voordat de super methode wordt
         * aangeroepen.
         *
         * Dit stukje code lijkt erg op het eerste stuk in de super-methode
         * welke persistant login checked.
         */

        boolean loggedInByToken = false;

        if(acceptCookie) {
            if(Boolean.TRUE.equals(request.getSession().getAttribute(AUTHORIZED_BY_AUTH_TOKEN))) {
                loggedInByToken = true;
            } else if(request.getRemoteUser() == null) {
                Cookie[] cookies = request.getCookies();
                if(cookies != null) {
                    for(int i = 0; i < cookies.length; i++) {
                        if(COOKIE_NAME.equals(cookies[i].getName())) {
                            Principal authTokenPrincipal = getAuthTokenPrincipal(request, cookies[i]);
                            if(authTokenPrincipal != null) {
                                request.setUserPrincipal(authTokenPrincipal);
                                request.getSession().setAttribute(AUTHORIZED_BY_AUTH_TOKEN, Boolean.TRUE);
                                log.info("user " + request.getRemoteUser() + " logged in by auth token cookie (" + cookies[i].getValue() + ")");
                                loggedInByToken = true;
                            }
                            break;
                        }
                    }
                }
            }
        }

        if(!setCookies || loggedInByToken) {
            /* geen speciale processing, roep alleen super-methode aan */
            return super.processLogin(request, response);
        } else {

            /* Check na het aanroepen van de super-methode of er een principal
             * is waarvoor we een cookie moeten zetten.
             */

            /* Zorg er wel voor dat eventuele redirects niet direct worden
             * verstuurd, want dan is het niet meer mogelijk om cookies aan het
             * request toe te voegen.
             */
            DelayRedirectHttpServletResponseWrapper wrappedResponse = new DelayRedirectHttpServletResponseWrapper(response);

            boolean processLogin = super.processLogin(request, wrappedResponse);
            /* indien gebruiker is ingelogd en eerder nog geen cookie is gezet,
             * voeg cookie toe.
             */
            if(request.getUserPrincipal() != null && request.getUserPrincipal() != request.getSession().getAttribute(AUTH_TOKEN_COOKIE_PRINCIPAL)) {
                request.getSession().setAttribute(AUTH_TOKEN_COOKIE_PRINCIPAL, request.getUserPrincipal());

                setAuthTokenCookies(request, response);
            }

            /* verwijder eventueel bestaand cookie indien niet ingelogd */
            if(request.getUserPrincipal() == null && request.getSession().getAttribute(AUTH_TOKEN_COOKIE_PRINCIPAL) != null) {
                removeCookies(request, response);
                request.getSession().removeAttribute(AUTH_TOKEN_COOKIE_PRINCIPAL);
            }

            /* Indien door de super-methode sendRedirect() was aangeroepen op de
             * wrapper, doe dit nu op de originele response (nadat hierboven
             * eventueel cookies zijn toegevoegd).
             */
            wrappedResponse.sendDelayedRedirect();
            return processLogin;
        }
   }

    private void setAuthTokenCookies(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String username = request.getParameter(FORM_USERNAME);
        String password = request.getParameter(FORM_PASSWORD);
        
        if(log.isDebugEnabled()) {
        	log.debug("set AuthToken cookie(s) for user: " + username);
		}

        /* Maak voor elk path een cookie aan */
        for(int i = 0; i < cookiePaths.length; i++) {
            String path = cookiePaths[i];
            /* De inhoud van het cookie is het path (om te checken met het path
             * van het cookie in het request, zodat niet door het veranderen
             * van het path iemand op een webapp kan inloggen terwijl dat niet
             * bedoeld is), username, password,  geldigheidsduur en huidige tijd
             * (om geldigheidsduur van het token te controleren).
             */
            
            String value = System.currentTimeMillis() 
                    + ";" + cookieExpire
                    + ";" + username
                    + ";" + password
                    + ";" + path;

            /* Voeg een extra waarde toe zodat met behulp van een hash de
             * geldigheid kan worden gecontroleerd.
             */
            value = value + ";" + DigestUtils.shaHex((value + ";" + extraHashString).getBytes(CHARSET));

            String encryptedValue = encryptText(value, getCipherParameters(), secretKey, CHARSET);
            /* Verwijder eventuele \r\n karakters die door Commons-Codec 1.4
             * zijn toegevoegd. Deze zijn niet toegestaan in een cookie.
             */
            encryptedValue = encryptedValue.replaceAll("[\r\n]", "");
            log.debug("settting auth token cookie value (len=" + value.length() + "): " + value + " - encrypted: (len=" + encryptedValue.length() + "): " + encryptedValue);

            Cookie token = new Cookie(COOKIE_NAME, encryptedValue);
            token.setPath(path);
            token.setMaxAge(cookieExpire);
            response.addCookie(token);
        }
    }

    private Principal getAuthTokenPrincipal(SecurityRequestWrapper request, Cookie authToken) throws Exception {
        String value = authToken.getValue();

        /* Decrypt cookie */
        try {
            value = decryptText(value, getCipherParameters(), secretKey, CHARSET);
        } catch(Exception e) {
            log.info("Not accepting auth token cookie because of exception during decryption: " + e.getClass() + ": " + e.getMessage());;
            log.debug("Exception decrypting auth token cookie", e);
            return null;
        }

        String[] fields = value.split(";");
        if(fields.length != 6) {
            log.warn("invalid auth token cookie (invalid field count: " + fields.length + ")");
            return null;
        }
        long cookieSetTime = -1;
        int cookieExpire = -1;
        try {
            cookieSetTime = Long.parseLong(fields[0]);
            cookieExpire = Integer.parseInt(fields[1]);
        } catch(NumberFormatException nfe) {
            log.warn("invalid auth token cookie, wrong number format");
            return null;
        }
        String username = fields[2];
        String password = fields[3];
        String path = fields[4];
        String hash = fields[5];

        if(!request.getContextPath().equals(path)) {
            log.warn("auth token cookie path invalid: " + path);
            return null;
        }

        String hashInput = cookieSetTime + ";" + cookieExpire + ";" + username + ";" + password + ";" + path + ";" + extraHashString;
        String hashed = DigestUtils.shaHex(hashInput.getBytes(CHARSET));

        if(!hashed.equals(hash)) {
            log.warn("auth token cookie hash mismatch: input=" + hashInput + "; hashed=" + hashed + "; cookie hash=" + fields[4]);
            return null;
        }

        log.info("accepting auth token cookie for user " + username);

        return ((ExternalAuthenticatedRealm)realm).getAuthenticatedPrincipal(username, password);
    }

    private String getCipherParameters() {
        return encryptionAlgorithm;
    }

   /**
    * Encrypt a string.
    *
    * @param clearText
    * @return clearText, encrypted
    */
    private String encryptText(String clearText, String cipherParameters, SecretKey secretKey, String charset) throws Exception {
        Base64 encoder = new Base64();
        Cipher c1 = Cipher.getInstance(cipherParameters);
        c1.init(Cipher.ENCRYPT_MODE, secretKey);
        byte clearTextBytes[];
        clearTextBytes = clearText.getBytes();
        byte encryptedText[] = c1.doFinal(clearTextBytes);
        String encryptedEncodedText = new String(encoder.encode(encryptedText), charset);
        return encryptedEncodedText;
    }

    /**
     * Decrypt a string.
     *
     * @param encryptedText
     * @return encryptedText, decrypted
     */
    private static String decryptText(String encryptedText, String cipherParameters, SecretKey secretKey, String charset) throws Exception {
        Base64 decoder = new Base64();
        byte decodedEncryptedText[] = decoder.decode(encryptedText.getBytes(charset));
        Cipher c1 = Cipher.getInstance(cipherParameters);
        c1.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedText = c1.doFinal(decodedEncryptedText);
        String decryptedTextString = new String(decryptedText);
        return decryptedTextString;
    }

    private void removeCookies(HttpServletRequest request, HttpServletResponse response) {
		if(log.isDebugEnabled()) {
        	log.debug("removing AuthToken cookies in request: " + request.getRequestURI());
		}
        for(int i = 0; i < cookiePaths.length; i++) {
            Cookie expired = new Cookie(COOKIE_NAME, "none");
            expired.setPath(cookiePaths[i]);
            expired.setMaxAge(0);
            response.addCookie(expired);
        }
    }

    public boolean processLogout(SecurityRequestWrapper request, HttpServletResponse response, URLPatternMatcher patternMatcher) throws Exception {
        boolean processLogout = super.processLogout(request, response, patternMatcher);

        if(processLogout) {
            if(request.getSession().getAttribute(AUTH_TOKEN_COOKIE_PRINCIPAL) != null) {
                removeCookies(request, response);
                request.getSession().removeAttribute(AUTH_TOKEN_COOKIE_PRINCIPAL);
            }

            /* indien auth token geaccepteerd is, verwijder dat cookie voor ons
             * path
             */
            if(Boolean.TRUE.equals(request.getSession().getAttribute(AUTHORIZED_BY_AUTH_TOKEN))) {
                log.debug("processLogout(): principal was authorized by auth token cookie, removing cookie");
                Cookie authToken = new Cookie(COOKIE_NAME, "none");
                authToken.setPath(request.getContextPath());
                authToken.setMaxAge(0);
                response.addCookie(authToken);
            }

        }
        return processLogout;
    }

    private void setEncryptionKey(byte[] encryptionkey) throws Exception {
        secretKey = new SecretKeySpec(encryptionkey, encryptionAlgorithm);    
    }
}