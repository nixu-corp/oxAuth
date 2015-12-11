/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.client;

import org.apache.commons.lang.StringUtils;
import org.xdi.oxauth.model.common.AuthenticationMethod;
import org.xdi.oxauth.model.common.GrantType;
import org.xdi.oxauth.model.crypto.signature.ECDSAPrivateKey;
import org.xdi.oxauth.model.crypto.signature.RSAPrivateKey;
import org.xdi.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.xdi.oxauth.model.exception.InvalidJwtException;
import org.xdi.oxauth.model.jws.ECDSASigner;
import org.xdi.oxauth.model.jws.HMACSigner;
import org.xdi.oxauth.model.jws.RSASigner;
import org.xdi.oxauth.model.jwt.Jwt;
import org.xdi.oxauth.model.jwt.JwtType;
import org.xdi.oxauth.model.token.ClientAssertionType;
import org.xdi.oxauth.model.uma.UmaScopeType;

import javax.ws.rs.core.MediaType;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

/**
 * Represents a token request to send to the authorization server.
 *
 * @author Javier Rojas Blum Date: 10.17.2011
 */
public class TokenRequest extends BaseRequest {

    public static class Builder {

        private GrantType grantType;
        private String scope;

        public Builder grantType(GrantType grantType) {
            this.grantType = grantType;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder pat(String... scopeArray) {
            String scope = UmaScopeType.PROTECTION.getValue();
            if (scopeArray != null && scopeArray.length > 0) {
                for (String s : scopeArray) {
                    scope = scope + " " + s;
                }
            }
            return scope(scope);
        }

        public Builder aat(String... scopeArray) {
            String scope = UmaScopeType.AUTHORIZATION.getValue();
            if (scopeArray != null && scopeArray.length > 0) {
                for (String s : scopeArray) {
                    scope = scope + " " + s;
                }
            }
            return scope(scope);
        }

        public TokenRequest build() {
            final TokenRequest request = new TokenRequest(grantType);
            request.setScope(scope);
            return request;
        }
    }

    private GrantType grantType;
    private String code;
    private String redirectUri;
    private String username;
    private String password;
    private String scope;
    private String assertion;
    private String refreshToken;
    private String oxAuthExchangeToken;
    private String audience;

    private SignatureAlgorithm algorithm;
    private String sharedKey;
    private RSAPrivateKey rsaPrivateKey;
    private ECDSAPrivateKey ecPrivateKey;
    private String keyId;

    /**
     * Constructs a token request.
     *
     * @param grantType The grant type is mandatory and could be:
     *                  <code>authorization_code</code>, <code>password</code>,
     *                  <code>client_credentials</code>, <code>refresh_token</code>.
     */
    public TokenRequest(GrantType grantType) {
        super();
        this.grantType = grantType;

        setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        setAuthenticationMethod(AuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder umaBuilder() {
        return new Builder().grantType(GrantType.CLIENT_CREDENTIALS);
    }

    /**
     * Returns the grant type.
     *
     * @return The grant type.
     */
    public GrantType getGrantType() {
        return grantType;
    }

    /**
     * Sets the grant type.
     *
     * @param grantType The grant type.
     */
    public void setGrantType(GrantType grantType) {
        this.grantType = grantType;
    }

    /**
     * Returns the authorization code.
     *
     * @return The authorization code.
     */
    public String getCode() {
        return code;
    }

    /**
     * Sets the authorization code.
     *
     * @param code The authorization code.
     */
    public void setCode(String code) {
        this.code = code;
    }

    /**
     * Returns the redirect URI.
     *
     * @return The redirect URI.
     */
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * Sets the redirect URI.
     *
     * @param redirectUri The redirect URI.
     */
    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    /**
     * Returns the username.
     *
     * @return The username.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the username.
     *
     * @param username The username.
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns the password.
     *
     * @return The password.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets the password.
     *
     * @param password The password.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Returns the scope.
     *
     * @return The scope.
     */
    public String getScope() {
        return scope;
    }

    /**
     * Sets the scope.
     *
     * @param scope The scope.
     */
    public void setScope(String scope) {
        this.scope = scope;
    }

    /**
     * Returns the assertion.
     *
     * @return The assertion.
     */
    public String getAssertion() {
        return assertion;
    }

    /**
     * Sets the assertion.
     *
     * @param assertion The assertion.
     */
    public void setAssertion(String assertion) {
        this.assertion = assertion;
    }

    /**
     * Returns the refresh token.
     *
     * @return The refresh token.
     */
    public String getRefreshToken() {
        return refreshToken;
    }

    /**
     * Sets the refresh token.
     *
     * @param refreshToken The refresh token.
     */
    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getOxAuthExchangeToken() {
        return oxAuthExchangeToken;
    }

    public void setOxAuthExchangeToken(String oxAuthExchangeToken) {
        this.oxAuthExchangeToken = oxAuthExchangeToken;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public void setAlgorithm(SignatureAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public void setSharedKey(String sharedKey) {
        this.sharedKey = sharedKey;
    }

    public void setRsaPrivateKey(RSAPrivateKey rsaPrivateKey) {
        this.rsaPrivateKey = rsaPrivateKey;
    }

    public void setEcPrivateKey(ECDSAPrivateKey ecPrivateKey) {
        this.ecPrivateKey = ecPrivateKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getClientAssertion() {
        Jwt clientAssertion = new Jwt();

        if (algorithm == null) {
            algorithm = SignatureAlgorithm.HS256;
        }
        GregorianCalendar calendar = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        Date issuedAt = calendar.getTime();
        calendar.add(Calendar.MINUTE, 5);
        Date expirationTime = calendar.getTime();

        // Header
        clientAssertion.getHeader().setType(JwtType.JWS);
        clientAssertion.getHeader().setAlgorithm(algorithm);
        if (StringUtils.isNotBlank(keyId)) {
            clientAssertion.getHeader().setKeyId(keyId);
        }

        // Claims
        clientAssertion.getClaims().setIssuer(getAuthUsername());
        clientAssertion.getClaims().setSubjectIdentifier(getAuthUsername());
        clientAssertion.getClaims().setAudience(audience);
        clientAssertion.getClaims().setJwtId(UUID.randomUUID());
        clientAssertion.getClaims().setExpirationTime(expirationTime);
        clientAssertion.getClaims().setIssuedAt(issuedAt);

        // Signature
        try {
            if (algorithm == SignatureAlgorithm.HS256 || algorithm == SignatureAlgorithm.HS384 || algorithm == SignatureAlgorithm.HS512) {
                if (sharedKey == null) {
                    sharedKey = getAuthPassword();
                }
                HMACSigner hmacSigner = new HMACSigner(algorithm, sharedKey);
                clientAssertion = hmacSigner.sign(clientAssertion);
            } else if (algorithm == SignatureAlgorithm.RS256 || algorithm == SignatureAlgorithm.RS384 || algorithm == SignatureAlgorithm.RS512) {
                RSASigner rsaSigner = new RSASigner(algorithm, rsaPrivateKey);
                clientAssertion = rsaSigner.sign(clientAssertion);
            } else if (algorithm == SignatureAlgorithm.ES256 || algorithm == SignatureAlgorithm.ES384 || algorithm == SignatureAlgorithm.ES512) {
                ECDSASigner ecdsaSigner = new ECDSASigner(algorithm, ecPrivateKey);
                clientAssertion = ecdsaSigner.sign(clientAssertion);
            }
        } catch (SignatureException e) {
            return null;
        } catch (InvalidJwtException e) {
            return null;
        }

        return clientAssertion.toString();
    }

    /**
     * Returns a query string with the parameters of the authorization request.
     * Any <code>null</code> or empty parameter will be omitted.
     *
     * @return A query string of parameters.
     */
    @Override
    public String getQueryString() {
        StringBuilder queryStringBuilder = new StringBuilder();

        try {
            if (grantType != null) {
                queryStringBuilder.append("grant_type=").append(grantType.toString());
            }
            if (code != null && !code.isEmpty()) {
                queryStringBuilder.append("&");
                queryStringBuilder.append("code=").append(code);
            }
            if (redirectUri != null && !redirectUri.isEmpty()) {
                queryStringBuilder.append("&");
                queryStringBuilder.append("redirect_uri=").append(
                        URLEncoder.encode(redirectUri, "UTF-8"));
            }
            if (scope != null && !scope.isEmpty()) {
                queryStringBuilder.append("&");
                queryStringBuilder.append("scope=").append(
                        URLEncoder.encode(scope, "UTF-8"));
            }
            if (username != null && !username.isEmpty()) {
                queryStringBuilder.append("&");
                queryStringBuilder.append("username=").append(username);
            }
            if (password != null && !password.isEmpty()) {
                queryStringBuilder.append("&");
                queryStringBuilder.append("password=").append(password);
            }
            if (assertion != null && !assertion.isEmpty()) {
                queryStringBuilder.append("&");
                queryStringBuilder.append("assertion=").append(assertion);
            }
            if (refreshToken != null && !refreshToken.isEmpty()) {
                queryStringBuilder.append("&");
                queryStringBuilder.append("refresh_token=").append(refreshToken);
            }
            if (oxAuthExchangeToken != null && !oxAuthExchangeToken.isEmpty()) {
                queryStringBuilder.append("&");
                queryStringBuilder.append("oxauth_exchange_token=").append(oxAuthExchangeToken);
            }
            if (getAuthenticationMethod() == AuthenticationMethod.CLIENT_SECRET_POST) {
                if (getAuthUsername() != null && !getAuthUsername().isEmpty()) {
                    queryStringBuilder.append("&");
                    queryStringBuilder.append("client_id=").append(
                            URLEncoder.encode(getAuthUsername(), "UTF-8"));
                }
                if (getAuthPassword() != null && !getAuthPassword().isEmpty()) {
                    queryStringBuilder.append("&");
                    queryStringBuilder.append("client_secret=").append(
                            URLEncoder.encode(getAuthPassword(), "UTF-8"));
                }
            } else if (getAuthenticationMethod() == AuthenticationMethod.CLIENT_SECRET_JWT ||
                    getAuthenticationMethod() == AuthenticationMethod.PRIVATE_KEY_JWT) {
                queryStringBuilder.append("&client_assertion_type=").append(
                        URLEncoder.encode(ClientAssertionType.JWT_BEARER.toString(), "UTF-8"));
                queryStringBuilder.append("&");
                queryStringBuilder.append("client_assertion=").append(getClientAssertion());
            }
            for (String key : getCustomParameters().keySet()) {
                queryStringBuilder.append("&");
                queryStringBuilder.append(key).append("=").append(getCustomParameters().get(key));
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return queryStringBuilder.toString();
    }

    /**
     * Returns a collection of parameters of the token request. Any
     * <code>null</code> or empty parameter will be omitted.
     *
     * @return A collection of parameters.
     */
    public Map<String, String> getParameters() {
        Map<String, String> parameters = new HashMap<String, String>();

        if (grantType != null) {
            parameters.put("grant_type", grantType.toString());
        }
        if (code != null && !code.isEmpty()) {
            parameters.put("code", code);
        }
        if (redirectUri != null && !redirectUri.isEmpty()) {
            parameters.put("redirect_uri", redirectUri);
        }
        if (username != null && !username.isEmpty()) {
            parameters.put("username", username);
        }
        if (password != null && !password.isEmpty()) {
            parameters.put("password", password);
        }
        if (scope != null && !scope.isEmpty()) {
            parameters.put("scope", scope);
        }
        if (assertion != null && !assertion.isEmpty()) {
            parameters.put("assertion", assertion);
        }
        if (refreshToken != null && !refreshToken.isEmpty()) {
            parameters.put("refresh_token", refreshToken);
        }
        if (oxAuthExchangeToken != null && !oxAuthExchangeToken.isEmpty()) {
            parameters.put("oxauth_exchange_token", oxAuthExchangeToken);
        }
        if (getAuthenticationMethod() == AuthenticationMethod.CLIENT_SECRET_POST) {
            if (getAuthUsername() != null && !getAuthUsername().isEmpty()) {
                parameters.put("client_id", getAuthUsername());
            }
            if (getAuthPassword() != null && !getAuthPassword().isEmpty()) {
                parameters.put("client_secret", getAuthPassword());
            }
        } else if (getAuthenticationMethod() == AuthenticationMethod.CLIENT_SECRET_JWT ||
                getAuthenticationMethod() == AuthenticationMethod.PRIVATE_KEY_JWT) {
            parameters.put("client_assertion_type", ClientAssertionType.JWT_BEARER.toString());
            parameters.put("client_assertion", getClientAssertion());
        }
        for (String key : getCustomParameters().keySet()) {
            parameters.put(key, getCustomParameters().get(key));
        }

        return parameters;
    }
}