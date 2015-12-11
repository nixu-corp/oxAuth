/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.client;

import com.google.common.base.Strings;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.ClientRequest;
import org.xdi.oxauth.model.register.ApplicationType;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MediaType;
import java.util.List;
import java.util.Map;

import static org.xdi.oxauth.model.register.RegisterRequestParam.*;

/**
 * Encapsulates functionality to make Register request calls to an authorization server via REST Services.
 *
 * @author Javier Rojas Blum Date: 01.17.2012
 * @author Yuriy Zabrovarnyy
 * @author Yuriy Movchan Date: 08/06/2013
 * @version 0.1, 01.17.2012
 */
public class RegisterClient extends BaseClient<RegisterRequest, RegisterResponse> {

    private static final Logger LOG = Logger.getLogger(RegisterClient.class);

    /**
     * Construct a register client by providing an URL where the REST service is located.
     *
     * @param url The REST service location.
     */
    public RegisterClient(String url) {
        super(url);
    }

    @Override
    public RegisterRequest getRequest() {
        if (request instanceof RegisterRequest) {
            return (RegisterRequest) request;
        } else {
            return null;
        }
    }

    @Override
    public void setRequest(RegisterRequest request) {
        super.request = request;
    }

    @Override
    public RegisterResponse getResponse() {
        if (response instanceof RegisterResponse) {
            return (RegisterResponse) response;
        } else {
            return null;
        }
    }

    @Override
    public void setResponse(RegisterResponse response) {
        super.response = response;
    }

    @Override
    public String getHttpMethod() {
        if (getRequest() != null) {
            if (StringUtils.isNotBlank(getRequest().getHttpMethod())) {
                return getRequest().getHttpMethod();
            }
            if (getRequest().getRegistrationAccessToken() != null) {
                return HttpMethod.GET;
            }
        }

        return HttpMethod.POST;
    }

    /**
     * Executes the call to the REST service requesting to register and process the response.
     *
     * @param applicationType The application type.
     * @param clientName      The client name.
     * @param redirectUri     A list of space-delimited redirection URIs.
     * @return The service response.
     */
    public RegisterResponse execRegister(ApplicationType applicationType,
                                         String clientName, List<String> redirectUri) {
        setRequest(new RegisterRequest(applicationType, clientName, redirectUri));

        return exec();
    }

    public RegisterResponse exec() {
        initClientRequest();
        return _exec();
    }

    @Deprecated
    public RegisterResponse exec(ClientExecutor clientExecutor) {
        this.clientRequest = new ClientRequest(getUrl(), clientExecutor);
        return _exec();
    }

    private RegisterResponse _exec() {
        try {
            // Prepare request parameters
            clientRequest.setHttpMethod(getHttpMethod());

            // POST - Client Register, PUT - update client
            if (getHttpMethod().equals(HttpMethod.POST) || getHttpMethod().equals(HttpMethod.PUT)) {
                clientRequest.header("Content-Type", getRequest().getContentType());
                clientRequest.accept(getRequest().getMediaType());

                JSONObject requestBody = new JSONObject();

                if (StringUtils.isNotBlank(getRequest().getRegistrationAccessToken())) {
                    clientRequest.header("Authorization", "Bearer " + getRequest().getRegistrationAccessToken());
                }
                if (getRequest().getRedirectUris() != null && !getRequest().getRedirectUris().isEmpty()) {
                    requestBody.put(REDIRECT_URIS.toString(), new JSONArray(getRequest().getRedirectUris()));
                }
                if (getRequest().getResponseTypes() != null && !getRequest().getResponseTypes().isEmpty()) {
                    requestBody.put(RESPONSE_TYPES.toString(), new JSONArray(getRequest().getResponseTypes()));
                }
                if (getRequest().getGrantTypes() != null && !getRequest().getGrantTypes().isEmpty()) {
                    requestBody.put(GRANT_TYPES.toString(), new JSONArray(getRequest().getGrantTypes()));
                }
                if (getRequest().getApplicationType() != null) {
                    requestBody.put(APPLICATION_TYPE.toString(), getRequest().getApplicationType());
                }
                if (getRequest().getContacts() != null && !getRequest().getContacts().isEmpty()) {
                    requestBody.put(CONTACTS.toString(), new JSONArray(getRequest().getContacts()));
                }
                if (StringUtils.isNotBlank(getRequest().getClientName())) {
                    requestBody.put(CLIENT_NAME.toString(), getRequest().getClientName());
                }
                if (StringUtils.isNotBlank(getRequest().getLogoUri())) {
                    requestBody.put(LOGO_URI.toString(), getRequest().getLogoUri());
                }
                if (StringUtils.isNotBlank(getRequest().getClientUri())) {
                    requestBody.put(CLIENT_URI.toString(), getRequest().getClientUri());
                }
                if (getRequest().getTokenEndpointAuthMethod() != null) {
                    requestBody.put(TOKEN_ENDPOINT_AUTH_METHOD.toString(), getRequest().getTokenEndpointAuthMethod());
                }
                if (StringUtils.isNotBlank(getRequest().getPolicyUri())) {
                    requestBody.put(POLICY_URI.toString(), getRequest().getPolicyUri());
                }
                if (StringUtils.isNotBlank(getRequest().getTosUri())) {
                    requestBody.put(TOS_URI.toString(), getRequest().getTosUri());
                }
                if (StringUtils.isNotBlank(getRequest().getJwksUri())) {
                    requestBody.put(JWKS_URI.toString(), getRequest().getJwksUri());
                }
                if (StringUtils.isNotBlank(getRequest().getJwks())) {
                    requestBody.put(JWKS.toString(), getRequest().getJwks());
                }
                if (StringUtils.isNotBlank(getRequest().getSectorIdentifierUri())) {
                    requestBody.put(SECTOR_IDENTIFIER_URI.toString(), getRequest().getSectorIdentifierUri());
                }
                if (getRequest().getSubjectType() != null) {
                    requestBody.put(SUBJECT_TYPE.toString(), getRequest().getSubjectType());
                }
                if (getRequest().getRequestObjectSigningAlg() != null) {
                    requestBody.put(REQUEST_OBJECT_SIGNING_ALG.toString(), getRequest().getRequestObjectSigningAlg().getName());
                }
                if (getRequest().getUserInfoSignedResponseAlg() != null) {
                    requestBody.put(USERINFO_SIGNED_RESPONSE_ALG.toString(), getRequest().getUserInfoSignedResponseAlg().getName());
                }
                if (getRequest().getUserInfoEncryptedResponseAlg() != null) {
                    requestBody.put(USERINFO_ENCRYPTED_RESPONSE_ALG.toString(), getRequest().getUserInfoEncryptedResponseAlg().getName());
                }
                if (getRequest().getUserInfoEncryptedResponseEnc() != null) {
                    requestBody.put(USERINFO_ENCRYPTED_RESPONSE_ENC.toString(), getRequest().getUserInfoEncryptedResponseEnc().getName());
                }
                if (getRequest().getIdTokenSignedResponseAlg() != null) {
                    requestBody.put(ID_TOKEN_SIGNED_RESPONSE_ALG.toString(), getRequest().getIdTokenSignedResponseAlg().getName());
                }
                if (getRequest().getIdTokenEncryptedResponseAlg() != null) {
                    requestBody.put(ID_TOKEN_ENCRYPTED_RESPONSE_ALG.toString(), getRequest().getIdTokenEncryptedResponseAlg().getName());
                }
                if (getRequest().getIdTokenEncryptedResponseEnc() != null) {
                    requestBody.put(ID_TOKEN_ENCRYPTED_RESPONSE_ENC.toString(), getRequest().getIdTokenEncryptedResponseEnc().getName());
                }
                if (getRequest().getDefaultMaxAge() != null) {
                    requestBody.put(DEFAULT_MAX_AGE.toString(), getRequest().getDefaultMaxAge());
                }
                if (getRequest().getRequireAuthTime() != null) {
                    requestBody.put(REQUIRE_AUTH_TIME.toString(), getRequest().getRequireAuthTime());
                }
                if (getRequest().getDefaultAcrValues() != null && !getRequest().getDefaultAcrValues().isEmpty()) {
                    requestBody.put(DEFAULT_ACR_VALUES.toString(), getRequest().getDefaultAcrValues());
                }
                if (StringUtils.isNotBlank(getRequest().getInitiateLoginUri())) {
                    requestBody.put(INITIATE_LOGIN_URI.toString(), getRequest().getInitiateLoginUri());
                }
                if (getRequest().getPostLogoutRedirectUris() != null && !getRequest().getPostLogoutRedirectUris().isEmpty()) {
                    requestBody.put(POST_LOGOUT_REDIRECT_URIS.toString(), getRequest().getPostLogoutRedirectUris());
                }
                if (!Strings.isNullOrEmpty(getRequest().getLogoutUri())) {
                    requestBody.put(LOGOUT_URI.getName(), getRequest().getLogoutUri());
                }
                if (getRequest().getLogoutSessionRequired() != null) {
                    requestBody.put(LOGOUT_SESSION_REQUIRED.getName(), getRequest().getLogoutSessionRequired());
                }
                if (getRequest().getRequestUris() != null && !getRequest().getRequestUris().isEmpty()) {
                    requestBody.put(REQUEST_URIS.toString(), new JSONArray(getRequest().getRequestUris()));
                }
                if (getRequest().getScopes() != null && !getRequest().getScopes().isEmpty()) {
                    requestBody.put(SCOPES.toString(), new JSONArray(getRequest().getScopes()));
                }

                // Federation params
                if (StringUtils.isNotBlank(getRequest().getFederationUrl())) {
                    requestBody.put(FEDERATION_METADATA_URL.toString(), getRequest().getFederationUrl());
                }
                if (StringUtils.isNotBlank(getRequest().getFederationId())) {
                    requestBody.put(FEDERATION_METADATA_ID.toString(), getRequest().getFederationId());
                }
                // Custom params
                final Map<String, String> customAttributes = getRequest().getCustomAttributes();
                if (customAttributes != null && !customAttributes.isEmpty()) {
                    for (Map.Entry<String, String> entry : customAttributes.entrySet()) {
                        final String name = entry.getKey();
                        final String value = entry.getValue();
                        if (StringUtils.isNotBlank(name) && StringUtils.isNotBlank(value)) {
                            requestBody.put(name, value);
                        }
                    }
                }
                clientRequest.body(MediaType.APPLICATION_JSON, requestBody.toString(4));
            } else { // GET, Client Read
                clientRequest.accept(MediaType.APPLICATION_JSON);

                if (StringUtils.isNotBlank(getRequest().getRegistrationAccessToken())) {
                    clientRequest.header("Authorization", "Bearer " + getRequest().getRegistrationAccessToken());
                }
            }

            // Call REST Service and handle response

            if (getHttpMethod().equals(HttpMethod.POST)) {
                clientResponse = clientRequest.post(String.class);
            } else if (getHttpMethod().equals(HttpMethod.PUT)) {
                clientResponse = clientRequest.put(String.class);
            } else { // GET
                clientResponse = clientRequest.get(String.class);
            }
            setResponse(new RegisterResponse(clientResponse));
        } catch (JSONException e) {
            LOG.error(e.getMessage(), e);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        } finally {
            closeConnection();
        }

        return getResponse();
    }
}