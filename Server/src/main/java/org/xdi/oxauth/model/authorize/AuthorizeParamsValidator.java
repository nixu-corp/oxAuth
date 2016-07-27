/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.authorize;

import org.apache.commons.lang.StringUtils;
import org.xdi.oxauth.model.common.Prompt;
import org.xdi.oxauth.model.common.ResponseType;
import org.xdi.oxauth.model.registration.Client;

import java.util.Arrays;
import java.util.List;

/**
 * Validates the parameters received for the authorize web service.
 *
 * @author Javier Rojas Blum
 * @version June 3, 2015
 */
public class AuthorizeParamsValidator {

    /**
     * Validates the parameters for an authorization request.
     *
     * @param responseType The response type string. This parameter is mandatory, its
     *                     value must be set to <strong>code</strong> or
     *                     <strong>token</strong>.
     * @param clientId     The client identifier. This parameter is mandatory.
     * @return Returns <code>true</code> when all the parameters are valid.
     */
    public static boolean validateParams(String responseType, String clientId,
                                         List<Prompt> prompts, String nonce,
                                         String request, String requestUri) {
        List<ResponseType> responseTypes = ResponseType.fromString(responseType, " ");
        if (responseTypes.contains(ResponseType.TOKEN) || responseTypes.contains(ResponseType.ID_TOKEN)) {
            if (StringUtils.isBlank(nonce)) {
                return false;
            }
        }

        if (StringUtils.isNotBlank(request) && StringUtils.isNotBlank(requestUri)) {
            return false;
        }

        boolean validParams = responseType != null && !responseType.isEmpty()
                && clientId != null && !clientId.isEmpty();

        return validParams && noNonePrompt(prompts);
    }

    public static boolean noNonePrompt(List<Prompt> prompts) {
        return !(prompts.contains(Prompt.NONE) && prompts.size() > 1);
    }

    public static boolean validateResponseTypes(List<ResponseType> responseTypes, Client client) {
        if (responseTypes == null || responseTypes.isEmpty() || client == null || client.getResponseTypes() == null) {
            return false;
        }

        List<ResponseType> clientSupportedResponseTypes = Arrays.asList(client.getResponseTypes());

        return clientSupportedResponseTypes.containsAll(responseTypes);
    }
}