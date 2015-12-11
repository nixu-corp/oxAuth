/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.error;

import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.log.Log;
import org.xdi.oxauth.model.authorize.AuthorizeErrorResponseType;
import org.xdi.oxauth.model.clientinfo.ClientInfoErrorResponseType;
import org.xdi.oxauth.model.federation.FederationErrorResponseType;
import org.xdi.oxauth.model.fido.u2f.U2fErrorResponseType;
import org.xdi.oxauth.model.register.RegisterErrorResponseType;
import org.xdi.oxauth.model.session.EndSessionErrorResponseType;
import org.xdi.oxauth.model.token.TokenErrorResponseType;
import org.xdi.oxauth.model.token.ValidateTokenErrorResponseType;
import org.xdi.oxauth.model.uma.UmaErrorResponse;
import org.xdi.oxauth.model.uma.UmaErrorResponseType;
import org.xdi.oxauth.model.userinfo.UserInfoErrorResponseType;
import org.xdi.oxauth.util.ServerUtil;
import org.xdi.util.StringHelper;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.List;

/**
 * Provides an easy way to get Error responses based in an error response type
 *
 * @author Yuriy Zabrovarnyy
 * @author Javier Rojas Blum
 */
@Name("errorResponseFactory")
@AutoCreate
@Scope(ScopeType.APPLICATION)
public class ErrorResponseFactory {

    @Logger
    private Log log;

    private volatile ErrorMessages messages;

    public ErrorMessages getMessages() {
        return messages;
    }

    public void setMessages(ErrorMessages p_messages) {
        messages = p_messages;
    }

    /**
     * Looks for an error message.
     *
     * @param p_list error list
     * @param type   The type of the error.
     * @return Error message or <code>null</code> if not found.
     */
    private ErrorMessage getError(List<ErrorMessage> p_list, IErrorType type) {
        log.debug("Looking for the error with id: {0}", type);

        if (p_list != null) {
            for (ErrorMessage error : p_list) {
                if (error.getId().equals(type.getParameter())) {
                    log.debug("Found error, id: {0}", type);
                    return error;
                }
            }
        }

        log.debug("Error not found, id: {0}", type);
        return null;
    }

    public String getErrorAsJson(IErrorType p_type) {
        return getErrorResponse(p_type).toJSonString();
    }

    public void throwUnauthorizedException(IErrorType type) throws WebApplicationException {
        throwWebApplicationException(Response.Status.UNAUTHORIZED, type);
    }

    public void throwBadRequestException(IErrorType type) throws WebApplicationException {
        throwWebApplicationException(Response.Status.BAD_REQUEST, type);
    }

    public void throwWebApplicationException(Response.Status status, IErrorType type) throws WebApplicationException {
        final Response response = Response.status(status).entity(getErrorAsJson(type)).build();
        throw new WebApplicationException(response);
    }

    public String getErrorAsJson(IErrorType p_type, String p_state) {
        return getErrorResponse(p_type, p_state).toJSonString();
    }

    public String getErrorAsQueryString(IErrorType p_type, String p_state) {
        return getErrorResponse(p_type, p_state).toQueryString();
    }

    public DefaultErrorResponse getErrorResponse(IErrorType type, String p_state) {
        final DefaultErrorResponse response = getErrorResponse(type);
        response.setState(p_state);
        return response;
    }

    public DefaultErrorResponse getErrorResponse(IErrorType type) {
        final DefaultErrorResponse response = new DefaultErrorResponse();
        response.setType(type);

        if (type != null && messages != null) {
            List<ErrorMessage> list = null;
            if (type instanceof AuthorizeErrorResponseType) {
                list = messages.getAuthorize();
            } else if (type instanceof FederationErrorResponseType) {
                list = messages.getFederation();
            } else if (type instanceof ClientInfoErrorResponseType) {
                list = messages.getClientInfo();
            } else if (type instanceof EndSessionErrorResponseType) {
                list = messages.getEndSession();
            } else if (type instanceof RegisterErrorResponseType) {
                list = messages.getRegister();
            } else if (type instanceof TokenErrorResponseType) {
                list = messages.getToken();
            } else if (type instanceof UmaErrorResponseType) {
                list = messages.getUma();
            } else if (type instanceof UserInfoErrorResponseType) {
                list = messages.getUserInfo();
            } else if (type instanceof ValidateTokenErrorResponseType) {
                list = messages.getValidateToken();
            } else if (type instanceof U2fErrorResponseType) {
                list = messages.getFido();
            }

            if (list != null) {
                final ErrorMessage m = getError(list, type);
                response.setErrorDescription(m.getDescription());
                response.setErrorUri(m.getUri());
            }
        }

        return response;
    }

    public UmaErrorResponse getUmaErrorResponse(IErrorType type) {
        final UmaErrorResponse response = new UmaErrorResponse();

        final ErrorMessage errorMessage = getError(messages.getUma(), type);
        response.setError(errorMessage.getId());
        response.setErrorDescription(errorMessage.getDescription());
        response.setErrorUri(errorMessage.getUri());

        return response;
    }

    public String getUmaJsonErrorResponse(IErrorType type) {
        final UmaErrorResponse response = getUmaErrorResponse(type);

        JSONObject jsonObj = new JSONObject();

        try {
            jsonObj.put("error", response.getError());

            if (StringHelper.isNotEmpty(response.getStatus())) {
                jsonObj.put("status", response.getStatus());
            }

            if (StringHelper.isNotEmpty(response.getErrorDescription())) {
                jsonObj.put("error_description", response.getErrorDescription());
            }


            if (StringHelper.isNotEmpty(response.getErrorUri())) {
                jsonObj.put("error_uri", response.getErrorUri());
            }
        } catch (JSONException ex) {
            log.error("Failed to generate error response", ex);
            return null;
        }

        return jsonObj.toString();
    }


    public String getJsonErrorResponse(IErrorType type) {
        final DefaultErrorResponse response = getErrorResponse(type);
        
        JsonErrorResponse jsonErrorResponse = new JsonErrorResponse(response);

        try {
			return ServerUtil.asJson(jsonErrorResponse);
		} catch (IOException ex) {
            log.error("Failed to generate error response", ex);
            return null;
		}
    }

}