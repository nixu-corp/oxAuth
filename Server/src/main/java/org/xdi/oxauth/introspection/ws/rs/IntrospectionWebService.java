/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.introspection.ws.rs;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.lang.StringUtils;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;
import org.xdi.oxauth.model.authorize.AuthorizeErrorResponseType;
import org.xdi.oxauth.model.common.AbstractToken;
import org.xdi.oxauth.model.common.AuthorizationGrant;
import org.xdi.oxauth.model.common.AuthorizationGrantList;
import org.xdi.oxauth.model.common.AuthorizationGrantType;
import org.xdi.oxauth.model.common.IntrospectionResponse;
import org.xdi.oxauth.model.config.ConfigurationFactory;
import org.xdi.oxauth.model.error.ErrorResponseFactory;
import org.xdi.oxauth.service.token.TokenService;
import org.xdi.oxauth.util.ServerUtil;

import com.wordnik.swagger.annotations.Api;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 17/09/2013
 */
@Name("introspectionWS")
@Path("/introspection")
@Api(value= "/introspection", description = "The Introspection Endpoint is an OAuth 2 Endpoint that responds to " +
        "   HTTP GET and HTTP POST requests from token holders.  The endpoint " +
        "   takes a single parameter representing the token (and optionally " +
        "   further authentication) and returns a JSON document representing the meta information surrounding the token.")
public class IntrospectionWebService {

    @Logger
    private Log log;
    @In
    private TokenService tokenService;
    @In
    private ErrorResponseFactory errorResponseFactory;
    @In
    private AuthorizationGrantList authorizationGrantList;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspectGet(@HeaderParam("Authorization") String p_authorization,
                                  @QueryParam("token") String p_token,
                                  @QueryParam("token_type_hint") String tokenTypeHint
    ) {
        return introspect(p_authorization, p_token, tokenTypeHint);
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspectPost(@HeaderParam("Authorization") String p_authorization,
                                   @FormParam("token") String p_token,
                                   @FormParam("token_type_hint") String tokenTypeHint
    ) {
        return introspect(p_authorization, p_token, tokenTypeHint);
    }

    private Response introspect(String p_authorization, String p_token, String tokenTypeHint) {
        try {
            log.trace("Introspect token, authorization: {}, token to introsppect: {}, tokenTypeHint:", p_authorization, p_token, tokenTypeHint);
            if (StringUtils.isNotBlank(p_authorization) && StringUtils.isNotBlank(p_token)) {
                final AuthorizationGrant authorizationGrant = tokenService.getAuthorizationGrant(p_authorization);
                if (authorizationGrant != null) {
                    final AbstractToken accessToken = authorizationGrant.getAccessToken(tokenService.getTokenFromAuthorizationParameter(p_authorization));
                    if (accessToken != null && accessToken.isValid()) {
                        final IntrospectionResponse response = new IntrospectionResponse(false);

                        final AuthorizationGrant grantOfIntrospectionToken = authorizationGrantList.getAuthorizationGrantByAccessToken(p_token);
                        if (grantOfIntrospectionToken != null) {
                            final AbstractToken tokenToIntrospect = grantOfIntrospectionToken.getAccessToken(p_token);
                            if (tokenToIntrospect != null) {
                                response.setActive(tokenToIntrospect.isValid());
                                response.setExpiresAt(tokenToIntrospect.getExpirationDate());
                                response.setIssuedAt(tokenToIntrospect.getCreationDate());
                                response.setAuthLevel(tokenToIntrospect.getAuthLevel());
                                response.setAuthMode(tokenToIntrospect.getAuthMode());
                                
                                if (tokenToIntrospect.isValid()) {
                                	
                                	if (authorizationGrant.getScopes() != null && authorizationGrant.getScopes().size() > 0) {
                                		final StringBuilder sb = new StringBuilder();
                                		for (String scope : authorizationGrant.getScopes()) {
                                			sb.append(" ");
                                			sb.append(scope);
                                		}
                                		if (sb.length() > 0) {
                                			response.setScope(sb.substring(1));
                                		}
                                	}
                                	
                                	response.setClientId(authorizationGrant.getClientId());
                                	response.setUsername(authorizationGrant.getUserId());
                                	response.setIssuer(ConfigurationFactory.getConfiguration().getIssuer());
                                	
                                	if (authorizationGrant.getAuthorizationGrantType() != null && authorizationGrant.getAuthorizationGrantType() == AuthorizationGrantType.CLIENT_CREDENTIALS) {
                                		
                                		response.setSubject(authorizationGrant.getClientId());
                                		
                                	} else {
                                		
                                		if (ConfigurationFactory.getConfiguration().getSubjectClaim() != null && authorizationGrant.getUser() != null) {
                                		
                                			Object attributeValue = authorizationGrant.getUser().getAttribute(ConfigurationFactory.getConfiguration().getSubjectClaim(), true);
                                			if (attributeValue != null && attributeValue instanceof String) {
                                				response.setSubject(attributeValue.toString());
                                			}
                                			
                                		}
                                		
                                	}
                                }
                                
                            }
                        }
                        return Response.status(Response.Status.OK).entity(ServerUtil.asJson(response)).build();
                    }
                }

                return Response.status(Response.Status.BAD_REQUEST).entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.ACCESS_DENIED)).build();
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        return Response.status(Response.Status.BAD_REQUEST).entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.INVALID_REQUEST)).build();
    }
}
