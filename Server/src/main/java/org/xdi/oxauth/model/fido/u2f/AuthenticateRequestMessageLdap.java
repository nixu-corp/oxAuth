/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */
package org.xdi.oxauth.model.fido.u2f;

import java.io.Serializable;

import org.gluu.site.ldap.persistence.annotation.LdapAttribute;
import org.gluu.site.ldap.persistence.annotation.LdapJsonObject;
import org.xdi.oxauth.model.fido.u2f.protocol.AuthenticateRequestMessage;

/**
 * U2F authentication requests
 *
 * @author Yuriy Movchan Date: 06/02/2015
 */
public class AuthenticateRequestMessageLdap extends RequestMessageLdap implements Serializable {

	private static final long serialVersionUID = -1142931562244920584L;

    @LdapJsonObject
    @LdapAttribute(name = "oxRequest")
	private AuthenticateRequestMessage authenticateRequestMessage;
	
	public AuthenticateRequestMessageLdap() {}

	public AuthenticateRequestMessageLdap(AuthenticateRequestMessage authenticateRequestMessage) {
		this.authenticateRequestMessage = authenticateRequestMessage;
		this.requestId = authenticateRequestMessage.getRequestId();
	}

	public AuthenticateRequestMessage getAuthenticateRequestMessage() {
		return authenticateRequestMessage;
	}

	public void setAuthenticateRequestMessage(AuthenticateRequestMessage authenticateRequestMessage) {
		this.authenticateRequestMessage = authenticateRequestMessage;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("AuthenticateRequestMessageLdap [id=").append(id).append(", authenticateRequestMessage=").append(authenticateRequestMessage)
				.append(", requestId=").append(requestId).append(", creationDate=").append(creationDate).append("]");
		return builder.toString();
	}

}
