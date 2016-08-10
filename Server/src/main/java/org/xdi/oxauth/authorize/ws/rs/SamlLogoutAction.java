package org.xdi.oxauth.authorize.ws.rs;

import javax.faces.context.FacesContext;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.faces.FacesManager;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.international.StatusMessage.Severity;
import org.jboss.seam.log.Log;
import org.xdi.model.custom.script.conf.CustomScriptConfiguration;
import org.xdi.oxauth.model.common.SessionState;
import org.xdi.oxauth.service.SessionStateService;
import org.xdi.oxauth.service.external.ExternalAuthenticationService;
import org.xdi.util.StringHelper;

@Name("samlLogoutAction")
@Scope(ScopeType.EVENT)
public class SamlLogoutAction {

    @Logger
    private Log log;
    
	@In
	private SessionStateService sessionStateService;
	
    @In
    private FacesMessages facesMessages;
    
    @In
    private ExternalAuthenticationService externalAuthenticationService;
    
	public void redirect() {
		
		SessionState sessionState = sessionStateService.getSessionState();
		if (sessionState != null && sessionState.getSessionAttributes() != null && sessionState.getSessionAttributes().containsKey("acr_values")) {
			
			String acr = sessionState.getSessionAttributes().get("acr_values");
			boolean isExternalAuthenticatorLogoutPresent = StringHelper.isNotEmpty(acr);
			if (isExternalAuthenticatorLogoutPresent) {
				log.debug("Attempting to execute logout method of '{0}' external authenticator.", acr);

				CustomScriptConfiguration customScriptConfiguration = externalAuthenticationService.getCustomScriptConfigurationByName(acr);
				if (customScriptConfiguration == null) {
					log.error("Failed to get ExternalAuthenticatorConfiguration. auth_mode: {0}", acr);
					logoutFailed();
					return;
					
				} else {
					boolean externalLogoutResult = externalAuthenticationService.executeExternalLogout(customScriptConfiguration, FacesContext.getCurrentInstance().getExternalContext().getRequestParameterValuesMap());
					log.debug("Logout result for {0}. result: {1}", acr, externalLogoutResult);
					return;
				}
			} else {
				return;
			}
			
			
		} else {
			logoutFailed();
		}
		
	}
	
	public void logoutFailed() {
		facesMessages.add(Severity.ERROR, "Failed to process logout");
		FacesManager.instance().redirect("/error.xhtml");
	}
	
}
