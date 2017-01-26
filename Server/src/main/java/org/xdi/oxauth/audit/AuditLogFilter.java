package org.xdi.oxauth.audit;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.MDC;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Startup;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.annotations.web.Filter;
import org.jboss.seam.log.Log;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.jboss.seam.web.AbstractFilter;

@Startup
@Scope(ScopeType.APPLICATION)
@Name("org.xdi.oxauth.servlet.AuditLogFilter")
@BypassInterceptors
@Filter(within = { "org.jboss.seam.web.authenticationFilter" })
@Install(classDependencies = { "org.apache.log4j.Logger" }, dependencies = { "org.jboss.seam.security.identity" })
public class AuditLogFilter extends AbstractFilter {

	@Logger("org.xdi.oxauth.audit")
	private Log log;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp,
			FilterChain chain) throws IOException, ServletException {

		HttpSession session = null;
		try {
			session = ((HttpServletRequest) req).getSession(false);
			if (session != null) {
				Object attribute = session
						.getAttribute("org.jboss.seam.security.identity");
				if (attribute instanceof Identity) {
					Identity identity = (Identity) attribute;
					Credentials credentials = identity.getCredentials();
					String username = credentials != null ? credentials
							.getUsername() : null;
					if (username != null) {
						MDC.put("subject", username);
					}
				}
			}

			MDC.put("ip", ((HttpServletRequest) req).getRemoteAddr());
			MDC.put("app", ((HttpServletRequest) req).getRequestURI());
			MDC.put("host", ((HttpServletRequest) req).getLocalName());
			MDC.put("method", ((HttpServletRequest) req).getMethod());
			MDC.put("scheme", ((HttpServletRequest) req).getScheme());

		} catch (Exception e) {
			log.error("Request handling failed " + e.getMessage());
		}
			
		chain.doFilter(req, resp);

		try {

			// if (req.getAttribute("sessionUser") != null) {
			// MDC.put("sessionUser", req.getAttribute("sessionUser"));
			// }
			
			if (session != null) {
				MDC.put("session_id", session.getId());
			}
			if (req.getAttribute("client_id") != null) {
				MDC.put("client_id", req.getAttribute("client_id"));
			}

			Enumeration<String> e = ((HttpServletRequest) req).getHeaderNames();
			while (e.hasMoreElements()) {
				String header = e.nextElement();
				MDC.put("header." + header.toLowerCase(),
						((HttpServletRequest) req).getHeader(header));
			}

			MDC.put("status", ((HttpServletResponse) resp).getStatus());

			log.info("");

			MDC.remove("subject");
			
		} catch (Exception e) {
			log.error("Request handling failed " + e.getMessage());
		}
	}

}
