package org.xdi.oxauth.rp.demo;

import com.google.common.base.Strings;
import org.apache.log4j.Logger;
import org.xdi.oxauth.client.*;
import org.xdi.oxauth.model.common.GrantType;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author yuriyz on 07/19/2016.
 */
public class LoginFilter implements Filter {

    private static final Logger LOG = Logger.getLogger(LoginFilter.class);

    public static final String WELL_KNOWN_CONNECT_PATH = "/.well-known/openid-configuration";

    private String authorizeParameters;
    private String redirectUri;
    private String authorizationServerHost;
    private OpenIdConfigurationResponse discoveryResponse;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        authorizeParameters = filterConfig.getInitParameter("authorizeParameters");
        redirectUri = filterConfig.getInitParameter("redirectUri");
        authorizationServerHost = filterConfig.getInitParameter("authorizationServerHost");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        boolean redirectForLogin = fetchTokenIfCodeIsPresent(request);

        Object accessToken = request.getSession(true).getAttribute("access_token");
        if (accessToken == null) {
            if (redirectForLogin) {
                redirectToLogin(request, response);
            } else {
                LOG.trace("Login failed.");
                response.setContentType("text/html;charset=utf-8");

                PrintWriter pw = response.getWriter();
                pw.println("<h3>Login failed.</h3>");
            }
        } else {
            LOG.trace("User is already authenticated.");
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }

    private void fetchDiscovery(HttpServletRequest request) {
        try {
            if (discoveryResponse != null) { // already initialized
                return;
            }

            OpenIdConfigurationClient discoveryClient = new OpenIdConfigurationClient(authorizationServerHost + WELL_KNOWN_CONNECT_PATH);
            discoveryClient.setExecutor(Utils.createTrustAllExecutor());

            discoveryResponse = discoveryClient.execOpenIdConfiguration();
            LOG.trace("Discovery: " + discoveryResponse);

            if (discoveryResponse.getStatus() == 200) {
                request.getSession(true).setAttribute("discovery", discoveryResponse);
                return;
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }

        throw new RuntimeException("Failed to fetch discovery information at : " + authorizationServerHost + WELL_KNOWN_CONNECT_PATH);
    }

    /**
     * @param request request
     * @return whether login is still required
     */
    private boolean fetchTokenIfCodeIsPresent(HttpServletRequest request) {
        String code = request.getParameter("code");
        if (code != null && !code.trim().isEmpty()) {
            LOG.trace("Fetching token for code " + code + " ...");
            fetchDiscovery(request);

            TokenRequest tokenRequest = new TokenRequest(GrantType.AUTHORIZATION_CODE);
            tokenRequest.setCode(code);
            tokenRequest.setRedirectUri(redirectUri);

            TokenClient tokenClient = new TokenClient(discoveryResponse.getTokenEndpoint());
            tokenClient.setExecutor(Utils.createTrustAllExecutor());
            tokenClient.setRequest(tokenRequest);

            TokenResponse tokenResponse = tokenClient.exec();
            if (!Strings.isNullOrEmpty(tokenResponse.getAccessToken())) {
                LOG.trace("Token is successfully fetched.");

                request.getSession(true).setAttribute("access_token", tokenResponse.getAccessToken());
                request.getSession(true).setAttribute("id_token", tokenResponse.getIdToken());
            } else {
                LOG.trace("Failed to obtain token.");
            }
            return false;
        }
        return true;
    }

    private void redirectToLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        fetchDiscovery(request);

        String redirectTo = discoveryResponse.getAuthorizationEndpoint() +
                "?redirect_uri=" + redirectUri + "&" + authorizeParameters;
        LOG.trace("Redirecting to authorization url : " + redirectTo);
        response.sendRedirect(redirectTo);
    }

    @Override
    public void destroy() {
    }
}