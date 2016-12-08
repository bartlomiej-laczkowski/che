/*******************************************************************************
 * Copyright (c) 2012-2016 Codenvy, S.A.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Codenvy, S.A. - initial API and implementation
 *******************************************************************************/
package org.eclipse.che.security.oauth1;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Map;

import static org.eclipse.che.security.OAuthUtils.getParameter;
import static org.eclipse.che.security.OAuthUtils.getRequestParameters;
import static org.eclipse.che.security.OAuthUtils.getRequestUrl;

/**
 * RESTful wrapper for OAuth 1.0.
 *
 * @author Kevin Pollet
 * @author Igor Vinokur
 */
@Path("oauth/1.0")
public class OAuthAuthenticationService {
    private static final Logger LOG = LoggerFactory.getLogger(OAuthAuthenticationService.class);

    @Inject
    protected OAuthAuthenticatorProvider providers;

    /**
     * Redirect request to OAuth provider site for authentication|authorization. Client request must contains set of
     * required query parameters:
     * <table>
     * <tr><th>Name</th><th>Description</th><th>Mandatory</th><th>Default value</th></tr>
     * <tr><td>oauth_provider</td><td>Name of OAuth provider. At the moment <tt>google</tt> and <tt>github</tt>
     * supported</td><td>yes</td><td>none</td></tr>
     * <tr><td>scope</td><td>Specify exactly what type of access needed. List of scopes dependents to OAuth provider.
     * Requested scopes displayed at user authorization page at OAuth provider site. Check docs about scopes
     * supported by
     * suitable OAuth provider.</td><td>no</td><td>Empty list</td></tr>
     * <tr><td>mode</td><td>Authentication mode. May be <tt>federated_login</tt> or <tt>token</tt>. If <tt>mode</tt>
     * set
     * as <tt>federated_login</tt> that parameters 'username' and 'password' added to redirect URL after successful
     * user
     * authentication. (see next parameter) In this case 'password' is temporary generated password. This password will
     * be validated by FederatedLoginModule.</td><td>no</td><td>token</td></tr>
     * <tr><td>redirect_after_login</td><td>URL for user redirection after successful
     * authentication</td><td>yes</td><td>none</td></tr>
     * </table>
     *
     * @param uriInfo
     *         UriInfo
     * @return typically Response that redirect user for OAuth provider site
     */
    @GET
    @Path("authenticate")
    public Response authenticate(@Context UriInfo uriInfo)
            throws OAuthAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException {
        final OAuthAuthenticator oauth = getAuthenticator(uriInfo.getQueryParameters().getFirst("oauth_provider"));
        final String authUrl = oauth.getAuthenticateUrl(getRequestUrl(uriInfo));

        return Response.temporaryRedirect(URI.create(authUrl)).build();
    }

    @GET
    @Path("callback")
    public Response callback(@Context UriInfo uriInfo)
            throws OAuthAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException {
        final URL requestUrl = getRequestUrl(uriInfo);
        final Map<String, List<String>> params = getRequestParameters(requestUrl);

        final String providerName = getParameter(params, "oauth_provider");
        final OAuthAuthenticator oauth = getAuthenticator(providerName);

        oauth.callback(requestUrl);

        final String redirectAfterLogin = getParameter(params, "redirect_after_login");
        return Response.temporaryRedirect(URI.create(redirectAfterLogin)).build();
    }

    @GET
    @Path("authorization")
    public String authorization(@QueryParam("oauth_provider") String oauthProviderName,
                                @QueryParam("request_method") String requestMethod,
                                @QueryParam("request_url") String requestUrl,
                                @QueryParam("user_id") String userId)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        final OAuthAuthenticator oAuthAuthenticator = providers.getAuthenticator(oauthProviderName);
        if (oAuthAuthenticator != null) {
            return oAuthAuthenticator.computeAuthorizationHeader(userId, requestMethod, requestUrl);
        }
        return null;
    }

    private OAuthAuthenticator getAuthenticator(String oauthProviderName) {
        OAuthAuthenticator oauth = providers.getAuthenticator(oauthProviderName);
        if (oauth == null) {
            LOG.error("Unsupported OAuth provider {} ", oauthProviderName);
            throw new WebApplicationException(Response.status(400).entity("Unsupported OAuth provider " +
                                                                          oauthProviderName).type(MediaType.TEXT_PLAIN)
                                                      .build());
        }
        return oauth;
    }
}
