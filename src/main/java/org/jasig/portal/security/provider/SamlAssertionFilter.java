/**
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.jasig.portal.security.provider;

import java.io.IOException;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpConnectionManagerParams;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.springframework.web.filter.GenericFilterBean;

public class SamlAssertionFilter extends GenericFilterBean {

    private MultiThreadedHttpConnectionManager connectionManager = null;
    private HttpClient httpClient;
    
    private String samlAssertionSessionAttributeName = null;
    private String idpPublicKeysSessionAttributeName = null;
    private int maxTotalConnections = 200;
    private int connectionTimeout = (int)TimeUnit.SECONDS.convert(30, TimeUnit.MILLISECONDS);
    private int readTimeout = (int)TimeUnit.SECONDS.convert(30, TimeUnit.MILLISECONDS);

    public void setSamlAssertionSessionAttributeName(String samlAssertionSessionAttributeName) {
        this.samlAssertionSessionAttributeName = samlAssertionSessionAttributeName;
    }

    public void setIdpPublicKeysSessionAttributeName(String idpPublicKeysSessionAttributeName) {
        this.idpPublicKeysSessionAttributeName = idpPublicKeysSessionAttributeName;
    }
    
    /**
     * @param maxTotalConnections Defaults to 200
     */
    public void setMaxTotalConnections(int maxTotalConnections) {
        this.maxTotalConnections = maxTotalConnections;
    }

    /**
     * @param connectionTimeout In milliseconds, defaults to 30 seconds
     */
    public void setConnectionTimeout(int connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    /**
     * @param readTimeout In milliseconds, defaults to 30 seconds
     */
    public void setReadTimeout(int readTimeout) {
        this.readTimeout = readTimeout;
    }

    @Override
    protected void initFilterBean() throws ServletException {
        this.connectionManager = new MultiThreadedHttpConnectionManager();
        final HttpConnectionManagerParams params = this.connectionManager.getParams();
        params.setMaxTotalConnections(this.maxTotalConnections);
        params.setMaxConnectionsPerHost(HostConfiguration.ANY_HOST_CONFIGURATION, this.maxTotalConnections);
        params.setConnectionTimeout(this.connectionTimeout);
        params.setSoTimeout(this.readTimeout);
        
        this.httpClient = new HttpClient(this.connectionManager);
    }
    
    @Override
    public void destroy() {
        this.httpClient = null;
        
        this.connectionManager.shutdown();
        this.connectionManager = null;
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        this.doHttpFilter((HttpServletRequest)req, (HttpServletResponse)res, chain);
    }
    
    protected int getAssertionCount(HttpServletRequest req) {
        final String assertionCountHeader = req.getHeader("Shib-Assertion-Count");
        return NumberUtils.toInt(assertionCountHeader, 0);
    }

    public void doHttpFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        if (logger.isDebugEnabled()) {
            logger.debug("HTTP headers: [" + headersAsString(req) + "]");
        }
        
        final int assertionCount = this.getAssertionCount(req); 
        
        String idp = null, assertion = null, signingKeys = null;

        if (assertionCount > 0) {
            idp = req.getHeader("Shib-Identity-Provider");
            final String firstAssertionHeader = req.getHeader("Shib-Assertion-01");

            if (idpPublicKeysSessionAttributeName != null) {
                signingKeys = req.getHeader("Meta-Signing-Keys");
            }

            if (StringUtils.isNotEmpty(firstAssertionHeader)) {
                if (logger.isInfoEnabled()) {
                    logger.info("Retrieving SAML assertion from the URL: " + firstAssertionHeader);
                }
                final HttpMethod method = new GetMethod(firstAssertionHeader);

                try {
                    int result = this.httpClient.executeMethod(method);

                    if (result >= HttpStatus.SC_OK && result < 300) {
                        assertion = method.getResponseBodyAsString();
                    }
                    else {
                        logger.error("Unsupported HTTP result code when retrieving the SAML assertion: " + result);
                    }
                }
                catch (Exception ex) {
                    // There is nothing that can be done about this exception other than to log it
                    // Exception must be caught and not rethrown to allow normal processing to continue
                    logger.error("Exception caught when trying to retrieve SAML assertion.", ex);
                }
                finally {
                    method.releaseConnection();
                }
            }
            else {
                logger.error("SAML assertion URL not present, but the assertion count was " + assertionCount + ".");
            }
        }
        else {
            logger.warn("SAML assertion count not present or zero");
        }

        // Start with processing the login.  This way if the login process creates a new session,
        // the assertion will remain in the session to be picked up by SamlAssertionUserInfoService
        try {
            chain.doFilter(req, res);
        }
        finally {
            HttpSession session = req.getSession();

            if (assertion != null) {
                session.setAttribute(samlAssertionSessionAttributeName, assertion);
            }
            if (idp != null) {
                session.setAttribute("IdP", idp);
            }
            if (signingKeys != null) {
                session.setAttribute(idpPublicKeysSessionAttributeName, signingKeys);
            }
        }
    }

    private String headersAsString(HttpServletRequest req) {
        StringBuilder sb = new StringBuilder();
        Enumeration<?> headers = req.getHeaderNames();

        while (headers.hasMoreElements()) {
            String headerName = (String) headers.nextElement();
            String headerValue = req.getHeader(headerName);
            sb.append(headerName).append("=").append(headerValue).append(", ");
        }
        return sb.toString();
    }
}
