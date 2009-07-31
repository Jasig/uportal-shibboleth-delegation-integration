/**
 * Copyright 2009 University of Chicago
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jasig.portal.security.provider;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class SamlAssertionFilter implements Filter {

  private final Log log = LogFactory.getLog(this.getClass());
  private String samlAssertionAttributeName = null;
  private String idpPublicKeysAttributeName = null;

  /*
   * Public API.
   */

  public void init(FilterConfig filterConfig) throws ServletException {
    idpPublicKeysAttributeName = filterConfig.getInitParameter("idpPublicKeysSessionAttributeName");
    samlAssertionAttributeName = filterConfig.getInitParameter("samlAssertionSessionAttributeName");
    
    if (samlAssertionAttributeName == null)
      throw new ServletException ("samlAssertionAttributeName parameter is required.");
  }

  public void destroy() {

  }

  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
    log.debug("Entering SamlAssertionFilter.doFilter().");
    log.info("HTTP headers: [" + headersAsString ((HttpServletRequest)req) + "]");
    String header = ((HttpServletRequest)req).getHeader ("Shib-Assertion-Count");
    int assertionCount = 0;
    String idp = null, assertion = null, signingKeys = null;
    
    if (header != null && !header.isEmpty() && (assertionCount = Integer.parseInt(header)) >= 1) {
      idp = ((HttpServletRequest)req).getHeader ("Shib-Identity-Provider");
      header = ((HttpServletRequest)req).getHeader ("Shib-Assertion-01");
      
      if (idpPublicKeysAttributeName != null)
        signingKeys = ((HttpServletRequest)req).getHeader ("Meta-Signing-Keys");

      if (header != null && !header.isEmpty()) {
        log.info("Retrieving SAML assertion from the URL: " + header);
        HttpClient client = new HttpClient ();
        HttpMethod method = new GetMethod(header);
        
        try {
          int result = client.executeMethod(method);
          
          if (result >= HttpStatus.SC_OK && result < 300) {
            assertion = method.getResponseBodyAsString();
          } else {
            log.error("Unsupported HTTP result code when retrieving the SAML assertion: " + result + ".");
          }
        } catch (Exception ex) {
          // There is nothing that can be done about this exception other than to log it
          // Exception must be caught and not rethrown to allow normal processing to continue
          log.error("Exception caught when trying to retrieve SAML assertion.", ex);
        } finally {
          method.releaseConnection();
        }
      } else {
        log.error("SAML assertion URL not present, but the assertion count was " + assertionCount + ".");
      }
    } else {
      log.warn("SAML assertion count not present or zero");
    }
    
    // Start with processing the login.  This way if the login process creates a new session,
    // the assertion will remain in the session to be picked up by SamlAssertionUserInfoService
    try {
      chain.doFilter(req, res);
    }
    finally {
      HttpSession session = ((HttpServletRequest)req).getSession();

      if (assertion != null) {
        session.setAttribute(samlAssertionAttributeName, assertion);
      }
      if (idp != null) {
        session.setAttribute("IdP", idp);
      }
      if (signingKeys != null) {
        session.setAttribute(idpPublicKeysAttributeName, signingKeys);
      }
    }
  }

  private String headersAsString(HttpServletRequest req) {
    StringBuilder sb = new StringBuilder();
    Enumeration headers = req.getHeaderNames();

    while (headers.hasMoreElements()) {
      String headerName = (String)headers.nextElement();
      String headerValue = req.getHeader(headerName);
      sb.append(headerName + "=" + headerValue + ", ");
    }
    return sb.toString();
  }
}
