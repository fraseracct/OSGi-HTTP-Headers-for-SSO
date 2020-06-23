package com.axway.generic.ssoagent;

import java.io.*;
import java.security.Principal;
import java.util.*;

import javax.servlet.*;
import javax.servlet.http.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSOAgentFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory
            .getLogger(SSOAgentFilter.class);

    private final Configuration m_configuration;

    public SSOAgentFilter(Configuration configuration) {
        m_configuration = configuration;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        // determine if the request contains authentication information
        String username = trimValue(httpRequest.getHeader(m_configuration.getUserIdParam()));

        Enumeration headerNames = httpRequest.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = (String) headerNames.nextElement();
            LOGGER.debug("HEADER " + headerName + "=" + httpRequest.getHeader(headerName));
        }

        if (username != null) {
            LOGGER.debug("Authenticated user '{}' found in the HTTP request", username);

            // extract user roles, if required
            Set<String> roles;
            String rolesParam = m_configuration.getRolesParam();
            if (rolesParam != null && !rolesParam.isEmpty()) {
                String userRoles = trimValue(httpRequest.getHeader(rolesParam));
                LOGGER.debug("Roles '{}' found in the HTTP request", userRoles);

                if (userRoles != null && !userRoles.isEmpty()) {
                    String delimiter = trimValue(m_configuration.getDelimiterParam());
                    if (delimiter == null) {
                        delimiter = "[,\\s]+"; // default
                    }
                    roles = new HashSet<>(Arrays.asList(userRoles.split(delimiter)));
                    LOGGER.debug("Delimited Roles='{}'", roles.toString());
                } else {
                    roles = Collections.emptySet();
                }
            } else {
                roles = Collections.emptySet();
            }

            // Make sure any domain name prefix is stripped from the username (eg. "AD/user" becomes "user"), as ADI does not support it.
            // Only the following characters are possible for a user name:
            // 		lowercase letters, numbers, dashes (-), underscores (_), periods (.) and at signs (@)
            int domainIndex = username.indexOf ("\\");
            if (domainIndex > -1) {
            	username = username.substring(domainIndex + 1);
            }

            // Supply user name and role via request wrapping
            request = new AuthenticatedHttpServletRequestWrapper(httpRequest, username, roles, m_configuration.getMappings());
        } else {
            LOGGER.info("No authenticated user found in the HTTP request");
        }

        // continue request processing in the filter chain
        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // should be empty, use initialization through constructor
    }

    @Override
    public void destroy() {
        // should be empty, if a release mechanism is needed, use an ad-hoc method to be called by the activator
    }

    private String trimValue(String value) {
        if (value != null) {
            value = value.trim();
            if (value.isEmpty()) {
                value = null;
            }
        }
        return value;
    }

    private static class AuthenticatedHttpServletRequestWrapper extends HttpServletRequestWrapper {

        private final Principal principal;
        private final Set<String> roles;
        private final Map<String, String> roleMappings;

        public AuthenticatedHttpServletRequestWrapper(HttpServletRequest request, String username, Set<String> roles, Map<String, String> roleMappings) {
            super(request);
            principal = new PrincipalImpl(username);
            this.roles = roles;
            this.roleMappings = roleMappings;
        }

        @Override
        public Principal getUserPrincipal() {
            return principal;
        }

        @Override
        public boolean isUserInRole(String adiRole) {
            String ldapRoleName = roleMappings.get(adiRole);
            return roles.contains(ldapRoleName);
        }
    }

    private static class PrincipalImpl implements Principal {

        private final String name;

        private PrincipalImpl(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object obj) {
            return (this == obj) || ((obj instanceof PrincipalImpl) && name.equals(((PrincipalImpl) obj).name));
        }

        @Override
        public int hashCode() {
            return name.hashCode();
        }

        @Override
        public String toString() {
            return name;
        }
    }
}
