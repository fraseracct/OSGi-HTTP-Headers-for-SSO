package com.axway.generic.ssoagent;

import java.util.*;
import javax.servlet.*;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.osgi.service.http.whiteboard.HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_PATTERN;

public class Activator implements BundleActivator {
    private static final Logger LOGGER = LoggerFactory.getLogger(Activator.class);
    private ServiceRegistration<Filter> registration;
    private static final String SSO_HTTP_HEADER_USERID_PARAM = "sso.httpHeader.uid";
    private static final String SSO_HTTP_HEADER_ROLES_PARAM = "sso.httpHeader.roles";
    private static final String SSO_HTTP_HEADER_ROLES_DELIMITER_PARAM = "sso.httpHeader.roles.delimiter";
    private static final String SSO_LDAP_MAPPINGS_PARAM = "sso.ldap.mappings";

    @Override
    public void start(BundleContext context) throws Exception {    
        Filter authenticationFilter = createAuthenticationFilter(context);
        registerAuthenticationFilter(context, authenticationFilter);
    }

    @Override
    public void stop(BundleContext context) throws Exception {
        unregisterAuthenticationFilter();
    }

    private Filter createAuthenticationFilter(BundleContext context) {
    	String userIdParam = context.getProperty(SSO_HTTP_HEADER_USERID_PARAM);
    	String rolesParam = context.getProperty(SSO_HTTP_HEADER_ROLES_PARAM);
    	String mappingsParam = context.getProperty(SSO_LDAP_MAPPINGS_PARAM);
    	String delimiterParam = context.getProperty(SSO_HTTP_HEADER_ROLES_DELIMITER_PARAM);
    	Configuration configuration = new Configuration(userIdParam,
    			rolesParam, mappingsParam, delimiterParam);

        LOGGER.debug("Authentication filter has been created using parameters: " + userIdParam + "," + rolesParam + "," + mappingsParam + "," + delimiterParam);

        return new SSOAgentFilter(configuration);
    }

    private void registerAuthenticationFilter(BundleContext context, Filter authenticationFilter) {
        Dictionary<String, Object> props = new Hashtable<>();
        props.put(HTTP_WHITEBOARD_FILTER_PATTERN, "/*");
        registration = context.registerService(Filter.class, authenticationFilter, props);
        LOGGER.info("Authentication filter has been registered");
    }

    private void unregisterAuthenticationFilter() {
        if (registration != null) {
            registration.unregister();
            LOGGER.info("Authentication filter has been unregistered");
        }
    }
}