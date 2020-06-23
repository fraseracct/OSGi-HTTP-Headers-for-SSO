package com.axway.generic.ssoagent;

import java.util.*;

public final class Configuration {

	private static final String MAPPING_AUTHORISATION_SEPARATOR = ";";
	private static final String MAPPING_SEPARATOR = ":";

	private final String m_userIdParam;
	private final String m_rolesParam;
	private final String m_delimiterParam;
	private final Map<String, String> m_mappings;

	public Configuration(String userIdParam, String rolesParam,
			String mappingsParam, String delimiterParam) {
		if (userIdParam == null || userIdParam.isEmpty()) {
			throw new IllegalArgumentException("Missing userIdParam");
		}
/*		optional, if roles not delegated to SSO
		if (rolesParam == null || rolesParam.isEmpty()) {
			throw new IllegalArgumentException("Missing rolesParam");
		}
		if (mappingsParam == null || mappingsParam.isEmpty()
				|| !mappingsParam.contains(MAPPING_SEPARATOR)) {
			throw new IllegalArgumentException(
					"Missing or incorrect groupRolesMap");
		}
*/		
		m_userIdParam = userIdParam;
		m_rolesParam = rolesParam;
		m_delimiterParam = delimiterParam;

		if (mappingsParam == null || mappingsParam.isEmpty()
				|| !mappingsParam.contains(MAPPING_SEPARATOR)) {
			m_mappings = Collections.emptyMap();
		}
		else {
			m_mappings = computeMappings(mappingsParam);
		}
	}

	
	public String getDelimiterParam() {
		return m_delimiterParam;
	}

	public String getUserIdParam() {
		return m_userIdParam;
	}

	public String getRolesParam() {
		return m_rolesParam;
	}

	public Map<String, String> getMappings() {
		return m_mappings;
	}

	private Map<String, String> computeMappings(String mappings) {
		Map<String, String> mappingResult = new HashMap<>();
		String[] literalMappings = mappings
				.split(MAPPING_AUTHORISATION_SEPARATOR);
		for (String literalMapping : literalMappings) {
			String[] mappingDescription = literalMapping
					.split(MAPPING_SEPARATOR);
			mappingResult.put(mappingDescription[0], mappingDescription[1]);
		}
		return mappingResult;
	}
}
