package com.example.resserver.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.annotation.Resource;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class RoleBasedVoter implements AccessDecisionVoter<Object> {

    @Resource
    private JdbcTemplate jdbcTemplate;

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        // Deny access if the user is not authenticated.
        if (authentication == null) {
            return ACCESS_DENIED;
        }
        // Get the roles that the user has been authorized.
        Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();
        // Use the Ant-style syntax matcher for simplicity.
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        String requestURI = ((FilterInvocation) object).getRequest().getRequestURI(); // Example: /products
        // Query the database for authorization data.
        List<Map<String, Object>> dbAuthList = jdbcTemplate.queryForList("select r.role_id, r.role_name, u.url_pattern, u.namespace from role r, role_url_mapping ru, url_resource u where r.role_id = ru.role_id and ru.url_id = u.url_id and u.namespace =?", new Object[]{"res-sample"});

        log.debug("Authority data has been queried: " + dbAuthList);
        // First, compare URIs and then check for access permissions.
        for (Map<String, Object> dbAuthority : dbAuthList) {
            // Example: /user/create matches /user/*
            if (antPathMatcher.match(dbAuthority.get("url_pattern").toString(), requestURI)) {
                // Example: /user/* matches USER role
                for (GrantedAuthority userRole : roles) {
                    // Role names in Spring OAuth2 typically start with ROLE_
                    // So, we add it for comparison.
                    String dbRoleName = "role_" + dbAuthority.get("role_name").toString().toLowerCase();
                    if (dbRoleName.equals(userRole.getAuthority().toLowerCase())) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }

        return ACCESS_DENIED;
    }


    @Override
    public boolean supports(Class clazz) {
        return true;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }
}