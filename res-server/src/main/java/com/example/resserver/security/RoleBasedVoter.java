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
        //如果用户还没有经过认证，则直接拒绝
        if (authentication == null) {
            return ACCESS_DENIED;
        }

        //得到该用户已被授权的角色对象
        Collection<? extends GrantedAuthority> roles = authentication.getAuthorities(); //ROLE_USER
        //采用Ant语法规则的匹配器，只因为它用起来简单
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        String requestURI = ((FilterInvocation) object).getRequest().getRequestURI(); // /products
        List<Map<String, Object>> dbAuthList = jdbcTemplate.queryForList("select r.role_id,r.role_name,u.url_pattern , u.namespace from role r, role_url_mapping ru , url_resource u where r.role_id = ru.role_id and ru.url_id = u.url_id and u.namespace =?", new Object[]{"res-sample"});
        log.debug("Authority data has been queried:" + dbAuthList);
        //先比较URI，有符合条件的在判断是否有访问权限
        for (Map<String, Object> dbAuthority : dbAuthList) {
            // /user/create     /user/*
            if (antPathMatcher.match(dbAuthority.get("url_pattern").toString(), requestURI)) {
                // /user/* -> USER
                for (GrantedAuthority userRole : roles) {
                    //因为角色名在Spring OAuth2 中固定以ROLE_开头，所以增加上
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