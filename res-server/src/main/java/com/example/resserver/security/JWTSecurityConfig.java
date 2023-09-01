package com.example.resserver.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Configuration
public class JWTSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                response.getWriter().println("{code:403,msg:Access is denied}");
            }
        });
        JwtAuthenticationConverter jwtAuthenticationConverter =  new  JwtAuthenticationConverter () ;
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new  JwtRoleConverter()) ;
        http.authorizeRequests().accessDecisionManager(accessDecisionManager()).anyRequest().authenticated();
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt().jwtAuthenticationConverter(jwtAuthenticationConverter));

        return http.build();
    }

    @Resource
    RoleBasedVoter roleBasedVoter;

    @Bean
    //实例化决策器对象
    public AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<? extends Object>> decisionVoters
                = Arrays.asList(
                new WebExpressionVoter(),
                roleBasedVoter,
                new AuthenticatedVoter());
        return new UnanimousBased(decisionVoters);
    }
}