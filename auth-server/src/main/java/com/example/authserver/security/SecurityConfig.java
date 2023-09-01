package com.example.authserver.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        //设置默认的登录页面地址
        http.exceptionHandling((exceptions) -> exceptions
                .authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/login"))
        );

        return http.build();
    }

    /**
     * 这个也是个Spring Security的过滤器链，用于Spring Security的身份认证。
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                //采用表单认证方式
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * 配置用户信息，或者配置用户数据来源，主要用于用户的检索。
     *
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    /**
     * oauth2 用于第三方认证，RegisteredClientRepository 主要用于管理第三方（每个第三方就是一个客户端）
     *
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret") //不加密
                //客户端接入通过SECRET密码认证方式接入
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                //客户端允许使用的授权模式，授权码模式、Refresh_Token刷新令牌、客户端认证
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                //此客户端允许跳转的URI注册地址
                .redirectUri("http://auth-server:8080/authorized")
                .redirectUri("http://client:8082/login/oauth2/code/demo")
                //此客户端允许使用的授权范围
                .scope("message.read")
                .scope("message.write")
                //是否开启用户手动确认，fasle为自动确认
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * 通过非对称加密生成ACCESS_TOKEN(JWT)的签名部分。
     *
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成秘钥对，为jwkSource提供服务，私钥服务器自身持有，公钥对外开放。
     *
     * @return
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * 配置Authorization Server Provider实例，默认配置即可
     *
     * @return
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            //判断JWT类型是否为ACCESS_TOKEN
            if (context.getTokenType() == OAuth2TokenType.ACCESS_TOKEN) {
                //获得认证对象，即当前登录的用户
                Authentication principal = context.getPrincipal();
                List roles = new ArrayList<>();
                //得到该用户所有的权限信息，即ROLE角色，循环遍历放入roles集合
                for (GrantedAuthority authority : principal.getAuthorities()) {
                    roles.add(authority.getAuthority());
                }
                //写入JWT
            /*
            Payload
            {"sub":"user","aud":"messaging-client","nbf":1669021408,
            "scope":["message.read"],"roles":["ROLE_USER"],
            "iss":"http:\/\/auth-server:8080","exp":1669021708,"iat":1669021408}
             */
                context.getClaims().claim("roles", roles);
            }
        };
    }
}