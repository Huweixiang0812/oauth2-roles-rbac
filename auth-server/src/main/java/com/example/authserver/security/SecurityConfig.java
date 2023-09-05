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
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        // Default login page
        http.exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

        return http.build();
    }

    /**
     * This is also a Spring Security filter chain used for Spring Security authentication.
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                // Form login authentication
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * Configure user information or the source of user data, mainly used for user retrieval.
     *
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    /**
     * OAuth2 for third-party authentication. RegisteredClientRepository is mainly used to manage third parties (each third party is a client).
     *
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Define a registered client with a unique ID.
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                // Set the client ID and client secret (in plaintext, for demonstration purposes).
                .clientId("messaging-client").clientSecret("{noop}secret") // Not encrypted
                // Specify the client authentication method as CLIENT_SECRET_BASIC.
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // Define the allowed authorization grant types for this client.
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                // Register the URIs where this client is allowed to redirect to after authorization.
                .redirectUri("http://auth-server:8080/authorized").redirectUri("http://client:8082/login/oauth2/code/demo")
                // Define the scopes (permissions) that this client can request.
                .scope("message.read").scope("message.write")
                // Specify whether user manual consent is required (false for automatic consent).
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build()).build();

        // Create an in-memory repository and return the registered client.
        return new InMemoryRegisteredClientRepository(registeredClient);
    }


    /**
     * Generate the signature part of ACCESS_TOKEN (JWT) through asymmetric encryption.
     *
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * Generate a key pair for use by jwkSource. The private key is held by the server, and the public key is exposed externally.
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
     * Configure Authorization Server Provider instance. Default configuration is sufficient.
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
            // Check if the JWT type is ACCESS_TOKEN
            if (context.getTokenType() == OAuth2TokenType.ACCESS_TOKEN) {
                // Get the authentication object, which is the currently logged-in user
                Authentication principal = context.getPrincipal();
                List roles = new ArrayList<>();
                // Get all the permissions (ROLE roles) for this user, loop through and add them to the roles list
                for (GrantedAuthority authority : principal.getAuthorities()) {
                    roles.add(authority.getAuthority());
                }
                // Write to JWT
            /*
            Payload
            {"sub":"user","aud":"messaging-client","nbf":1693904007,"scope":["message.read"],
            "roles":["ROLE_USER"],"iss":"http:\/\/auth-server:8080",
            "exp":1693904307,"iat":1693904007}
             */
                context.getClaims().claim("roles", roles);
            }
        };
    }
}
