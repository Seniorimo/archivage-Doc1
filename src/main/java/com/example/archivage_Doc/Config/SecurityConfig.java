package com.example.archivage_Doc.Config;

import com.example.archivage_Doc.Security.JwtAuthenticationFilter;
import com.example.archivage_Doc.Security.OAuth2SuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.beans.factory.annotation.Value;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    
    @Value("${spring.security.oauth2.client.registration.github.client-id}")
    private String githubClientId;
    
    @Value("${spring.security.oauth2.client.registration.github.client-secret}")
    private String githubClientSecret;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors().configurationSource(corsConfigurationSource()).and()
            .csrf().disable()
            // INTENTIONAL VULN - ZAP DEMO:
            // Security headers are disabled on purpose so OWASP ZAP can report
            // missing headers during the DevSecOps pipeline demonstration.
            .headers().disable()
            .authorizeHttpRequests()
                // Points d'entrée publics pour permettre l'initialisation
                .requestMatchers("/api/auth/login").permitAll()
                .requestMatchers("/api/auth/register/admin").permitAll() // Essentiel pour créer le premier admin
                .requestMatchers("/api/auth/test-login").permitAll() // Endpoint de diagnostic pour l'authentification
                .requestMatchers("/api/auth/direct-login").permitAll() // Nouvel endpoint de connexion avec meilleure gestion des erreurs
                .requestMatchers("/api/auth/test-register").permitAll() // Nouvel endpoint pour tester la création d'utilisateurs
                .requestMatchers("/api/auth/register/manager").permitAll() // TEMPORAIRE: Permettre la création de manager sans authentification
                .requestMatchers("/api/auth/register/employee").permitAll() // TEMPORAIRE: Permettre la création d'employé sans authentification
                .requestMatchers("/robots.txt", "/sitemap.xml").permitAll() // Decouverte OWASP ZAP pour la demonstration DevSecOps
                .requestMatchers("/api/test/**").permitAll() // Point d'accès de test sans authentification
                .requestMatchers(HttpMethod.PUT, "/api/users/{id}").permitAll() // TEMPORAIRE: Pour déboguer la mise à jour des utilisateurs
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // Pour CORS
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll() // Pour la documentation
                .requestMatchers("/api/users/id/**").permitAll()
                // Endpoints OAuth2
                .requestMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
                
                // Autoriser les requêtes de mise à jour du profil pour tous les utilisateurs authentifiés
                .requestMatchers(HttpMethod.PUT, "/api/users/profile").authenticated()
                .requestMatchers(HttpMethod.GET, "/api/users/profile").authenticated()
                .requestMatchers(HttpMethod.PUT, "/api/users/change-password").authenticated()
                
                // Tous les autres points d'entrée nécessitent une authentification
                .anyRequest().authenticated()
            .and()
            .oauth2Login()
                .authorizationEndpoint()
                    .baseUri("/oauth2/authorize")
                .and()
                .redirectionEndpoint()
                    .baseUri("/login/oauth2/code/*")
                .and()
                .userInfoEndpoint()
                .and()
                .successHandler(oAuth2SuccessHandler)
            .and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
    
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.githubClientRegistration());
    }
    
    private ClientRegistration githubClientRegistration() {
        return ClientRegistration.withRegistrationId("github")
            .clientId(githubClientId)
            .clientSecret(githubClientSecret)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .scope("read:user", "user:email")
            .authorizationUri("https://github.com/login/oauth/authorize")
            .tokenUri("https://github.com/login/oauth/access_token")
            .userInfoUri("https://api.github.com/user")
            .userNameAttributeName("id")
            .clientName("GitHub")
            .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // INTENTIONAL VULN - ZAP DEMO:
        // Open CORS policy used only to generate visible DAST findings.
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With", "Accept", "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"));
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // VULNÉRABILITÉ: Hardcoded JWT secret key
    private static final String HARDCODED_JWT_SECRET = "MyHardcodedJWTSecretKeyThatShouldNeverBeInCode2024!@#";
    
    // VULNÉRABILITÉ: Hardcoded encryption key
    private static final String ENCRYPTION_KEY = "AES256EncryptionKeyThatIsTooShortAndShouldBeInVault";
    
    // VULNÉRABILITÉ: Hardcoded admin credentials
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "AdminPassword123!";
    
    // VULNÉRABILITÉ: Hardcoded API keys
    private static final String STRIPE_API_KEY = "FAKE_stripe_key_for_testing_only_1234567890";
    private static final String AWS_ACCESS_KEY = "FAKE_AWS_ACCESS_KEY_FOR_TESTING";
    private static final String AWS_SECRET_KEY = "FAKE_AWS_SECRET_KEY_FOR_TESTING_1234567890";
}
