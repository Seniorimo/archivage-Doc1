package com.example.archivage_Doc.Security;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.archivage_Doc.Enums.AuditAction;
import com.example.archivage_Doc.Services.AuditService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final AuditService auditService;
    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    
    // Endpoints publics qui ne nécessitent pas d'authentification
    private final List<String> publicEndpoints = Arrays.asList(
        "/api/auth/login", 
        "/api/auth/register/admin",
        "/api/auth/register/manager",
        "/api/auth/register/employee",
        "/api/auth/test-login",
        "/api/auth/direct-login",
        "/api/auth/test-register",
        "/api/auth/check-username",
        "/api/users/ping",
        "/api/users/echo"
    );
    
    // Préfixes d'URL publics
    private final List<String> publicPrefixes = Arrays.asList(
        // Removed /api/users/ from public prefixes as these endpoints should require authentication
    );

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        String requestPath = request.getRequestURI();

        // Ne pas logger les requêtes pour les ressources statiques ou les requêtes OPTIONS
        if (!requestPath.startsWith("/api/") || request.getMethod().equals("OPTIONS")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Vérifier si c'est un endpoint public
        if (publicEndpoints.stream().anyMatch(requestPath::startsWith)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // Audit de tentative d'accès sans authentification
            try {
                auditService.logAuthAction(
                    AuditAction.LOGIN_FAILURE,
                    "anonymous",
                    "Tentative d'accès à " + requestPath + " sans authentification valide",
                    "ÉCHEC"
                );
            } catch (Exception e) {
                log.error("Erreur lors de l'audit d'une tentative d'accès sans authentification: {}", e.getMessage());
            }
            
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        username = jwtService.extractUsername(jwt);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
                );
                
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
                
                // Ne plus logger chaque requête API comme une authentification réussie
                // Seulement logger les échecs d'authentification
            } else {
                // Audit de l'échec de validation du token
                try {
                    auditService.logAuthAction(
                        AuditAction.LOGIN_FAILURE,
                        username,
                        "Échec de validation du token JWT pour accéder à " + requestPath,
                        "ÉCHEC"
                    );
                } catch (Exception e) {
                    log.error("Erreur lors de l'audit d'un échec de validation de token: {}", e.getMessage());
                }
            }
        } else if (username == null) {
            // Audit de token invalide
            try {
                auditService.logAuthAction(
                    AuditAction.LOGIN_FAILURE,
                    "unknown",
                    "Token JWT invalide (impossible d'extraire le nom d'utilisateur) pour accéder à " + requestPath,
                    "ÉCHEC"
                );
            } catch (Exception e) {
                log.error("Erreur lors de l'audit d'un token invalide: {}", e.getMessage());
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    private boolean isPublicEndpoint(String requestPath) {
        // Vérifier les correspondances exactes
        if (publicEndpoints.contains(requestPath)) {
            return true;
        }
        
        // Vérifier si le chemin commence par un préfixe public
        for (String prefix : publicPrefixes) {
            if (requestPath.startsWith(prefix)) {
                return true;
            }
        }
        
        // Vérifier si le chemin commence par un préfixe public avec wildcard
        return publicEndpoints.stream()
                .anyMatch(path -> path.endsWith("**") && requestPath.startsWith(path.substring(0, path.length() - 2)));
    }
} 