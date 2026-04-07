package com.example.archivage_Doc.Security;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.Comparator;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.example.archivage_Doc.Entities.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        
        // Ajouter les permissions au token JWT
        if (userDetails instanceof User) {
            User user = (User) userDetails;
            
            // Extraire les permissions sous forme de liste
            List<String> permissions = user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            
            claims.put("permissions", permissions);
            
            // Log pour le débogage
            System.out.println("Generating token for user: " + user.getUsername());
            System.out.println("Adding permissions to token: " + permissions);
            
            // Determiner le rôle principal (ADMIN, MANAGER, EMPLOYEE)
            String mainRole = determineMainRole(user);
            claims.put("role", mainRole);
            System.out.println("Setting main role in token: " + mainRole);
                
            // Ajouter le département principal
            user.getUserRoles().stream()
                .findFirst()
                .ifPresent(role -> {
                    if (role.getDepartment() != null) {
                        claims.put("department", role.getDepartment().getCode());
                        System.out.println("Setting department in token: " + role.getDepartment().getCode());
                    } else {
                        claims.put("department", "DEFAULT");
                        System.out.println("Setting default department in token");
                    }
                });
        }
        
        return generateToken(claims, userDetails);
    }
    
    // Méthode pour déterminer le rôle principal de l'utilisateur
    private String determineMainRole(User user) {
        // Vérifier tous les rôles et prendre le niveau le plus élevé (ADMIN > MANAGER > EMPLOYEE)
        return user.getUserRoles().stream()
            .map(role -> role.getLevel())
            .min(Comparator.comparingInt(Enum::ordinal)) // ADMIN est généralement ordinal=0
            .map(Enum::name)
            .orElse("EMPLOYEE"); // Par défaut
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
} 