package com.example.archivage_Doc.Security;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.example.archivage_Doc.Entities.Department;
import com.example.archivage_Doc.Entities.User;
import com.example.archivage_Doc.Entities.UserRole;
import com.example.archivage_Doc.Enums.DepartmentLevel;
import com.example.archivage_Doc.Repositories.DepartmentRepository;
import com.example.archivage_Doc.Repositories.UserRepository;
import com.example.archivage_Doc.Repositories.UserRoleRepository;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final DepartmentRepository departmentRepository;
    private final UserRoleRepository userRoleRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, 
                                        Authentication authentication) throws IOException, ServletException {
        
        log.info("OAuth2 authentication success handler triggered");
        log.info("Request URI: {}", request.getRequestURI());
        log.info("Request URL: {}", request.getRequestURL());
        log.info("Server name: {}", request.getServerName());
        log.info("Server port: {}", request.getServerPort());
        
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauthToken.getPrincipal();
        
        Map<String, Object> attributes = oAuth2User.getAttributes();
        log.info("GitHub OAuth2 attributes: {}", attributes);
        
        // Récupérer l'identifiant GitHub et l'access token
        Integer githubId = (Integer) attributes.get("id");
        log.info("ID GitHub: {}", githubId);
        
        // Récupérer les informations de l'utilisateur GitHub
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String login = (String) attributes.get("login"); // GitHub username
        
        log.info("User details - email: {}, name: {}, login: {}", email, name, login);
        log.info("Tous les attributs GitHub disponibles: {}", attributes.keySet());
        
        // Première recherche par identifiant GitHub pour voir si l'utilisateur existe déjà
        Optional<User> existingUserByGithubId = userRepository.findByGithubId(githubId);
        if (existingUserByGithubId.isPresent()) {
            log.info("L'utilisateur existe déjà avec l'ID GitHub {}", githubId);
            User existingUser = existingUserByGithubId.get();
            
            // Générer JWT pour l'utilisateur existant
            String jwt = jwtService.generateToken(existingUser);
            redirectWithToken(request, response, existingUser, jwt);
            return;
        }
        
        // Si nous n'avons pas d'email, c'est un problème critique
        if (email == null || email.isEmpty()) {
            log.warn("L'email GitHub est null ou vide. Tentative de recherche avec le nom d'utilisateur.");
            // Comme dernier recours, rechercher par nom d'utilisateur
            Optional<User> userByUsername = userRepository.findByUsername(login);
            if (userByUsername.isPresent()) {
                User existingUser = userByUsername.get();
                log.info("Utilisateur trouvé par nom d'utilisateur: {}", login);
                
                // Mettre à jour l'identifiant GitHub de l'utilisateur
                existingUser.setGithubId(githubId);
                userRepository.save(existingUser);
                
                // Générer JWT pour l'utilisateur existant
                String jwt = jwtService.generateToken(existingUser);
                redirectWithToken(request, response, existingUser, jwt);
                return;
            }
            
            log.error("Impossible de trouver un utilisateur pour GitHub ID {} et username {}", githubId, login);
            email = login + "@github.com"; // Email de dernier recours
        }
        
        // Rechercher l'utilisateur par email de manière insensible à la casse
        String finalEmail = email;
        log.info("Recherche d'utilisateur par email: {}", finalEmail);
        Optional<User> existingUserByEmail = userRepository.findByEmailIgnoreCase(finalEmail);
        
        if (existingUserByEmail.isPresent()) {
            User existingUser = existingUserByEmail.get();
            log.info("Utilisateur trouvé par email: {}, roles: {}", existingUser.getEmail(), existingUser.getUserRoles().size());
            
            // Mettre à jour l'identifiant GitHub de l'utilisateur
            existingUser.setGithubId(githubId);
            userRepository.save(existingUser);
            
            // Générer JWT pour l'utilisateur existant
            String jwt = jwtService.generateToken(existingUser);
            redirectWithToken(request, response, existingUser, jwt);
            return;
        }
        
        // Si on arrive ici, c'est qu'aucun utilisateur existant n'a été trouvé
        log.info("Aucun utilisateur existant trouvé, création d'un nouveau compte.");
        User newUser = createNewUser(finalEmail, name, login, githubId);
        String jwt = jwtService.generateToken(newUser);
        redirectWithToken(request, response, newUser, jwt);
    }

    // Méthode pour créer un nouvel utilisateur
    private User createNewUser(String email, String name, String login, Integer githubId) {
        String firstName = name != null && name.contains(" ") ? name.split(" ")[0] : login;
        String lastName = name != null && name.contains(" ") ? name.split(" ")[1] : "";
        
        User newUser = User.builder()
                .email(email)
                .username(login)
                .firstName(firstName)
                .lastName(lastName)
                .password("") // Pas de mot de passe pour les utilisateurs OAuth
                .githubId(githubId)
                .enabled(true)
                .userRoles(new HashSet<>())
                .build();
        
        User savedUser = userRepository.save(newUser);
        log.info("Nouvel utilisateur GitHub créé: {}", savedUser.getUsername());
        
        // Attribuer un rôle utilisateur par défaut
        Optional<Department> defaultDept = departmentRepository.findByCode("DEFAULT");
        Department department = defaultDept.orElseGet(() -> {
            log.info("Default department not found, creating one");
            Department newDept = Department.builder()
                    .name("Département par défaut")
                    .code("DEFAULT")
                    .description("Département par défaut pour les utilisateurs OAuth")
                    .build();
            return departmentRepository.save(newDept);
        });
        
        // Créer un rôle d'employé basique
        UserRole userRole = UserRole.builder()
                .user(savedUser)
                .department(department)
                .level(DepartmentLevel.EMPLOYEE)
                .permissions(new HashSet<>())
                .build();
        
        userRoleRepository.save(userRole);
        log.info("User role created and saved for user: {}", savedUser.getUsername());
        
        // Ajouter le rôle à l'utilisateur
        savedUser.getUserRoles().add(userRole);
        return userRepository.save(savedUser);
    }

    // Méthode pour rediriger l'utilisateur avec le token
    private void redirectWithToken(HttpServletRequest request, HttpServletResponse response, 
                                  User user, String jwt) throws IOException {
        log.info("JWT généré pour l'utilisateur: {}", user.getUsername());
        
        // Ajouter des informations supplémentaires dans l'URL
        String username = user.getUsername() != null ? user.getUsername() : "";
        String firstName = user.getFirstName() != null ? user.getFirstName() : "";
        String roles = user.getUserRoles().stream()
                .map(r -> r.getLevel().toString())
                .reduce((a, b) -> a + "," + b)
                .orElse("");
        
        // Rediriger vers le frontend avec le token et les informations utilisateur
        String redirectUrl = "http://localhost:5173/oauth/callback?token=" + jwt + 
                           "&username=" + username + 
                           "&firstName=" + firstName +
                           "&roles=" + roles +
                           "&isLogin=true";
        
        log.info("Redirection vers: {}", redirectUrl);
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
} 