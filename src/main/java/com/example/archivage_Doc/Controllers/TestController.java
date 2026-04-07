package com.example.archivage_Doc.Controllers;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.example.archivage_Doc.Entities.Department;
import com.example.archivage_Doc.Entities.User;
import com.example.archivage_Doc.Entities.UserRole;
import com.example.archivage_Doc.Enums.DepartmentLevel;
import com.example.archivage_Doc.Enums.Permission;
import com.example.archivage_Doc.Repositories.UserRepository;
import com.example.archivage_Doc.Security.JwtService;
import com.example.archivage_Doc.Services.UserService;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
@Slf4j
public class TestController {
    
    private final UserService userService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @GetMapping("/ping")
    @Operation(summary = "Test de connectivité simple")
    public ResponseEntity<Map<String, String>> ping() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "L'API est opérationnelle");
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/echo")
    @Operation(summary = "Renvoie les données reçues pour tester la communication")
    public ResponseEntity<Map<String, Object>> echo(@RequestBody Map<String, Object> request) {
        Map<String, Object> response = new HashMap<>();
        response.put("received", request);
        response.put("status", "success");
        response.put("timestamp", System.currentTimeMillis());
        
        // Ajouter des informations sur l'authentification si disponible
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            response.put("authenticated", SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
            response.put("principal", SecurityContextHolder.getContext().getAuthentication().getName());
            response.put("authorities", SecurityContextHolder.getContext().getAuthentication().getAuthorities().toString());
        } else {
            response.put("authenticated", false);
        }
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/users")
    @Operation(summary = "Récupérer la liste des utilisateurs (endpoint public pour tests)")
    public ResponseEntity<?> getUsers() {
        try {
            log.info("Récupération de la liste des utilisateurs pour test");
            List<User> users = userRepository.findAll();
            
            // Transformer les utilisateurs en DTO simplifiés pour éviter les données sensibles
            List<Map<String, Object>> userDTOs = users.stream()
                .map(user -> {
                    Map<String, Object> dto = new HashMap<>();
                    dto.put("id", user.getId());
                    dto.put("username", user.getUsername());
                    
                    // Déterminer le rôle principal
                    String role = "EMPLOYEE";
                    Department userDept = null;
                    
                    for (UserRole userRole : user.getUserRoles()) {
                        if (userDept == null) {
                            userDept = userRole.getDepartment();
                        }
                        
                        if (userRole.getLevel() == DepartmentLevel.ADMIN) {
                            role = "ADMIN";
                            break;
                        } else if (userRole.getLevel() == DepartmentLevel.MANAGER) {
                            role = "MANAGER";
                        }
                    }
                    dto.put("role", role);
                    
                    // Ajouter les permissions
                    Set<String> permissions = user.getUserRoles().stream()
                        .flatMap(userRole -> userRole.getPermissions().stream())
                        .map(Permission::name)
                        .collect(Collectors.toSet());
                    dto.put("permissions", permissions);
                    
                    // Ajouter le département
                    if (userDept != null) {
                        Map<String, Object> deptInfo = new HashMap<>();
                        deptInfo.put("id", userDept.getId());
                        deptInfo.put("name", userDept.getName());
                        deptInfo.put("code", userDept.getCode());
                        dto.put("department", deptInfo);
                    }
                    
                    return dto;
                })
                .collect(Collectors.toList());
            
            return ResponseEntity.ok(userDTOs);
        } catch (Exception e) {
            log.error("Erreur lors de la récupération des utilisateurs: {}", e.getMessage(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Erreur lors de la récupération des utilisateurs: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse);
        }
    }
    
    @GetMapping("/users/{id}")
    @Operation(summary = "Récupérer un utilisateur par son ID (endpoint public pour tests)")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        try {
            log.info("Récupération de l'utilisateur avec ID {} pour test", id);
            User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec l'ID: " + id));
            
            // Créer un DTO simplifié
            Map<String, Object> dto = new HashMap<>();
            dto.put("id", user.getId());
            dto.put("username", user.getUsername());
            
            // Déterminer le rôle principal
            String role = "EMPLOYEE";
            Department userDept = null;
            
            for (UserRole userRole : user.getUserRoles()) {
                if (userDept == null) {
                    userDept = userRole.getDepartment();
                }
                
                if (userRole.getLevel() == DepartmentLevel.ADMIN) {
                    role = "ADMIN";
                    break;
                } else if (userRole.getLevel() == DepartmentLevel.MANAGER) {
                    role = "MANAGER";
                }
            }
            dto.put("role", role);
            
            // Ajouter les permissions
            Set<String> permissions = user.getUserRoles().stream()
                .flatMap(userRole -> userRole.getPermissions().stream())
                .map(Permission::name)
                .collect(Collectors.toSet());
            dto.put("permissions", permissions);
            
            // Ajouter le département
            if (userDept != null) {
                Map<String, Object> deptInfo = new HashMap<>();
                deptInfo.put("id", userDept.getId());
                deptInfo.put("name", userDept.getName());
                deptInfo.put("code", userDept.getCode());
                dto.put("department", deptInfo);
            }
            
            return ResponseEntity.ok(dto);
        } catch (Exception e) {
            log.error("Erreur lors de la récupération de l'utilisateur: {}", e.getMessage(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Erreur lors de la récupération de l'utilisateur: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse);
        }
    }
    
    @PutMapping("/users/{id}")
    @Operation(summary = "Mettre à jour un utilisateur (endpoint public pour tests)")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody Map<String, Object> userData) {
        try {
            log.info("Mise à jour de l'utilisateur avec ID {} pour test", id);
            log.info("Données reçues: {}", userData);
            
            User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec l'ID: " + id));
            
            // Mettre à jour les champs de base
            if (userData.containsKey("username")) {
                user.setUsername((String) userData.get("username"));
            }
            
            // Mettre à jour le mot de passe si fourni
            if (userData.containsKey("password") && userData.get("password") != null) {
                String newPassword = (String) userData.get("password");
                if (!newPassword.trim().isEmpty()) {
                    // Encoder le mot de passe avec BCrypt
                    user.setPassword(passwordEncoder.encode(newPassword));
                    log.info("Mot de passe mis à jour pour l'utilisateur ID: {}", id);
                }
            }
            
            // Mettre à jour le rôle si fourni
            if (userData.containsKey("role") && userData.get("role") != null) {
                String newRole = ((String) userData.get("role")).toUpperCase();
                log.info("Tentative de changement de rôle pour l'utilisateur {} vers {}", id, newRole);
                
                // Trouver tous les rôles actuels de l'utilisateur
                Set<UserRole> userRoles = user.getUserRoles();
                if (userRoles == null || userRoles.isEmpty()) {
                    log.warn("L'utilisateur {} n'a pas de rôles définis", id);
                } else {
                    // Modifier le niveau du premier rôle
                    for (UserRole userRole : userRoles) {
                        DepartmentLevel newLevel;
                        switch (newRole) {
                            case "ADMIN":
                                newLevel = DepartmentLevel.ADMIN;
                                break;
                            case "MANAGER":
                                newLevel = DepartmentLevel.MANAGER;
                                break;
                            case "EMPLOYEE":
                                newLevel = DepartmentLevel.EMPLOYEE;
                                break;
                            default:
                                log.warn("Rôle non reconnu: {}, utilisation d'EMPLOYEE par défaut", newRole);
                                newLevel = DepartmentLevel.EMPLOYEE;
                        }
                        
                        // Mise à jour du niveau et ajustement des permissions selon le nouveau rôle
                        userRole.setLevel(newLevel);
                        
                        // Ajuster les permissions selon le nouveau rôle
                        Set<Permission> permissions = new HashSet<>();
                        if (newLevel == DepartmentLevel.ADMIN) {
                            permissions.add(Permission.DOCUMENT_READ);
                            permissions.add(Permission.DOCUMENT_WRITE);
                            permissions.add(Permission.DOCUMENT_DELETE);
                            permissions.add(Permission.USER_MANAGE);
                            permissions.add(Permission.ADMIN_CREATE);
                            permissions.add(Permission.MANAGER_CREATE);
                        } else if (newLevel == DepartmentLevel.MANAGER) {
                            permissions.add(Permission.DOCUMENT_READ);
                            permissions.add(Permission.DOCUMENT_WRITE);
                            permissions.add(Permission.USER_MANAGE);
                            permissions.add(Permission.MANAGER_CREATE);
                        } else { // EMPLOYEE
                            permissions.add(Permission.DOCUMENT_READ);
                        }
                        
                        userRole.setPermissions(permissions);
                        log.info("Rôle mis à jour pour l'utilisateur ID {}: {} avec permissions: {}", 
                                id, newLevel, permissions);
                    }
                }
            }
            
            // Enregistrer les modifications
            userRepository.save(user);
            
            // Construire la réponse
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Utilisateur mis à jour avec succès");
            response.put("id", user.getId());
            response.put("username", user.getUsername());
            
            // Ajouter les informations de rôle dans la réponse
            String role = "UNKNOWN";
            Set<String> permissions = new HashSet<>();
            for (UserRole userRole : user.getUserRoles()) {
                if (userRole.getLevel() == DepartmentLevel.ADMIN) {
                    role = "ADMIN";
                } else if (userRole.getLevel() == DepartmentLevel.MANAGER && !role.equals("ADMIN")) {
                    role = "MANAGER";
                } else if (userRole.getLevel() == DepartmentLevel.EMPLOYEE && 
                          !role.equals("ADMIN") && !role.equals("MANAGER")) {
                    role = "EMPLOYEE";
                }
                
                // Collecter toutes les permissions
                for (Permission permission : userRole.getPermissions()) {
                    permissions.add(permission.name());
                }
            }
            response.put("role", role);
            response.put("permissions", permissions);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Erreur lors de la mise à jour de l'utilisateur: {}", e.getMessage(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Erreur lors de la mise à jour de l'utilisateur: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse);
        }
    }
    
    @DeleteMapping("/users/{id}")
    @Operation(summary = "Supprimer un utilisateur (endpoint public pour tests)")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        try {
            log.info("Suppression de l'utilisateur avec ID {} pour test", id);
            
            // Vérifier si l'utilisateur existe
            if (!userRepository.existsById(id)) {
                Map<String, Object> notFoundResponse = new HashMap<>();
                notFoundResponse.put("status", "error");
                notFoundResponse.put("message", "Utilisateur non trouvé avec l'ID: " + id);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(notFoundResponse);
            }
            
            // Supprimer l'utilisateur
            userRepository.deleteById(id);
            
            // Construire la réponse
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Utilisateur supprimé avec succès");
            response.put("id", id);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Erreur lors de la suppression de l'utilisateur: {}", e.getMessage(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Erreur lors de la suppression de l'utilisateur: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse);
        }
    }

    @GetMapping("/user-profile")
    @Operation(summary = "Récupérer le profil de l'utilisateur connecté (endpoint public pour tests)")
    public ResponseEntity<?> getUserProfile() {
        try {
            // Récupérer l'utilisateur actuellement authentifié
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || "anonymousUser".equals(authentication.getName())) {
                log.warn("Aucun utilisateur authentifié trouvé ou utilisateur anonyme");
                
                // Essayer de récupérer le token depuis la requête
                String token = null;
                try {
                    HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
                    String authHeader = request.getHeader("Authorization");
                    if (authHeader != null && authHeader.startsWith("Bearer ")) {
                        token = authHeader.substring(7);
                    }
                } catch (Exception e) {
                    log.error("Erreur lors de la récupération du token: {}", e.getMessage());
                }
                
                // Si un token est présent, essayer d'extraire le nom d'utilisateur
                if (token != null) {
                    try {
                        String username = jwtService.extractUsername(token);
                        log.info("Nom d'utilisateur extrait du token: {}", username);
                        
                        // Rechercher l'utilisateur par nom d'utilisateur
                        User user = userRepository.findByUsername(username)
                            .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec le nom: " + username));
                        
                        return buildUserProfileResponse(user);
                    } catch (Exception e) {
                        log.error("Erreur lors de l'extraction du nom d'utilisateur du token: {}", e.getMessage());
                    }
                }
                
                // Réponse par défaut avec les informations basiques extraites du token
                Map<String, Object> defaultProfile = new HashMap<>();
                defaultProfile.put("username", authentication != null ? authentication.getName() : "anonymousUser");
                defaultProfile.put("status", "warning");
                defaultProfile.put("message", "Profil utilisateur limité - authentification incomplète");
                
                return ResponseEntity.ok(defaultProfile);
            }
            
            String username = authentication.getName();
            log.info("Récupération du profil pour l'utilisateur: {}", username);
            
            // Rechercher l'utilisateur par nom d'utilisateur
            Optional<User> userOpt = userRepository.findByUsername(username);
            
            if (userOpt.isEmpty()) {
                log.warn("Utilisateur authentifié mais non trouvé dans la base de données: {}", username);
                
                // Créer un profil par défaut basé sur l'authentification
                Map<String, Object> defaultProfile = new HashMap<>();
                defaultProfile.put("username", username);
                defaultProfile.put("status", "warning");
                defaultProfile.put("message", "Profil utilisateur limité - utilisateur non trouvé en base de données");
                
                // Ajouter les informations d'autorisation si disponibles
                if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
                    Set<String> permissions = authentication.getAuthorities().stream()
                        .map(a -> a.getAuthority())
                        .collect(Collectors.toSet());
                    defaultProfile.put("permissions", permissions);
                }
                
                return ResponseEntity.ok(defaultProfile);
            }
            
            // Utilisateur trouvé, construire la réponse complète
            return buildUserProfileResponse(userOpt.get());
            
        } catch (Exception e) {
            log.error("Erreur lors de la récupération du profil utilisateur: {}", e.getMessage(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Erreur lors de la récupération du profil: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse);
        }
    }

    // Méthode utilitaire pour construire la réponse de profil utilisateur
    private ResponseEntity<?> buildUserProfileResponse(User user) {
        // Créer un DTO simplifié
        Map<String, Object> profileDto = new HashMap<>();
        profileDto.put("id", user.getId());
        profileDto.put("username", user.getUsername());
        
        // Déterminer le rôle principal
        String role = "EMPLOYEE";
        Department userDept = null;
        
        for (UserRole userRole : user.getUserRoles()) {
            if (userDept == null) {
                userDept = userRole.getDepartment();
            }
            
            if (userRole.getLevel() == DepartmentLevel.ADMIN) {
                role = "ADMIN";
                break;
            } else if (userRole.getLevel() == DepartmentLevel.MANAGER) {
                role = "MANAGER";
            }
        }
        profileDto.put("role", role);
        
        // Ajouter les permissions
        Set<String> permissions = user.getUserRoles().stream()
            .flatMap(userRole -> userRole.getPermissions().stream())
            .map(Permission::name)
            .collect(Collectors.toSet());
        profileDto.put("permissions", permissions);
        
        // Ajouter le département
        if (userDept != null) {
            Map<String, Object> deptInfo = new HashMap<>();
            deptInfo.put("id", userDept.getId());
            deptInfo.put("name", userDept.getName());
            deptInfo.put("code", userDept.getCode());
            profileDto.put("department", deptInfo);
        }
        
        return ResponseEntity.ok(profileDto);
    }
}