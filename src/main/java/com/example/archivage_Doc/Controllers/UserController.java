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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
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
import com.example.archivage_Doc.Repositories.DepartmentRepository;
import com.example.archivage_Doc.Repositories.UserRepository;
import com.example.archivage_Doc.Security.JwtService;
import com.example.archivage_Doc.Services.UserService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Validated
@Slf4j
public class UserController {
    private final UserService userService;
    private final UserRepository userRepository;
    private final DepartmentRepository departmentRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Operation(summary = "Lister tous les utilisateurs")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Liste des utilisateurs récupérée"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    @GetMapping
    @PreAuthorize("hasAuthority('USER_MANAGE')")
    public ResponseEntity<?> getAllUsers() {
        try {
            log.info("Récupération de la liste des utilisateurs");
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

    @Operation(summary = "Récupérer un utilisateur par son username")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Utilisateur trouvé"),
        @ApiResponse(responseCode = "404", description = "Utilisateur non trouvé"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    @GetMapping("/{username}")
    @PreAuthorize("hasAuthority('USER_MANAGE') or #username == authentication.principal.username")
    public ResponseEntity<?> getUser(@PathVariable @NotBlank(message = "Le username ne peut pas être vide") String username) {
        try {
            log.info("Récupération de l'utilisateur avec username {}", username);
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec le username: " + username));
            
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
    
    @Operation(summary = "Mettre à jour le département d'un utilisateur")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Département de l'utilisateur mis à jour"),
        @ApiResponse(responseCode = "404", description = "Utilisateur ou département non trouvé"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    @PutMapping("/{id}/department")
    @PreAuthorize("hasAuthority('USER_MANAGE')")
    public ResponseEntity<?> updateUserDepartment(@PathVariable Long id, @RequestBody Map<String, Object> request) {
        try {
            log.info("Mise à jour du département pour l'utilisateur ID: {}", id);
            
            if (!request.containsKey("departmentId")) {
                return ResponseEntity.badRequest().body(Map.of(
                    "status", "error", 
                    "message", "Le champ departmentId est requis"
                ));
            }
            
            Long departmentId = Long.valueOf(request.get("departmentId").toString());
            
            // Récupérer l'utilisateur
            User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec l'ID: " + id));
            
            // Récupérer le département
            Department department = departmentRepository.findById(departmentId)
                .orElseThrow(() -> new RuntimeException("Département non trouvé avec l'ID: " + departmentId));
            
            // Mettre à jour le département de l'utilisateur
            user.setDepartment(department);
            
            // Mettre à jour le département dans les rôles de l'utilisateur
            user.getUserRoles().forEach(role -> role.setDepartment(department));
            
            // Sauvegarder les modifications
            userRepository.save(user);
            
            log.info("Département mis à jour pour l'utilisateur ID: {} vers le département ID: {} ({})", 
                id, departmentId, department.getName());
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Département de l'utilisateur mis à jour avec succès");
            response.put("userId", user.getId());
            response.put("username", user.getUsername());
            response.put("departmentId", department.getId());
            response.put("departmentName", department.getName());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Erreur lors de la mise à jour du département: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of(
                "status", "error",
                "message", "Erreur lors de la mise à jour du département: " + e.getMessage()
            ));
        }
    }
    
    @Operation(summary = "Mettre à jour un utilisateur")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Utilisateur mis à jour"),
        @ApiResponse(responseCode = "404", description = "Utilisateur non trouvé"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_MANAGE') or @userSecurity.isCurrentUser(#id)")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody Map<String, Object> userData) {
        try {
            log.info("Début de la mise à jour de l'utilisateur avec ID {}", id);
            log.info("Données reçues: {}", userData);
            
            User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec l'ID: " + id));
            
            log.info("Utilisateur trouvé: {}", user.getUsername());
            
            // Mettre à jour les champs de base
            if (userData.containsKey("username") && userData.get("username") != null) {
                user.setUsername(userData.get("username").toString());
                log.info("Username mis à jour: {}", userData.get("username"));
            }
            
            // Mettre à jour les informations personnelles
            if (userData.containsKey("firstName") && userData.get("firstName") != null) {
                user.setFirstName(userData.get("firstName").toString());
                log.info("Prénom mis à jour pour l'utilisateur ID {}: {}", id, userData.get("firstName"));
            } else {
                log.info("Aucun prénom fourni ou prénom null");
            }
            
            if (userData.containsKey("lastName") && userData.get("lastName") != null) {
                user.setLastName(userData.get("lastName").toString());
                log.info("Nom mis à jour pour l'utilisateur ID {}: {}", id, userData.get("lastName"));
            } else {
                log.info("Aucun nom fourni ou nom null");
            }
            
            if (userData.containsKey("email") && userData.get("email") != null) {
                user.setEmail(userData.get("email").toString());
                log.info("Email mis à jour pour l'utilisateur ID {}: {}", id, userData.get("email"));
            } else {
                log.info("Aucun email fourni ou email null");
            }
            
            if (userData.containsKey("phoneNumber") && userData.get("phoneNumber") != null) {
                user.setPhoneNumber(userData.get("phoneNumber").toString());
                log.info("Numéro de téléphone mis à jour pour l'utilisateur ID {}: {}", id, userData.get("phoneNumber"));
            } else {
                log.info("Aucun numéro de téléphone fourni ou numéro null");
            }
            
            // Mettre à jour le mot de passe si fourni
            if (userData.containsKey("password") && userData.get("password") != null) {
                String newPassword = (String) userData.get("password");
                if (!newPassword.trim().isEmpty()) {
                    user.setPassword(passwordEncoder.encode(newPassword));
                    log.info("Mot de passe mis à jour pour l'utilisateur ID: {}", id);
                }
            }
            
            // Mettre à jour le rôle si fourni
            if (userData.containsKey("role") && userData.get("role") != null) {
                String newRole = ((String) userData.get("role")).toUpperCase();
                
                Set<UserRole> userRoles = user.getUserRoles();
                if (userRoles != null && !userRoles.isEmpty()) {
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
            
            // Sauvegarder les modifications
            log.info("Sauvegarde des modifications pour l'utilisateur ID: {}", id);
            User savedUser = userRepository.save(user);
            log.info("Utilisateur sauvegardé avec succès, ID: {}", savedUser.getId());
            
            // Construire la réponse avec toutes les informations mises à jour
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Utilisateur mis à jour avec succès");
            response.put("id", savedUser.getId());
            response.put("username", savedUser.getUsername());
            response.put("firstName", savedUser.getFirstName());
            response.put("lastName", savedUser.getLastName());
            response.put("email", savedUser.getEmail());
            response.put("phoneNumber", savedUser.getPhoneNumber());
            
            log.info("Réponse préparée: {}", response);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Erreur lors de la mise à jour de l'utilisateur: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of(
                "status", "error",
                "message", "Erreur lors de la mise à jour de l'utilisateur: " + e.getMessage()
            ));
        }
    }
    
    @Operation(summary = "Supprimer un utilisateur")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Utilisateur supprimé"),
        @ApiResponse(responseCode = "404", description = "Utilisateur non trouvé"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_MANAGE')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        try {
            log.info("Suppression de l'utilisateur avec ID {}", id);
            
            if (!userRepository.existsById(id)) {
                return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", "Utilisateur non trouvé avec l'ID: " + id
                ));
            }
            
            userRepository.deleteById(id);
            
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Utilisateur supprimé avec succès",
                "id", id
            ));
        } catch (Exception e) {
            log.error("Erreur lors de la suppression de l'utilisateur: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of(
                "status", "error",
                "message", "Erreur lors de la suppression de l'utilisateur: " + e.getMessage()
            ));
        }
    }

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
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            response.put("authenticated", auth.isAuthenticated());
            response.put("principal", auth.getName());
            response.put("authorities", auth.getAuthorities().toString());
        } else {
            response.put("authenticated", false);
        }
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/profile")
    @Operation(summary = "Récupérer le profil de l'utilisateur connecté")
    @PreAuthorize("isAuthenticated()")
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
                
                Map<String, Object> defaultProfile = new HashMap<>();
                defaultProfile.put("username", authentication != null ? authentication.getName() : "anonymousUser");
                defaultProfile.put("status", "warning");
                defaultProfile.put("message", "Profil utilisateur limité - authentification incomplète");
                
                return ResponseEntity.ok(defaultProfile);
            }
            
            String username = authentication.getName();
            log.info("Récupération du profil pour l'utilisateur: {}", username);
            
            Optional<User> userOpt = userRepository.findByUsername(username);
            
            if (userOpt.isEmpty()) {
                log.warn("Utilisateur authentifié mais non trouvé dans la base de données: {}", username);
                
                Map<String, Object> defaultProfile = new HashMap<>();
                defaultProfile.put("username", username);
                defaultProfile.put("status", "warning");
                defaultProfile.put("message", "Profil utilisateur limité - utilisateur non trouvé en base de données");
                
                if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
                    Set<String> permissions = authentication.getAuthorities().stream()
                        .map(a -> a.getAuthority())
                        .collect(Collectors.toSet());
                    defaultProfile.put("permissions", permissions);
                }
                
                return ResponseEntity.ok(defaultProfile);
            }
            
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
        Map<String, Object> profileDto = new HashMap<>();
        profileDto.put("id", user.getId());
        profileDto.put("username", user.getUsername());
        profileDto.put("firstName", user.getFirstName());
        profileDto.put("lastName", user.getLastName());
        profileDto.put("email", user.getEmail());
        profileDto.put("phoneNumber", user.getPhoneNumber());
        
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
        
        Set<String> permissions = user.getUserRoles().stream()
            .flatMap(userRole -> userRole.getPermissions().stream())
            .map(Permission::name)
            .collect(Collectors.toSet());
        profileDto.put("permissions", permissions);
        
        if (userDept != null) {
            Map<String, Object> deptInfo = new HashMap<>();
            deptInfo.put("id", userDept.getId());
            deptInfo.put("name", userDept.getName());
            deptInfo.put("code", userDept.getCode());
            profileDto.put("department", deptInfo);
        }
        
        return ResponseEntity.ok(profileDto);
    }

    @Operation(summary = "Permettre à un utilisateur de mettre à jour son propre mot de passe")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Mot de passe mis à jour avec succès"),
        @ApiResponse(responseCode = "400", description = "Données invalides"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    @PutMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> passwordData) {
        try {
            // Récupérer l'utilisateur authentifié
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String username = auth.getName();
            
            log.info("Demande de changement de mot de passe pour l'utilisateur: {}", username);
            
            // Vérifier que les données requises sont présentes
            if (!passwordData.containsKey("newPassword") || passwordData.get("newPassword") == null 
                    || passwordData.get("newPassword").trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", "Le nouveau mot de passe est requis"
                ));
            }
            
            String newPassword = passwordData.get("newPassword").trim();
            
            // Trouver l'utilisateur dans la base de données
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé: " + username));
            
            // Mettre à jour le mot de passe
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            
            log.info("Mot de passe mis à jour avec succès pour l'utilisateur: {}", username);
            
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Mot de passe mis à jour avec succès"
            ));
        } catch (Exception e) {
            log.error("Erreur lors du changement de mot de passe: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "status", "error",
                "message", "Erreur lors du changement de mot de passe: " + e.getMessage()
            ));
        }
    }

    // Méthode pour récupérer les détails d'un utilisateur spécifique par nom d'utilisateur
    @GetMapping("/profile/{username}")
    @PreAuthorize("hasAuthority('USER_MANAGE')")
    public ResponseEntity<?> getUserProfileByUsername(@PathVariable String username) {
        try {
            log.info("Récupération du profil pour l'utilisateur spécifique: {}", username);
            
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec le nom: " + username));
            
            return buildUserProfileResponse(user);
        } catch (Exception e) {
            log.error("Erreur lors de la récupération du profil de l'utilisateur {}: {}", username, e.getMessage(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Erreur lors de la récupération du profil: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse);
        }
    }

    @GetMapping("/id/{id}")
    // Temporairement désactivé pour le débogage
    // @PreAuthorize("hasAuthority('USER_MANAGE')")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        try {
            log.info("Récupération de l'utilisateur avec ID {}", id);
            User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec l'ID: " + id));
            
            return buildUserProfileResponse(user);
        } catch (Exception e) {
            log.error("Erreur lors de la récupération de l'utilisateur: {}", e.getMessage(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Erreur lors de la récupération de l'utilisateur: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse);
        }
    }

    // Endpoint pour permettre aux utilisateurs de mettre à jour leur propre profil
    @PutMapping("/profile")
    public ResponseEntity<?> updateOwnProfile(@RequestBody Map<String, Object> userData, Authentication authentication) {
        try {
            if (authentication == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "status", "error",
                    "message", "Utilisateur non authentifié"
                ));
            }
            
            String username = authentication.getName();
            log.info("Mise à jour du profil par l'utilisateur lui-même: {}", username);
            log.info("Données reçues: {}", userData);
            
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé: " + username));
            
            log.info("Utilisateur trouvé: {}", user.getUsername());
            
            // Mettre à jour les informations personnelles uniquement
            boolean updated = false;
            
            if (userData.containsKey("firstName") && userData.get("firstName") != null) {
                user.setFirstName(userData.get("firstName").toString());
                log.info("Prénom mis à jour: {}", userData.get("firstName"));
                updated = true;
            }
            
            if (userData.containsKey("lastName") && userData.get("lastName") != null) {
                user.setLastName(userData.get("lastName").toString());
                log.info("Nom mis à jour: {}", userData.get("lastName"));
                updated = true;
            }
            
            if (userData.containsKey("email") && userData.get("email") != null) {
                user.setEmail(userData.get("email").toString());
                log.info("Email mis à jour: {}", userData.get("email"));
                updated = true;
            }
            
            if (userData.containsKey("phoneNumber") && userData.get("phoneNumber") != null) {
                user.setPhoneNumber(userData.get("phoneNumber").toString());
                log.info("Numéro de téléphone mis à jour: {}", userData.get("phoneNumber"));
                updated = true;
            }
            
            // Sauvegarder les modifications si des champs ont été mis à jour
            if (updated) {
                log.info("Sauvegarde des modifications pour l'utilisateur: {}", username);
                userRepository.save(user);
                log.info("Utilisateur sauvegardé avec succès");
            } else {
                log.info("Aucune modification à sauvegarder pour l'utilisateur: {}", username);
            }
            
            // Renvoyer le profil mis à jour
            return buildUserProfileResponse(user);
        } catch (Exception e) {
            log.error("Erreur lors de la mise à jour du profil: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "status", "error",
                "message", "Erreur lors de la mise à jour du profil: " + e.getMessage()
            ));
        }
    }
}

