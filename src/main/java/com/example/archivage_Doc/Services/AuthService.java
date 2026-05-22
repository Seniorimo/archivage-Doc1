package com.example.archivage_Doc.Services;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.archivage_Doc.DTOs.AuthRequest;
import com.example.archivage_Doc.DTOs.AuthResponse;
import com.example.archivage_Doc.DTOs.RegisterRequest;
import com.example.archivage_Doc.Entities.Department;
import com.example.archivage_Doc.Entities.User;
import com.example.archivage_Doc.Entities.UserRole;
import com.example.archivage_Doc.Enums.AuditAction;
import com.example.archivage_Doc.Enums.DepartmentLevel;
import com.example.archivage_Doc.Enums.Permission;
import com.example.archivage_Doc.Repositories.DepartmentRepository;
import com.example.archivage_Doc.Repositories.UserRepository;
import com.example.archivage_Doc.Repositories.UserRoleRepository;
import com.example.archivage_Doc.Security.JwtService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final DepartmentRepository departmentRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final AuditService auditService;

    public AuthResponse register(RegisterRequest request) {
        // Créer un nouvel utilisateur
        var user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .userRoles(new HashSet<>())
                .build();

        // Sauvegarder l'utilisateur
        user = userRepository.save(user);

        // Créer un rôle utilisateur par défaut avec des permissions de base
        Department defaultDepartment = departmentRepository.findByCode("DEFAULT")
                .orElseGet(() -> {
                    Department dept = Department.builder()
                            .name("Département par défaut")
                            .code("DEFAULT")
                            .description("Département par défaut pour les nouveaux utilisateurs")
                            .build();
                    return departmentRepository.save(dept);
                });

        Set<Permission> basicPermissions = new HashSet<>();
        basicPermissions.add(Permission.DOCUMENT_READ);
        basicPermissions.add(Permission.USER_MANAGE);

        UserRole userRole = UserRole.builder()
                .user(user)
                .department(defaultDepartment)
                .level(DepartmentLevel.EMPLOYEE)
                .permissions(basicPermissions)
                .build();

        userRoleRepository.save(userRole);

        // Générer le token
        var token = jwtService.generateToken(user);
        
        return AuthResponse.builder()
                .token(token)
                .build();
    }

    public AuthResponse authenticate(AuthRequest request) {
        try {
            // Tentative d'authentification
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword()
                )
            );
            
            // Si on arrive ici, l'authentification a réussi
            var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow();
                
            var token = jwtService.generateToken(user);
            
            // Audit de la connexion réussie
            auditService.logAuthAction(
                AuditAction.LOGIN_SUCCESS,
                user.getUsername(),
                "Connexion réussie via formulaire de login",
                "SUCCÈS"
            );
            
            return AuthResponse.builder()
                .token(token)
                .build();
        } catch (Exception e) {
            // Audit de l'échec d'authentification
            auditService.logAuthAction(
                AuditAction.LOGIN_FAILURE,
                request.getUsername(),
                "Échec de connexion: " + e.getMessage(),
                "ÉCHEC"
            );
            
            // Relancer l'exception pour être gérée par le contrôleur
            throw e;
        }
    }

    public AuthResponse registerAdmin(RegisterRequest request) {
        try {
            Set<Permission> adminPermissions = new HashSet<>();
            adminPermissions.add(Permission.DOCUMENT_READ);
            adminPermissions.add(Permission.DOCUMENT_WRITE);
            adminPermissions.add(Permission.DOCUMENT_DELETE);
            adminPermissions.add(Permission.USER_MANAGE);
            adminPermissions.add(Permission.ADMIN_CREATE);
            adminPermissions.add(Permission.MANAGER_CREATE);

            return registerUser(request, DepartmentLevel.ADMIN, adminPermissions);
        } catch (Exception e) {
            logger.error("Admin registration error: ", e);
            throw e;
        }
    }

    public AuthResponse registerManager(RegisterRequest request) {
        try {
            Set<Permission> managerPermissions = new HashSet<>();
            managerPermissions.add(Permission.DOCUMENT_READ);
            managerPermissions.add(Permission.DOCUMENT_WRITE);
            managerPermissions.add(Permission.USER_MANAGE);
            managerPermissions.add(Permission.MANAGER_CREATE);

            return registerUser(request, DepartmentLevel.MANAGER, managerPermissions);
        } catch (Exception e) {
            logger.error("Manager registration error: ", e);
            throw e;
        }
    }

    public AuthResponse registerEmployee(RegisterRequest request) {
        try {
            Set<Permission> employeePermissions = new HashSet<>();
            employeePermissions.add(Permission.DOCUMENT_READ);

            return registerUser(request, DepartmentLevel.EMPLOYEE, employeePermissions);
        } catch (Exception e) {
            logger.error("Employee registration error: ", e);
            throw e;
        }
    }

    private AuthResponse registerUser(RegisterRequest request, DepartmentLevel level, Set<Permission> permissions) {
        try {
            // Vérifier si l'utilisateur existe déjà
            if (userRepository.findByUsername(request.getUsername()).isPresent()) {
                throw new RuntimeException("Username already exists");
            }

            // Créer un nouvel utilisateur
            var user = User.builder()
                    .username(request.getUsername())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .userRoles(new HashSet<>())
                    .build();

            // Sauvegarder l'utilisateur
            user = userRepository.save(user);

            // Récupérer ou créer le département
            String deptCode = (request.getDepartmentCode() != null && !request.getDepartmentCode().isEmpty()) 
                ? request.getDepartmentCode().toUpperCase() 
                : "DEFAULT";
            
            Department department = departmentRepository.findByCode(deptCode)
                    .orElseGet(() -> {
                        logger.warn("Département {} non trouvé, utilisation du département par défaut", deptCode);
                        return departmentRepository.findByCode("DEFAULT")
                                .orElseThrow(() -> new RuntimeException("Département par défaut non trouvé"));
                    });

            UserRole userRole = UserRole.builder()
                    .user(user)
                    .department(department)
                    .level(level)
                    .permissions(permissions)
                    .build();

            userRoleRepository.save(userRole);
            
            // Ajouter explicitement le rôle à l'utilisateur et sauvegarder à nouveau
            user.getUserRoles().add(userRole);
            userRepository.save(user);
            
            // Journaliser l'état des permissions pour débogage
            logger.info("Utilisateur créé avec niveau: {} et permissions: {}", 
                level, 
                permissions.stream().map(Enum::name).collect(Collectors.joining(", ")));

            // Générer le token
            var token = jwtService.generateToken(user);
            
            return AuthResponse.builder()
                    .token(token)
                    .build();
        } catch (Exception e) {
            logger.error("Registration error: ", e);
            throw e;
        }
    }

    // Méthode spéciale pour créer un utilisateur via le test-register
    // Cette méthode contourne les vérifications de sécurité standard
    public AuthResponse registerUserAlternative(RegisterRequest request, String userType) {
        try {
            logger.info("Creating user using alternative method: type={}, username={}", 
                userType, request.getUsername());
            
            switch (userType.toLowerCase()) {
                case "manager":
                    logger.info("Creating manager using alternative method");
                    return registerManager(request);
                case "employee":
                    logger.info("Creating employee using alternative method");
                    return registerEmployee(request);
                default:
                    throw new RuntimeException("Type d'utilisateur non supporté: " + userType);
            }
        } catch (Exception e) {
            logger.error("Alternative user creation error: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Vérifie si un nom d'utilisateur existe déjà dans la base de données
     * @param username le nom d'utilisateur à vérifier
     * @return vrai si le nom d'utilisateur existe, faux sinon
     */
    public boolean usernameExists(String username) {
        logger.info("Vérification de l'existence du nom d'utilisateur: {}", username);
        return userRepository.findByUsername(username).isPresent();
    }
} 