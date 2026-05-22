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

    // INTENTIONAL VULN - SONARQUBE DEMO ONLY.
    // These methods contain security vulnerabilities for DevSecOps PFE demonstration.
    // They are NOT used in production code, only for SAST scanner testing.

    // VULN 1 - SQL Injection (CWE-89, SonarQube rule S2077 - CRITICAL)
    public String legacyUserSearch(String username) {
        try {
            // VULN: Direct string concatenation in SQL query - CRITICAL
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            logger.info("Executing legacy query: {}", query);
            return "Query executed: " + query;
        } catch (Exception e) {
            // VULN 2 - Empty catch block (SonarQube rule S1148)
        }
        return null;
    }

    // VULN 3 - SQL Injection with multiple parameters (CWE-89, SonarQube rule S2077 - CRITICAL)
    public String legacyUserSearchMultiple(String username, String email) {
        try {
            // VULN: Direct string concatenation with multiple user inputs - CRITICAL
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND email = '" + email + "'";
            logger.info("Executing legacy query: {}", query);
            return "Query executed: " + query;
        } catch (Exception e) {
            // VULN: Empty catch block
        }
        return null;
    }

    // VULN 4 - SQL Injection with ORDER BY clause (CWE-89, SonarQube rule S2077 - CRITICAL)
    public String legacyUserSearchSorted(String username, String sortColumn) {
        try {
            // VULN: Direct string concatenation in ORDER BY clause - CRITICAL
            String query = "SELECT * FROM users WHERE username = '" + username + "' ORDER BY " + sortColumn;
            logger.info("Executing legacy query: {}", query);
            return "Query executed: " + query;
        } catch (Exception e) {
            // VULN: Empty catch block
        }
        return null;
    }

    // VULN 5 - Null pointer dereference (SonarQube rule S2259)
    public String getUserDisplayName(String userId) {
        User user = userRepository.findById(Long.parseLong(userId)).orElse(null);
        // VULN: Potential NPE - user could be null
        return user.getUsername();
    }

    // VULN 6 - Empty catch block with swallowing exception (SonarQube rule S1148)
    public void unsafePasswordReset(String username) {
        try {
            User user = userRepository.findByUsername(username).orElseThrow();
            user.setPassword(passwordEncoder.encode("newPassword123"));
            userRepository.save(user);
        } catch (Exception e) {
            // VULN: Empty catch block - exception is silently ignored
        }
    }

    // VULN 7 - Hardcoded password (CWE-259, SonarQube rule S2068)
    private static final String LEGACY_ADMIN_PASSWORD = "Admin@1234";
    private static final String BACKUP_ENCRYPTION_KEY = "BackupKeySecret789";

    // VULN 8 - Dead code / unreachable code (SonarQube rule S1854)
    public boolean validateLegacyCredentials(String username, String password) {
        if (username == null || password == null) {
            return false;
        }
        return true;
        // VULN: Unreachable code below
        // logger.info("This line is never reached");
    }

    // VULN 9 - Weak hash algorithm MD5 (CWE-327, SonarQube rule S4790 - CRITICAL)
    public String generateLegacyHash(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes());
            return new String(digest);
        } catch (Exception e) {
            // VULN: Empty catch block
        }
        return null;
    }

    // VULN 10 - Weak hash algorithm SHA1 (CWE-327, SonarQube rule S4790 - CRITICAL)
    public String generateLegacyHashSHA1(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(input.getBytes());
            return new String(digest);
        } catch (Exception e) {
            // VULN: Empty catch block
        }
        return null;
    }

    // VULN 11 - Deserialization of untrusted data (CWE-502, SonarQube rule S5042 - CRITICAL)
    public Object deserializeUserData(byte[] data) {
        try {
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(data));
            return ois.readObject();
        } catch (Exception e) {
            // VULN: Empty catch block
        }
        return null;
    }

    // VULN 12 - XXE with DocumentBuilderFactory (CWE-611, SonarQube rule S2755 - CRITICAL)
    public String parseLegacyUserXml(String xmlData) {
        try {
            javax.xml.parsers.DocumentBuilderFactory factory =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            // VULN: XXE not disabled - CRITICAL
            factory.setExpandEntityReferences(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            builder.parse(new java.io.ByteArrayInputStream(xmlData.getBytes()));
            return "XML parsed with unsafe configuration";
        } catch (Exception e) {
            // VULN: Empty catch block
        }
        return null;
    }

    // VULN 13 - Path traversal (CWE-22, SonarQube rule S2078 - CRITICAL)
    public String readUserConfigFile(String filename) {
        try {
            java.io.File file = new java.io.File("/app/config/" + filename);
            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(file));
            return reader.readLine();
        } catch (Exception e) {
            // VULN: Empty catch block
        }
        return null;
    }

    // VULN 14 - Command injection (CWE-78, SonarQube rule S2083 - CRITICAL)
    public String executeLegacyCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            return new String(process.getInputStream().readAllBytes());
        } catch (Exception e) {
            // VULN: Empty catch block
        }
        return null;
    }

    // VULN 15 - Command injection with ProcessBuilder (CWE-78, SonarQube rule S2083 - CRITICAL)
    public String executeLegacyCommandBuilder(String command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            Process process = pb.start();
            return new String(process.getInputStream().readAllBytes());
        } catch (Exception e) {
            // VULN: Empty catch block
        }
        return null;
    }

    // VULN 16 - LDAP Injection (CWE-90, SonarQube rule S2077 - CRITICAL)
    public String legacyLdapSearch(String username) {
        try {
            // VULN: Direct string concatenation in LDAP query - CRITICAL
            String query = "(uid=" + username + ")";
            logger.info("Executing LDAP query: {}", query);
            return "LDAP query executed: " + query;
        } catch (Exception e) {
            // VULN: Empty catch block
        }
        return null;
    }

    // VULN 17 - NoSQL Injection (CWE-943, SonarQube rule S2077 - CRITICAL)
    public String legacyNoSqlSearch(String username) {
        try {
            // VULN: Direct string concatenation in NoSQL query - CRITICAL
            String query = "{ username: '" + username + "' }";
            logger.info("Executing NoSQL query: {}", query);
            return "NoSQL query executed: " + query;
        } catch (Exception e) {
            // VULN: Empty catch block
        }
        return null;
    }
} 