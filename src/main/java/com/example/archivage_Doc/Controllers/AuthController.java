package com.example.archivage_Doc.Controllers;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.example.archivage_Doc.DTOs.AuthRequest;
import com.example.archivage_Doc.DTOs.AuthResponse;
import com.example.archivage_Doc.DTOs.RegisterRequest;
import com.example.archivage_Doc.Services.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173", allowedHeaders = "*")
@Slf4j
public class AuthController {

    private final AuthService authService;

    // Gestionnaire de requêtes OPTIONS pour les endpoints d'enregistrement
    @RequestMapping(value = {"/register/admin", "/register/manager", "/register/employee", "/test-register"}, method = RequestMethod.OPTIONS)
    public ResponseEntity<?> handleOptionsRequests() {
        log.info("OPTIONS request received for register endpoints");
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    @Operation(summary = "Se connecter à l'application")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            log.info("Login attempt for user: {}", request.getUsername());
            AuthResponse authResponse = authService.authenticate(request);
            log.info("Login successful for user: {}", request.getUsername());
            return ResponseEntity.ok(authResponse);
        } catch (Exception e) {
            log.error("Login error for user {}: {}", request.getUsername(), e.getMessage());
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            errorResponse.put("status", "error");
            return ResponseEntity.status(401).body(errorResponse);
        }
    }

    @PostMapping("/register/admin")
    @Operation(summary = "Créer un compte administrateur")
    public ResponseEntity<?> registerAdmin(@RequestBody RegisterRequest request) {
        try {
            log.info("Registering admin: {}", request.getUsername());
            AuthResponse response = authService.registerAdmin(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Admin registration error: ", e);
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            errorResponse.put("status", "error");
            return ResponseEntity.status(400).body(errorResponse);
        }
    }

    @PostMapping("/register/manager")
    @Operation(summary = "Créer un compte manager de département")
    public ResponseEntity<?> registerManager(@RequestBody RegisterRequest request) {
        try {
            log.info("Registering manager with data: {}", request);
            
            // Validation de la requête
            if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
                log.error("Manager registration error: Username is empty");
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "Le nom d'utilisateur ne peut pas être vide");
                errorResponse.put("status", "error");
                errorResponse.put("field", "username");
                return ResponseEntity.status(400).body(errorResponse);
            }
            
            if (request.getPassword() == null || request.getPassword().trim().isEmpty()) {
                log.error("Manager registration error: Password is empty");
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "Le mot de passe ne peut pas être vide");
                errorResponse.put("status", "error");
                errorResponse.put("field", "password");
                return ResponseEntity.status(400).body(errorResponse);
            }
            
            // Log des autorités si l'authentification est présente
            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                log.info("Authorities: {}", SecurityContextHolder.getContext().getAuthentication().getAuthorities());
            } else {
                log.info("No authentication context available");
            }
            
            AuthResponse response = authService.registerManager(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Manager registration error details: {}", e.getMessage(), e);
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            errorResponse.put("status", "error");
            errorResponse.put("exception", e.getClass().getName());
            return ResponseEntity.status(400).body(errorResponse);
        }
    }

    @PostMapping("/register/employee")
    @Operation(summary = "Créer un compte employé de département")
    public ResponseEntity<?> registerEmployee(@RequestBody RegisterRequest request) {
        try {
            log.info("Registering employee with data: {}", request);
            
            // Validation de la requête
            if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
                log.error("Employee registration error: Username is empty");
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "Le nom d'utilisateur ne peut pas être vide");
                errorResponse.put("status", "error");
                errorResponse.put("field", "username");
                return ResponseEntity.status(400).body(errorResponse);
            }
            
            if (request.getPassword() == null || request.getPassword().trim().isEmpty()) {
                log.error("Employee registration error: Password is empty");
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "Le mot de passe ne peut pas être vide");
                errorResponse.put("status", "error");
                errorResponse.put("field", "password");
                return ResponseEntity.status(400).body(errorResponse);
            }
            
            // Log des autorités si l'authentification est présente
            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                log.info("Authorities: {}", SecurityContextHolder.getContext().getAuthentication().getAuthorities());
            } else {
                log.info("No authentication context available");
            }
            
            AuthResponse response = authService.registerEmployee(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Employee registration error details: {}", e.getMessage(), e);
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            errorResponse.put("status", "error");
            errorResponse.put("exception", e.getClass().getName());
            return ResponseEntity.status(400).body(errorResponse);
        }
    }
    
    @PostMapping("/test-register")
    @Operation(summary = "Test d'inscription - diagnostic")
    public ResponseEntity<?> testRegister(@RequestBody RegisterRequest request) {
        try {
            log.info("Test registration with data: {}", request);
            
            // Log des autorités si l'authentification est présente
            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                log.info("Authorities: {}", SecurityContextHolder.getContext().getAuthentication().getAuthorities());
            } else {
                log.info("No authentication context available");
            }
            
            // Vérifier si c'est une requête alternative de création d'utilisateur
            if (request.getUseAlternativeMethod() != null && request.getUseAlternativeMethod()) {
                String createType = request.getCreateType();
                log.info("Alternative user creation requested: {}", createType);
                
                if (createType != null && !createType.isEmpty()) {
                    try {
                        // Utiliser la méthode spéciale qui contourne les vérifications de sécurité
                        AuthResponse response = authService.registerUserAlternative(request, createType);
                        log.info("User created successfully using alternative method: {}", createType);
                        
                        Map<String, Object> successResponse = new HashMap<>();
                        successResponse.put("message", "Utilisateur créé avec succès (méthode alternative): " + createType);
                        successResponse.put("status", "success");
                        successResponse.put("token", response.getToken());
                        return ResponseEntity.ok(successResponse);
                    } catch (Exception e) {
                        log.error("Alternative user creation error: {}", e.getMessage());
                        Map<String, Object> errorResponse = new HashMap<>();
                        errorResponse.put("error", e.getMessage());
                        errorResponse.put("status", "error");
                        return ResponseEntity.status(400).body(errorResponse);
                    }
                }
            }
            
            // Cas standard - juste un test sans création d'utilisateur
            Map<String, Object> response = new HashMap<>();
            response.put("receivedData", request);
            response.put("status", "success");
            response.put("message", "Registration test completed successfully");
            
            // Ajouter les autorités si disponibles
            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                response.put("authorities", SecurityContextHolder.getContext().getAuthentication().getAuthorities().toString());
            } else {
                response.put("authorities", "No authentication context available");
            }
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Test registration error: {}", e.getMessage(), e);
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            errorResponse.put("status", "error");
            return ResponseEntity.status(400).body(errorResponse);
        }
    }

    @PostMapping("/test-login")
    @Operation(summary = "Test de connexion - diagnostic")
    public ResponseEntity<?> testLogin(@RequestBody AuthRequest request) {
        try {
            log.info("Test login attempt for user: {}", request.getUsername());
            
            Map<String, Object> response = new HashMap<>();
            response.put("username", request.getUsername());
            response.put("passwordProvided", request.getPassword() != null && !request.getPassword().isEmpty());
            
            try {
                // Tentative d'authentification
                AuthResponse authResponse = authService.authenticate(request);
                response.put("status", "success");
                response.put("authenticated", true);
                response.put("token", authResponse.getToken());
                log.info("Test login successful for: {}", request.getUsername());
                return ResponseEntity.ok(response);
            } catch (Exception e) {
                response.put("status", "error");
                response.put("authenticated", false);
                response.put("errorMessage", e.getMessage());
                response.put("errorType", e.getClass().getSimpleName());
                log.error("Test login failed for: {}", request.getUsername(), e);
                return ResponseEntity.status(400).body(response);
            }
        } catch (Exception e) {
            log.error("Test login error: ", e);
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            errorResponse.put("status", "error");
            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    @PostMapping("/direct-login")
    @Operation(summary = "Se connecter à l'application - alternative")
    public ResponseEntity<?> directLogin(@RequestBody AuthRequest request) {
        try {
            log.info("Direct login attempt for user: {}", request.getUsername());
            
            try {
                AuthResponse authResponse = authService.authenticate(request);
                log.info("Direct login successful for user: {}", request.getUsername());
                return ResponseEntity.ok(authResponse);
            } catch (Exception e) {
                log.error("Direct login failed for user {}: {}", request.getUsername(), e.getMessage());
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", e.getMessage());
                errorResponse.put("status", "error");
                return ResponseEntity.status(401).body(errorResponse);
            }
        } catch (Exception e) {
            log.error("Unexpected error in direct login: ", e);
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Une erreur inattendue s'est produite");
            errorResponse.put("status", "error");
            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    @PostMapping("/check-username")
    @Operation(summary = "Vérifier si un nom d'utilisateur existe déjà")
    public ResponseEntity<?> checkUsername(@RequestBody Map<String, String> request) {
        try {
            String username = request.get("username");
            log.info("Checking if username exists: {}", username);
            
            if (username == null || username.trim().isEmpty()) {
                Map<String, Object> response = new HashMap<>();
                response.put("status", "error");
                response.put("message", "Le nom d'utilisateur ne peut pas être vide");
                return ResponseEntity.badRequest().body(response);
            }
            
            boolean exists = authService.usernameExists(username.trim());
            
            Map<String, Object> response = new HashMap<>();
            response.put("username", username);
            response.put("exists", exists);
            response.put("status", "success");
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error checking username: {}", e.getMessage(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            errorResponse.put("status", "error");
            return ResponseEntity.status(500).body(errorResponse);
        }
    }
} 