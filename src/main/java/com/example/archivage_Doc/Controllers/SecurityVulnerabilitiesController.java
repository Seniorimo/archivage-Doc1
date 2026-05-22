package com.example.archivage_Doc.Controllers;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.sql.DataSource;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * CONTROLLER VULNÉRABLE - POUR DÉMONSTRATION DEVSECOPS SEULEMENT
 * 
 * CE CONTROLLER CONTIENT INTENTIONNELLEMENT DES VULNÉRABILITÉS DE SÉCURITÉ
 * POUR PERMETTRE LA DÉTECTION PAR LES OUTILS DE SÉCURITÉ (SAST, DAST, SCA)
 * 
 * NE JAMAIS UTILISER CE CODE EN PRODUCTION
 */
@RestController
@RequestMapping("/api/vuln")
@RequiredArgsConstructor
@Slf4j
public class SecurityVulnerabilitiesController {

    private final DataSource dataSource;
    private final ObjectMapper objectMapper;

    // ==========================================
    // SQL INJECTION VULNERABILITIES
    // ==========================================

    /**
     * VULNÉRABILITÉ: SQL Injection
     * L'entrée utilisateur est directement concaténée dans la requête SQL
     * sans validation ni paramétrage
     */
    @GetMapping("/sql-injection/login")
    @Operation(summary = "[VULN] SQL Injection - Login vulnérable")
    public ResponseEntity<Map<String, Object>> vulnerableLogin(
            @RequestParam String username,
            @RequestParam String password) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: Concaténation directe de l'entrée utilisateur dans la requête SQL
            String query = "SELECT * FROM users WHERE username = '" + username + 
                          "' AND password = '" + password + "'";
            
            log.info("Executing SQL query: {}", query); // Log injection aussi possible
            
            Connection conn = dataSource.getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                response.put("success", true);
                response.put("message", "Login successful");
                response.put("username", rs.getString("username"));
            } else {
                response.put("success", false);
                response.put("message", "Invalid credentials");
            }
            
            rs.close();
            stmt.close();
            conn.close();
            
        } catch (Exception e) {
            log.error("SQL Error: {}", e.getMessage());
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: SQL Injection dans une recherche
     */
    @GetMapping("/sql-injection/search")
    @Operation(summary = "[VULN] SQL Injection - Recherche vulnérable")
    public ResponseEntity<Map<String, Object>> vulnerableSearch(
            @RequestParam String searchTerm) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: SQL Injection via searchTerm
            String query = "SELECT * FROM documents WHERE title LIKE '%" + searchTerm + "%'";
            
            log.info("Search query: {}", query);
            
            Connection conn = dataSource.getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            java.util.List<Map<String, Object>> results = new java.util.ArrayList<>();
            while (rs.next()) {
                Map<String, Object> doc = new HashMap<>();
                doc.put("id", rs.getLong("id"));
                doc.put("title", rs.getString("title"));
                results.add(doc);
            }
            
            response.put("results", results);
            response.put("count", results.size());
            
            rs.close();
            stmt.close();
            conn.close();
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: SQL Injection avec UNION SELECT
     */
    @GetMapping("/sql-injection/user-info")
    @Operation(summary = "[VULN] SQL Injection - Extraction de données utilisateur")
    public ResponseEntity<Map<String, Object>> vulnerableUserInfo(
            @RequestParam String userId) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: Permet UNION SELECT pour extraire d'autres tables
            String query = "SELECT username, email FROM users WHERE id = " + userId;
            
            log.info("User info query: {}", query);
            
            Connection conn = dataSource.getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                response.put("username", rs.getString("username"));
                response.put("email", rs.getString("email"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // XSS (CROSS-SITE SCRIPTING) VULNERABILITIES
    // ==========================================

    /**
     * VULNÉRABILITÉ: Reflected XSS
     * L'entrée utilisateur est renvoyée sans échappement
     */
    @GetMapping("/xss/reflected")
    @Operation(summary = "[VULN] Reflected XSS - Recherche vulnérable")
    public ResponseEntity<Map<String, Object>> reflectedXSS(
            @RequestParam String query) {
        
        Map<String, Object> response = new HashMap<>();
        // VULNÉRABILITÉ: L'entrée utilisateur est renvoyée telle quelle
        response.put("message", "Résultats pour: " + query);
        response.put("query", query);
        response.put("html", "<div>Votre recherche: " + query + "</div>");
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: Stored XSS via commentaire
     * Le commentaire est stocké sans nettoyage
     */
    @PostMapping("/xss/stored-comment")
    @Operation(summary = "[VULN] Stored XSS - Commentaire vulnérable")
    public ResponseEntity<Map<String, Object>> storedXSSComment(
            @RequestBody Map<String, String> commentData) {
        
        Map<String, Object> response = new HashMap<>();
        String comment = commentData.get("comment");
        
        // VULNÉRABILITÉ: Le commentaire est stocké sans sanitization
        // Dans une vraie application, cela serait sauvegardé en base de données
        log.info("Storing comment: {}", comment);
        
        response.put("success", true);
        response.put("message", "Commentaire enregistré");
        response.put("comment", comment); // Renvoyé tel quel pour démonstration
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: DOM-based XSS
     * JavaScript vulnérable dans la réponse
     */
    @GetMapping("/xss/dom")
    @Operation(summary = "[VULN] DOM-based XSS")
    public ResponseEntity<Map<String, Object>> domXSS(
            @RequestParam String name) {
        
        Map<String, Object> response = new HashMap<>();
        
        // VULNÉRABILITÉ: JavaScript qui exécute l'entrée utilisateur
        String script = "<script>document.write('Bonjour, " + name + "');</script>";
        response.put("greeting", script);
        response.put("unsafeHtml", "<div onclick='alert(\"" + name + "\")'>Cliquez ici</div>");
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // PATH TRAVERSAL VULNERABILITIES
    // ==========================================

    /**
     * VULNÉRABILITÉ: Path Traversal
     * Permet de lire des fichiers en dehors du répertoire autorisé
     */
    @GetMapping("/path-traversal/read-file")
    @Operation(summary = "[VULN] Path Traversal - Lecture de fichier")
    public ResponseEntity<Map<String, Object>> pathTraversal(
            @RequestParam String filename) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: Pas de validation du chemin, permet ../ pour remonter
            String basePath = "uploads/";
            String fullPath = basePath + filename;
            
            Path path = Paths.get(fullPath);
            File file = path.toFile();
            
            if (file.exists()) {
                String content = Files.readString(path);
                response.put("filename", filename);
                response.put("content", content);
                response.put("success", true);
            } else {
                response.put("error", "File not found");
            }
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: Path Traversal avec téléchargement
     */
    @GetMapping("/path-traversal/download")
    @Operation(summary = "[VULN] Path Traversal - Téléchargement de fichier")
    public ResponseEntity<Map<String, Object>> pathTraversalDownload(
            @RequestParam String filepath) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: Permet de télécharger n'importe quel fichier
            Path path = Paths.get(filepath);
            String content = Files.readString(path);
            
            response.put("filepath", filepath);
            response.put("content", content);
            response.put("size", content.length());
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // COMMAND INJECTION VULNERABILITIES
    // ==========================================

    /**
     * VULNÉRABILITÉ: Command Injection
     * Exécution de commandes système via l'entrée utilisateur
     */
    @GetMapping("/command-injection/ping")
    @Operation(summary = "[VULN] Command Injection - Ping")
    public ResponseEntity<Map<String, Object>> commandInjectionPing(
            @RequestParam String host) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: L'entrée utilisateur est directement passée à Runtime.exec()
            String command = "ping -c 4 " + host;
            
            log.info("Executing command: {}", command);
            
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String output = reader.lines().collect(Collectors.joining("\n"));
            
            response.put("command", command);
            response.put("output", output);
            response.put("success", true);
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: Command Injection avec ls
     */
    @GetMapping("/command-injection/ls")
    @Operation(summary = "[VULN] Command Injection - List files")
    public ResponseEntity<Map<String, Object>> commandInjectionLs(
            @RequestParam String directory) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: Permet d'exécuter des commandes arbitraires
            String command = "ls -la " + directory;
            
            log.info("Executing command: {}", command);
            
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String output = reader.lines().collect(Collectors.joining("\n"));
            
            response.put("command", command);
            response.put("output", output);
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: Command Injection avec eval (bash)
     */
    @PostMapping("/command-injection/exec")
    @Operation(summary = "[VULN] Command Injection - Exécution arbitraire")
    public ResponseEntity<Map<String, Object>> commandInjectionExec(
            @RequestBody Map<String, String> request) {
        
        Map<String, Object> response = new HashMap<>();
        String command = request.get("command");
        
        try {
            // VULNÉRABILITÉ: Exécution directe de commande arbitraire
            String[] cmdArray = {"bash", "-c", command};
            
            log.info("Executing arbitrary command: {}", command);
            
            Process process = Runtime.getRuntime().exec(cmdArray);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String output = reader.lines().collect(Collectors.joining("\n"));
            
            response.put("command", command);
            response.put("output", output);
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // SSRF (SERVER-SIDE REQUEST FORGERY)
    // ==========================================

    /**
     * VULNÉRABILITÉ: SSRF
     * Le serveur fait des requêtes vers des URLs fournies par l'utilisateur
     */
    @GetMapping("/ssrf/fetch-url")
    @Operation(summary = "[VULN] SSRF - Récupération d'URL")
    public ResponseEntity<Map<String, Object>> ssrfFetchUrl(
            @RequestParam String url) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: Pas de validation de l'URL, permet d'accéder à
            // des ressources internes (localhost, 127.0.0.1, metadata AWS, etc.)
            URL targetUrl = new URL(url);
            URLConnection connection = targetUrl.openConnection();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()));
            
            String content = reader.lines().collect(Collectors.joining("\n"));
            
            response.put("url", url);
            response.put("content", content);
            response.put("success", true);
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: SSRF avec metadata cloud
     */
    @GetMapping("/ssrf/metadata")
    @Operation(summary = "[VULN] SSRF - Accès metadata cloud")
    public ResponseEntity<Map<String, Object>> ssrfMetadata(
            @RequestParam String metadataPath) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: Permet d'accéder aux metadata de cloud providers
            // Ex: http://169.254.169.254/latest/meta-data/
            String url = "http://169.254.169.254/" + metadataPath;
            
            URL targetUrl = new URL(url);
            URLConnection connection = targetUrl.openConnection();
            connection.setConnectTimeout(5000);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()));
            
            String content = reader.lines().collect(Collectors.joining("\n"));
            
            response.put("metadataPath", metadataPath);
            response.put("content", content);
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // LOG INJECTION VULNERABILITIES
    // ==========================================

    /**
     * VULNÉRABILITÉ: Log Injection
     * L'entrée utilisateur contient des caractères de contrôle de log
     */
    @PostMapping("/log-injection/log-user-action")
    @Operation(summary = "[VULN] Log Injection - Enregistrement d'action")
    public ResponseEntity<Map<String, Object>> logInjection(
            @RequestBody Map<String, String> request) {
        
        String username = request.get("username");
        String action = request.get("action");
        
        // VULNÉRABILITÉ: L'entrée utilisateur est loguée sans sanitization
        // Permet d'injecter des sauts de ligne, fausses entrées de log, etc.
        log.info("User action: {} performed action: {}", username, action);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Action logged");
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: CRLF Injection dans les logs
     */
    @GetMapping("/log-injection/search")
    @Operation(summary = "[VULN] Log Injection - Recherche avec log")
    public ResponseEntity<Map<String, Object>> logInjectionSearch(
            @RequestParam String query) {
        
        // VULNÉRABILITÉ: CRLF injection possible
        log.info("Search query from user: {}", query);
        
        Map<String, Object> response = new HashMap<>();
        response.put("query", query);
        response.put("results", "Simulated results for: " + query);
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // OPEN REDIRECT VULNERABILITIES
    // ==========================================

    /**
     * VULNÉRABILITÉ: Open Redirect
     * Redirection vers une URL fournie par l'utilisateur sans validation
     */
    @GetMapping("/open-redirect")
    @Operation(summary = "[VULN] Open Redirect")
    public RedirectView openRedirect(@RequestParam String url) {
        // VULNÉRABILITÉ: Redirection vers n'importe quelle URL
        // Permet le phishing
        return new RedirectView(url);
    }

    /**
     * VULNÉRABILITÉ: Open Redirect via parameter
     */
    @GetMapping("/open-redirect/next")
    @Operation(summary = "[VULN] Open Redirect - Parameter next")
    public RedirectView openRedirectNext(@RequestParam String next) {
        // VULNÉRABILITÉ: Redirection via paramètre 'next'
        return new RedirectView(next);
    }

    // ==========================================
    // HARDCODED CREDENTIALS
    // ==========================================

    /**
     * VULNÉRABILITÉ: Hardcoded credentials
     * Mots de passe et API keys en clair dans le code
     */
    @GetMapping("/hardcoded-credentials/admin-login")
    @Operation(summary = "[VULN] Hardcoded Credentials - Admin login")
    public ResponseEntity<Map<String, Object>> hardcodedCredentials(
            @RequestParam String username,
            @RequestParam String password) {
        
        Map<String, Object> response = new HashMap<>();
        
        // VULNÉRABILITÉ: Credentials hardcoded
        String ADMIN_USERNAME = "admin";
        String ADMIN_PASSWORD = "SuperSecretPassword123!";
        String DB_PASSWORD = "DbP@ssw0rd_2024";
        String API_KEY = "sk-1234567890abcdef";
        String AWS_SECRET_KEY = "AWS_SECRET_ACCESS_KEY=abcd1234efgh5678ijkl9012mnop3456";
        
        if (username.equals(ADMIN_USERNAME) && password.equals(ADMIN_PASSWORD)) {
            response.put("success", true);
            response.put("message", "Admin login successful");
            response.put("apiKey", API_KEY);
            response.put("dbPassword", DB_PASSWORD);
        } else {
            response.put("success", false);
            response.put("message", "Invalid credentials");
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: Hardcoded API keys
     */
    @GetMapping("/hardcoded-credentials/api-key")
    @Operation(summary = "[VULN] Hardcoded Credentials - API Key")
    public ResponseEntity<Map<String, Object>> hardcodedApiKey() {
        
        Map<String, Object> response = new HashMap<>();
        
        // VULNÉRABILITÉ: API keys hardcoded
        response.put("stripeKey", "FAKE_stripe_test_key_for_testing_only");
        response.put("awsAccessKey", "FAKE_AWS_ACCESS_KEY_FOR_TESTING");
        response.put("awsSecretKey", "FAKE_AWS_SECRET_KEY_FOR_TESTING_1234567890");
        response.put("githubToken", "FAKE_github_token_for_testing_only_1234567890");
        response.put("jwtSecret", "FAKE_jwt_secret_for_testing_only_1234567890");
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // WEAK AUTHENTICATION
    // ==========================================

    /**
     * VULNÉRABILITÉ: Authentification faible
     * Vérification de mot de passe en clair sans hachage
     */
    @PostMapping("/weak-auth/login")
    @Operation(summary = "[VULN] Weak Authentication - Password en clair")
    public ResponseEntity<Map<String, Object>> weakAuthLogin(
            @RequestBody Map<String, String> credentials) {
        
        Map<String, Object> response = new HashMap<>();
        String username = credentials.get("username");
        String password = credentials.get("password");
        
        // VULNÉRABILITÉ: Comparaison de mot de passe en clair
        // Pas de hachage, pas de sel
        if (username.equals("user") && password.equals("password123")) {
            response.put("success", true);
            response.put("token", "weak-jwt-token-" + System.currentTimeMillis());
        } else {
            response.put("success", false);
            response.put("message", "Invalid credentials");
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: Pas de rate limiting sur login
     */
    @PostMapping("/weak-auth/brute-force")
    @Operation(summary = "[VULN] Weak Authentication - Brute force possible")
    public ResponseEntity<Map<String, Object>> bruteForceLogin(
            @RequestBody Map<String, String> credentials) {
        
        Map<String, Object> response = new HashMap<>();
        
        // VULNÉRABILITÉ: Pas de rate limiting, pas de lockout
        // Permet les attaques par force brute
        String username = credentials.get("username");
        String password = credentials.get("password");
        
        log.info("Login attempt for user: {}", username);
        
        if (password.length() < 6) {
            response.put("success", false);
            response.put("message", "Password too weak");
        } else {
            response.put("success", true);
            response.put("message", "Login successful");
        }
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // UNSAFE DESERIALIZATION
    // ==========================================

    /**
     * VULNÉRABILITÉ: Désérialisation non sécurisée
     * Désérialisation d'objets Java depuis une entrée utilisateur
     */
    @PostMapping("/unsafe-deserialization/java")
    @Operation(summary = "[VULN] Unsafe Deserialization - Java")
    public ResponseEntity<Map<String, Object>> unsafeDeserialization(
            @RequestBody String serializedData) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: Désérialisation de données non fiables
            // Peut mener à l'exécution de code arbitraire (RCE)
            byte[] data = Base64.getDecoder().decode(serializedData);
            
            java.io.ByteArrayInputStream bis = new java.io.ByteArrayInputStream(data);
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(bis);
            
            Object obj = ois.readObject();
            
            response.put("deserialized", obj.toString());
            response.put("success", true);
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITITÉ: Désérialisation JSON non sécurisée
     */
    @PostMapping("/unsafe-deserialization/json")
    @Operation(summary = "[VULN] Unsafe Deserialization - JSON")
    public ResponseEntity<Map<String, Object>> unsafeJsonDeserialization(
            @RequestBody String jsonData) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: Configuration Jackson non sécurisée
            ObjectMapper unsafeMapper = new ObjectMapper();
            unsafeMapper.enableDefaultTyping(); // Permet la désérialisation de types arbitraires
            
            Object obj = unsafeMapper.readValue(jsonData, Object.class);
            
            response.put("deserialized", obj);
            response.put("success", true);
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // IDOR (INSECURE DIRECT OBJECT REFERENCES)
    // ==========================================

    /**
     * VULNÉRABILITÉ: IDOR
     * Accès direct aux ressources sans vérification d'autorisation
     */
    @GetMapping("/idor/user-profile")
    @Operation(summary = "[VULN] IDOR - Accès profil utilisateur")
    public ResponseEntity<Map<String, Object>> idorUserProfile(
            @RequestParam Long userId) {
        
        Map<String, Object> response = new HashMap<>();
        
        // VULNÉRABILITÉ: Pas de vérification que l'utilisateur a le droit d'accéder
        // à ce profil. N'importe qui peut accéder au profil de n'importe qui
        // en changeant l'ID
        try {
            Connection conn = dataSource.getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
            
            if (rs.next()) {
                response.put("id", rs.getLong("id"));
                response.put("username", rs.getString("username"));
                response.put("email", rs.getString("email"));
                response.put("firstName", rs.getString("first_name"));
                response.put("lastName", rs.getString("last_name"));
                response.put("phoneNumber", rs.getString("phone_number"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: IDOR sur les documents
     */
    @GetMapping("/idor/document")
    @Operation(summary = "[VULN] IDOR - Accès document")
    public ResponseEntity<Map<String, Object>> idorDocument(
            @RequestParam Long documentId) {
        
        Map<String, Object> response = new HashMap<>();
        
        // VULNÉRABILITÉ: Pas de vérification de permissions
        try {
            Connection conn = dataSource.getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM documents WHERE id = " + documentId);
            
            if (rs.next()) {
                response.put("id", rs.getLong("id"));
                response.put("title", rs.getString("title"));
                response.put("description", rs.getString("description"));
                response.put("filePath", rs.getString("file_path"));
                response.put("status", rs.getString("status"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // INFORMATION DISCLOSURE
    // ==========================================

    /**
     * VULNÉRABILITÉ: Information Disclosure
     * Révélation d'informations sensibles dans les messages d'erreur
     */
    @GetMapping("/info-disclosure/error")
    @Operation(summary = "[VULN] Information Disclosure - Erreur verbeuse")
    public ResponseEntity<Map<String, Object>> infoDisclosureError(
            @RequestParam String input) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: Stack trace complète exposée
            int result = Integer.parseInt(input);
            response.put("result", result);
            
        } catch (Exception e) {
            // VULNÉRABILITÉ: Révélation de la stack trace
            response.put("error", e.getMessage());
            response.put("stackTrace", e.getStackTrace());
            response.put("cause", e.getCause());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: Information Disclosure - Version exposée
     */
    @GetMapping("/info-disclosure/version")
    @Operation(summary = "[VULN] Information Disclosure - Version")
    public ResponseEntity<Map<String, Object>> infoDisclosureVersion() {
        
        Map<String, Object> response = new HashMap<>();
        
        // VULNÉRABILITÉ: Révélation des versions du système
        response.put("javaVersion", System.getProperty("java.version"));
        response.put("osName", System.getProperty("os.name"));
        response.put("osVersion", System.getProperty("os.version"));
        response.put("osArch", System.getProperty("os.arch"));
        response.put("serverInfo", "Spring Boot 3.5.14");
        response.put("database", "MySQL 8.0");
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // HEADER SECURITY ISSUES
    // ==========================================

    /**
     * VULNÉRABILITÉ: Missing Security Headers
     * Réponse sans headers de sécurité
     */
    @GetMapping("/missing-headers/data")
    @Operation(summary = "[VULN] Missing Security Headers")
    public ResponseEntity<Map<String, Object>> missingHeaders() {
        
        Map<String, Object> response = new HashMap<>();
        response.put("data", "Sensitive information");
        response.put("message", "This response lacks security headers");
        
        // VULNÉRABILITÉ: Pas de headers CSP, X-Frame-Options, X-Content-Type-Options, etc.
        return ResponseEntity.ok(response);
    }

    /**
     * VULNÉRABILITÉ: CORS permissif
     */
    @GetMapping("/cors/misconfigured")
    @Operation(summary = "[VULN] CORS Misconfigured")
    public ResponseEntity<Map<String, Object>> corsMisconfigured(
            @RequestHeader(value = "Origin", required = false) String origin) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("origin", origin);
        response.put("message", "CORS allows any origin");
        
        // VULNÉRABILITÉ: CORS configuré pour accepter n'importe quelle origine
        return ResponseEntity
                .ok()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                .header("Access-Control-Allow-Headers", "*")
                .header("Access-Control-Allow-Credentials", "true")
                .body(response);
    }

    // ==========================================
    // MASS ASSIGNMENT
    // ==========================================

    /**
     * VULNÉRABILITÉ: Mass Assignment
     * Mise à jour de champs sans validation
     */
    @PostMapping("/mass-assignment/update-user")
    @Operation(summary = "[VULN] Mass Assignment - Update user")
    public ResponseEntity<Map<String, Object>> massAssignment(
            @RequestBody Map<String, Object> userData) {
        
        Map<String, Object> response = new HashMap<>();
        
        // VULNÉRABILITÉ: Tous les champs sont acceptés sans validation
        // Un utilisateur peut s'élever lui-même en admin
        try {
            Connection conn = dataSource.getConnection();
            
            String sql = "UPDATE users SET ";
            java.util.List<String> updates = new java.util.ArrayList<>();
            
            for (Map.Entry<String, Object> entry : userData.entrySet()) {
                updates.add(entry.getKey() + " = '" + entry.getValue() + "'");
            }
            
            sql += String.join(", ", updates);
            sql += " WHERE id = " + userData.get("id");
            
            Statement stmt = conn.createStatement();
            stmt.executeUpdate(sql);
            
            response.put("success", true);
            response.put("message", "User updated");
            response.put("sql", sql);
            
            stmt.close();
            conn.close();
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    // ==========================================
    // XXE (XML EXTERNAL ENTITY)
    // ==========================================

    /**
     * VULNÉRABILITÉ: XXE Injection
     * Parsing XML non sécurisé
     */
    @PostMapping("/xxe/parse-xml")
    @Operation(summary = "[VULN] XXE Injection - Parse XML")
    public ResponseEntity<Map<String, Object>> xxeInjection(
            @RequestBody String xmlData) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNÉRABILITÉ: Parser XML configuré de manière non sécurisée
            javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            
            // VULNÉRABILITÉ: Features de sécurité désactivés
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
            dbf.setXIncludeAware(true);
            dbf.setExpandEntityReferences(true);
            
            javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = db.parse(new org.xml.sax.InputSource(new java.io.StringReader(xmlData)));
            
            response.put("success", true);
            response.put("rootElement", doc.getDocumentElement().getNodeName());
            
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }
}
