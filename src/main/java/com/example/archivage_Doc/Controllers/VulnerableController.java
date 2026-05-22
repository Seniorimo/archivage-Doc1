package com.example.archivage_Doc.Controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class VulnerableController {

    // VULN 1 - SQL INJECTION (A3 - Critical)
    // OWASP A03:2021 - Injection
    @GetMapping("/sql-test")
    public ResponseEntity<String> sqlInjection(@RequestParam String q) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
            Statement stmt = conn.createStatement();
            // VULN: Direct SQL injection - no sanitization
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + q + "'");
            StringBuilder result = new StringBuilder();
            while (rs.next()) {
                result.append("User: ").append(rs.getString("username")).append("\n");
            }
            return ResponseEntity.ok(result.toString());
        } catch (Exception e) {
            return ResponseEntity.ok("Error: " + e.getMessage());
        }
    }

    // VULN 2 - XSS (A3 - Critical)
    // OWASP A03:2021 - Injection
    @GetMapping("/comment")
    public ResponseEntity<String> xss(@RequestParam String text) {
        // VULN: Reflected XSS - no escaping, returns raw input
        return ResponseEntity.ok("<div>Your comment: " + text + "</div>");
    }

    // VULN 3 - IDOR (A1 - High)
    // OWASP A01:2021 - Broken Access Control
    @GetMapping("/private/user/{id}")
    public ResponseEntity<Map<String, Object>> idor(@PathVariable Long id) {
        // VULN: No authorization check - anyone can access any user data
        Map<String, Object> userData = new HashMap<>();
        userData.put("id", id);
        userData.put("username", "user" + id);
        userData.put("email", "user" + id + "@example.com");
        userData.put("ssn", "123-45-6789");
        userData.put("creditCard", "4532-1234-5678-9010");
        return ResponseEntity.ok(userData);
    }

    // VULN 4 - SSRF (A10 - Critical)
    // OWASP A10:2021 - Server-Side Request Forgery
    @GetMapping("/proxy")
    public ResponseEntity<String> ssrf(@RequestParam String url) {
        try {
            // VULN: SSRF - fetches any URL without validation
            RestTemplate restTemplate = new RestTemplate();
            String response = restTemplate.getForObject(url, String.class);
            return ResponseEntity.ok("Fetched from " + url + ":\n" + response);
        } catch (Exception e) {
            return ResponseEntity.ok("Error fetching URL: " + e.getMessage());
        }
    }

    // VULN 5 - HARDCODED SECRETS (A2 - Critical)
    // OWASP A02:2021 - Cryptographic Failures
    @GetMapping("/config")
    public ResponseEntity<Map<String, String>> hardcodedSecrets() {
        Map<String, String> config = new HashMap<>();
        // VULN: Hardcoded secrets exposed in API response
        config.put("aws_access_key", "AKIAIOSFODNN7EXAMPLE");
        config.put("aws_secret_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        config.put("stripe_api_key", "sk_test_4eC39HqLyjWDarjtT1zdp7dc");
        config.put("paypal_client_id", "AXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        config.put("paypal_secret", "EIXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        config.put("database_password", "SuperSecret123!");
        config.put("jwt_secret", "my-super-secret-jwt-key-32-chars-long");
        config.put("api_key", "12345-ABCDE-67890-FGHIJ");
        return ResponseEntity.ok(config);
    }

    // VULN 6 - COMMAND INJECTION (A3 - Critical)
    // OWASP A03:2021 - Injection
    @PostMapping("/ping")
    public ResponseEntity<String> commandInjection(@RequestParam String host) {
        try {
            // VULN: Command injection - no validation on host parameter
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return ResponseEntity.ok(output.toString());
        } catch (Exception e) {
            return ResponseEntity.ok("Error: " + e.getMessage());
        }
    }

    // VULN 7 - NO RATE LIMITING (A7 - Medium)
    // OWASP A07:2021 - Identification and Authentication Failures
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> noRateLimiting(
            @RequestParam String username,
            @RequestParam String password) {
        // VULN: No rate limiting - unlimited login attempts allowed
        Map<String, String> response = new HashMap<>();
        
        // Simulated login check (always fails but no rate limit)
        if (username.equals("admin") && password.equals("admin123")) {
            response.put("status", "success");
            response.put("token", "fake-jwt-token-" + System.currentTimeMillis());
        } else {
            response.put("status", "failed");
            response.put("message", "Invalid credentials");
        }
        
        return ResponseEntity.ok(response);
    }
}
