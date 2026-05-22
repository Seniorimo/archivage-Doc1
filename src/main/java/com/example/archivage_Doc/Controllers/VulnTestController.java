package com.example.archivage_Doc.Controllers;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.io.*;

@RestController
@RequestMapping("/api/test")
public class VulnTestController {

    // VULN 1 - SQL Injection (CWE-89)
    @GetMapping("/sqli")
    public String sqlInjection(@RequestParam String id) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'").toString();
    }

    // VULN 2 - Path Traversal (CWE-22)
    @GetMapping("/file")
    public String readFile(@RequestParam String name) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader("/app/uploads/" + name));
        return br.readLine();
    }

    // VULN 3 - Hardcoded password (CWE-259)
    private static final String DB_PASSWORD = "admin1234";
    private static final String SECRET_KEY  = "hardcoded_secret_key_xyz";

    // VULN 4 - Command Injection (CWE-78)
    @GetMapping("/cmd")
    public String commandInjection(@RequestParam String input) throws Exception {
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("ls " + input); // OS command injection
        return new String(process.getInputStream().readAllBytes());
    }

    // VULN 5 - XXE (CWE-611)
    @PostMapping("/xml")
    public String xxe(@RequestBody String xmlData) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        // VULN: XXE not disabled
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new java.io.ByteArrayInputStream(xmlData.getBytes())).toString();
    }

    // INTENTIONAL VULN - ZAP DEMO ONLY.
    // These endpoints contain security vulnerabilities for DevSecOps PFE demonstration.
    // They are designed to be detected by OWASP ZAP DAST scanner.

    // VULN 6 - Reflected XSS (CWE-79, ZAP alert: Cross Site Scripting (Reflected))
    @GetMapping("/xss")
    public ResponseEntity<String> reflectedXss(@RequestParam String input) {
        // VULN: Direct reflection of user input without sanitization
        String html = "<html><body>You entered: " + input + "</body></html>";
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .header("X-Powered-By", "PHP/5.6.0")
                .body(html);
    }

    // VULN 7 - CORS misconfiguration (ZAP alert: Cross-Domain Misconfiguration)
    @GetMapping("/cors")
    public ResponseEntity<String> corsMisconfig(@RequestParam String data) {
        // VULN: Overly permissive CORS configuration
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                .header("Access-Control-Allow-Headers", "*")
                .header("Access-Control-Allow-Credentials", "true")
                .body("CORS misconfigured endpoint: " + data);
    }

    // VULN 8 - Missing security headers (ZAP alerts: Multiple)
    @GetMapping("/headers")
    public ResponseEntity<String> missingSecurityHeaders(@RequestParam String info) {
        // VULN: Missing X-Frame-Options, CSP, HSTS, X-Content-Type-Options
        return ResponseEntity.ok()
                .header("Server", "Apache/2.4.18 (Ubuntu)")
                .header("X-Powered-By", "Express/4.0.0")
                .body("Endpoint with missing security headers: " + info);
    }

    // VULN 9 - Information disclosure in headers (ZAP alert: Information Disclosure)
    @GetMapping("/info-disclosure")
    public ResponseEntity<String> infoDisclosure(@RequestParam String query) {
        // VULN: Exposing sensitive information in response headers
        return ResponseEntity.ok()
                .header("X-Debug-Info", "debug_mode_enabled=true")
                .header("X-Server-Version", "1.0.0-beta")
                .header("X-Environment", "development")
                .header("X-Database-Version", "MySQL 5.7")
                .body("Information disclosure: " + query);
    }

    // VULN 10 - CSRF protection missing (ZAP alert: Cross Site Request Forgery)
    @PostMapping("/csrf")
    public ResponseEntity<String> csrfVulnerable(@RequestParam String action) {
        // VULN: No CSRF token required for state-changing operation
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .body("Action performed without CSRF protection: " + action);
    }

    // VULN 11 - Cookie without Secure flag (ZAP alert: Cookie Without Secure Flag)
    @GetMapping("/cookie")
    public ResponseEntity<String> insecureCookie(@RequestParam String value) {
        // VULN: Setting cookie without Secure and HttpOnly flags
        return ResponseEntity.ok()
                .header("Set-Cookie", "sessionid=" + value + "; Path=/; SameSite=Lax")
                .body("Insecure cookie set");
    }

    // VULN 12 - Content Type sniffing (ZAP alert: Content Type Sniffing)
    @GetMapping("/sniffing")
    public ResponseEntity<String> contentTypeSniffing(@RequestParam String data) {
        // VULN: Missing X-Content-Type-Options: nosniff
        return ResponseEntity.ok()
                .header("Content-Type", "text/html")
                .body("<div>User data: " + data + "</div>");
    }

    // VULN 13 - Clickjacking (ZAP alert: Clickjacking)
    @GetMapping("/clickjack")
    public ResponseEntity<String> clickjacking(@RequestParam String content) {
        // VULN: Missing X-Frame-Options or CSP frame-ancestors
        return ResponseEntity.ok()
                .body("<iframe src='https://evil.com'></iframe>" + content);
    }

    // VULN 14 - HTTP Strict Transport Security missing (ZAP alert: HSTS)
    @GetMapping("/no-hsts")
    public ResponseEntity<String> noHsts(@RequestParam String data) {
        // VULN: Missing Strict-Transport-Security header
        return ResponseEntity.ok()
                .body("Endpoint without HSTS: " + data);
    }

    // VULN 15 - Server version disclosure (ZAP alert: Server Header)
    @GetMapping("/server-info")
    public ResponseEntity<String> serverInfo(@RequestParam String query) {
        // VULN: Exposing server version information
        return ResponseEntity.ok()
                .header("Server", "nginx/1.14.0 Ubuntu")
                .header("X-AspNet-Version", "4.0.30319")
                .body("Server info endpoint: " + query);
    }
}
