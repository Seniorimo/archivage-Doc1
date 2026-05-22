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

    // VULN 6 - Reflected XSS (CWE-79, ZAP alert: Cross Site Scripting (Reflected) - HIGH)
    @GetMapping("/xss")
    public ResponseEntity<String> reflectedXss(@RequestParam String input) {
        // VULN: Direct reflection of user input without sanitization - HIGH
        String html = "<html><body>You entered: " + input + "</body></html>";
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .header("X-Powered-By", "PHP/5.6.0")
                .body(html);
    }

    // VULN 7 - Reflected XSS with script tag (CWE-79, ZAP alert: Cross Site Scripting (Reflected) - HIGH)
    @GetMapping("/xss-script")
    public ResponseEntity<String> reflectedXssScript(@RequestParam String input) {
        // VULN: Direct reflection with script tag - HIGH
        String html = "<html><body><script>alert('" + input + "');</script></body></html>";
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .header("X-Powered-By", "PHP/5.6.0")
                .body(html);
    }

    // VULN 8 - Stored XSS simulation (CWE-79, ZAP alert: Cross Site Scripting (Reflected) - HIGH)
    @GetMapping("/xss-stored")
    public ResponseEntity<String> storedXss(@RequestParam String comment) {
        // VULN: Direct reflection simulating stored XSS - HIGH
        String html = "<html><body>Comment: " + comment + "</body></html>";
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .body(html);
    }

    // VULN 9 - CORS misconfiguration (ZAP alert: Cross-Domain Misconfiguration - HIGH)
    @GetMapping("/cors")
    public ResponseEntity<String> corsMisconfig(@RequestParam String data) {
        // VULN: Overly permissive CORS configuration - HIGH
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
                .header("Access-Control-Allow-Headers", "*")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Access-Control-Max-Age", "3600")
                .body("CORS misconfigured endpoint: " + data);
    }

    // VULN 10 - CORS with null origin (ZAP alert: Cross-Domain Misconfiguration - HIGH)
    @GetMapping("/cors-null")
    public ResponseEntity<String> corsNullOrigin(@RequestParam String data) {
        // VULN: Accepting null origin - HIGH
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "null")
                .header("Access-Control-Allow-Credentials", "true")
                .body("CORS with null origin: " + data);
    }

    // VULN 11 - Missing security headers (ZAP alerts: Multiple - HIGH)
    @GetMapping("/headers")
    public ResponseEntity<String> missingSecurityHeaders(@RequestParam String info) {
        // VULN: Missing X-Frame-Options, CSP, HSTS, X-Content-Type-Options - HIGH
        return ResponseEntity.ok()
                .header("Server", "Apache/2.4.18 (Ubuntu)")
                .header("X-Powered-By", "Express/4.0.0")
                .body("Endpoint with missing security headers: " + info);
    }

    // VULN 12 - Information disclosure in headers (ZAP alert: Information Disclosure - MEDIUM)
    @GetMapping("/info-disclosure")
    public ResponseEntity<String> infoDisclosure(@RequestParam String query) {
        // VULN: Exposing sensitive information in response headers - MEDIUM
        return ResponseEntity.ok()
                .header("X-Debug-Info", "debug_mode_enabled=true")
                .header("X-Server-Version", "1.0.0-beta")
                .header("X-Environment", "development")
                .header("X-Database-Version", "MySQL 5.7")
                .header("X-Framework", "Spring Boot 2.7.0")
                .body("Information disclosure: " + query);
    }

    // VULN 13 - CSRF protection missing (ZAP alert: Cross Site Request Forgery - MEDIUM)
    @PostMapping("/csrf")
    public ResponseEntity<String> csrfVulnerable(@RequestParam String action) {
        // VULN: No CSRF token required for state-changing operation - MEDIUM
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .body("Action performed without CSRF protection: " + action);
    }

    // VULN 14 - Cookie without Secure flag (ZAP alert: Cookie Without Secure Flag - MEDIUM)
    @GetMapping("/cookie")
    public ResponseEntity<String> insecureCookie(@RequestParam String value) {
        // VULN: Setting cookie without Secure and HttpOnly flags - MEDIUM
        return ResponseEntity.ok()
                .header("Set-Cookie", "sessionid=" + value + "; Path=/; SameSite=Lax")
                .body("Insecure cookie set");
    }

    // VULN 15 - Cookie with HttpOnly missing (ZAP alert: Cookie Without HttpOnly Flag - MEDIUM)
    @GetMapping("/cookie-httponly")
    public ResponseEntity<String> cookieWithoutHttpOnly(@RequestParam String value) {
        // VULN: Setting cookie without HttpOnly flag - MEDIUM
        return ResponseEntity.ok()
                .header("Set-Cookie", "sessionid=" + value + "; Path=/; Secure; SameSite=Lax")
                .body("Cookie without HttpOnly set");
    }

    // VULN 16 - Content Type sniffing (ZAP alert: Content Type Sniffing - MEDIUM)
    @GetMapping("/sniffing")
    public ResponseEntity<String> contentTypeSniffing(@RequestParam String data) {
        // VULN: Missing X-Content-Type-Options: nosniff - MEDIUM
        return ResponseEntity.ok()
                .header("Content-Type", "text/html")
                .body("<div>User data: " + data + "</div>");
    }

    // VULN 17 - Clickjacking (ZAP alert: Clickjacking - MEDIUM)
    @GetMapping("/clickjack")
    public ResponseEntity<String> clickjacking(@RequestParam String content) {
        // VULN: Missing X-Frame-Options or CSP frame-ancestors - MEDIUM
        return ResponseEntity.ok()
                .body("<iframe src='https://evil.com'></iframe>" + content);
    }

    // VULN 18 - HTTP Strict Transport Security missing (ZAP alert: HSTS - MEDIUM)
    @GetMapping("/no-hsts")
    public ResponseEntity<String> noHsts(@RequestParam String data) {
        // VULN: Missing Strict-Transport-Security header - MEDIUM
        return ResponseEntity.ok()
                .body("Endpoint without HSTS: " + data);
    }

    // VULN 19 - Server version disclosure (ZAP alert: Server Header - LOW)
    @GetMapping("/server-info")
    public ResponseEntity<String> serverInfo(@RequestParam String query) {
        // VULN: Exposing server version information - LOW
        return ResponseEntity.ok()
                .header("Server", "nginx/1.14.0 Ubuntu")
                .header("X-AspNet-Version", "4.0.30319")
                .body("Server info endpoint: " + query);
    }

    // VULN 20 - SQL Injection endpoint (ZAP alert: SQL Injection - HIGH)
    @GetMapping("/sqli-direct")
    public ResponseEntity<String> sqlInjectionDirect(@RequestParam String id) {
        // VULN: Direct SQL injection - HIGH
        try {
            String query = "SELECT * FROM users WHERE id = '" + id + "'";
            return ResponseEntity.ok()
                    .header("Access-Control-Allow-Origin", "*")
                    .body("SQL query executed: " + query);
        } catch (Exception e) {
            return ResponseEntity.ok().body("Error: " + e.getMessage());
        }
    }

    // VULN 21 - Path Traversal endpoint (ZAP alert: Path Traversal - HIGH)
    @GetMapping("/path-traversal")
    public ResponseEntity<String> pathTraversal(@RequestParam String file) {
        // VULN: Direct path traversal - HIGH
        try {
            String filePath = "/app/uploads/" + file;
            return ResponseEntity.ok()
                    .header("Access-Control-Allow-Origin", "*")
                    .body("Attempting to read: " + filePath);
        } catch (Exception e) {
            return ResponseEntity.ok().body("Error: " + e.getMessage());
        }
    }

    // VULN 22 - Open Redirect (ZAP alert: Open Redirect - MEDIUM)
    @GetMapping("/redirect")
    public ResponseEntity<String> openRedirect(@RequestParam String url) {
        // VULN: Unvalidated redirect - MEDIUM
        return ResponseEntity.status(302)
                .header("Location", url)
                .header("Access-Control-Allow-Origin", "*")
                .body("Redirecting to: " + url);
    }
}
