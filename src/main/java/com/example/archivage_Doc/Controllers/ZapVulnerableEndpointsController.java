package com.example.archivage_Doc.Controllers;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

// INTENTIONAL VULN - ZAP DAST: Vulnerable HTTP endpoints for PFE demo
// These endpoints are designed to be detected by OWASP ZAP during runtime scanning
@RestController
@RequestMapping("/api/vuln")
public class ZapVulnerableEndpointsController {

    // VULN 1: SQL Injection via GET parameter
    @GetMapping("/sqli/get")
    public ResponseEntity<Map<String, Object>> sqliGet(@RequestParam String id) {
        Map<String, Object> response = new HashMap<>();
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE id = '" + id + "'";
            ResultSet rs = stmt.executeQuery(query);
            response.put("query", query);
            response.put("status", "executed");
            response.put("message", "SQL Injection vulnerable endpoint");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return ResponseEntity.ok(response);
    }

    // VULN 2: SQL Injection via POST parameter
    @PostMapping("/sqli/post")
    public ResponseEntity<Map<String, Object>> sqliPost(@RequestBody Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();
        try {
            String username = body.get("username");
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            ResultSet rs = stmt.executeQuery(query);
            response.put("query", query);
            response.put("status", "executed");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return ResponseEntity.ok(response);
    }

    // VULN 3: Reflected XSS via GET parameter
    @GetMapping("/xss/reflected")
    public ResponseEntity<String> xssReflected(@RequestParam String input) {
        String html = "<html><body>Your input: " + input + "</body></html>";
        return ResponseEntity.ok()
                .header("X-XSS-Protection", "0")
                .body(html);
    }

    // VULN 4: Stored XSS via POST
    @PostMapping("/xss/stored")
    public ResponseEntity<Map<String, Object>> xssStored(@RequestBody Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();
        String comment = body.get("comment");
        response.put("stored_comment", comment);
        response.put("message", "Comment stored (XSS vulnerable)");
        return ResponseEntity.ok(response);
    }

    // VULN 5: Path Traversal
    @GetMapping("/path/traversal")
    public ResponseEntity<Map<String, Object>> pathTraversal(@RequestParam String file) {
        Map<String, Object> response = new HashMap<>();
        try {
            String basePath = "/app/uploads/";
            String fullPath = basePath + file;
            File targetFile = new File(fullPath);
            response.put("requested_path", fullPath);
            response.put("canonical_path", targetFile.getCanonicalPath());
            response.put("exists", targetFile.exists());
            response.put("message", "Path traversal vulnerable endpoint");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return ResponseEntity.ok(response);
    }

    // VULN 6: Local File Inclusion
    @GetMapping("/lfi")
    public ResponseEntity<Map<String, Object>> lfi(@RequestParam String file) {
        Map<String, Object> response = new HashMap<>();
        try {
            String content = new String(Files.readAllBytes(Paths.get(file)));
            response.put("file", file);
            response.put("content", content);
            response.put("message", "Local file inclusion vulnerable");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return ResponseEntity.ok(response);
    }

    // VULN 7: Command Injection
    @GetMapping("/cmd/injection")
    public ResponseEntity<Map<String, Object>> commandInjection(@RequestParam String host) {
        Map<String, Object> response = new HashMap<>();
        try {
            Process process = Runtime.getRuntime().exec("ping -c 1 " + host);
            String output = new String(process.getInputStream().readAllBytes());
            response.put("command", "ping -c 1 " + host);
            response.put("output", output);
            response.put("message", "Command injection vulnerable");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return ResponseEntity.ok(response);
    }

    // VULN 8: Open Redirect
    @GetMapping("/redirect")
    public ResponseEntity<Object> openRedirect(@RequestParam String url) {
        return ResponseEntity.status(302)
                .header("Location", url)
                .build();
    }

    // VULN 9: Information Disclosure - Server Headers
    @GetMapping("/info/headers")
    public ResponseEntity<String> infoHeaders(HttpServletRequest request) {
        StringBuilder headers = new StringBuilder();
        headers.append("Server Information:\n");
        headers.append("Server: Apache/2.4.41 (Ubuntu)\n");
        headers.append("X-Powered-By: PHP/7.4.3\n");
        headers.append("X-AspNet-Version: 4.0.30319\n");
        return ResponseEntity.ok()
                .header("Server", "Apache/2.4.41 (Ubuntu)")
                .header("X-Powered-By", "PHP/7.4.3")
                .header("X-AspNet-Version", "4.0.30319")
                .body(headers.toString());
    }

    // VULN 10: Missing Security Headers
    @GetMapping("/missing/headers")
    public ResponseEntity<Map<String, Object>> missingHeaders() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This endpoint intentionally lacks security headers");
        response.put("missing_headers", new String[]{
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "Referrer-Policy",
                "Permissions-Policy"
        });
        return ResponseEntity.ok(response);
    }

    // VULN 11: CORS Misconfiguration - Allow-Origin: *
    @GetMapping("/cors/misconfigured")
    @CrossOrigin(origins = "*")
    public ResponseEntity<Map<String, Object>> corsMisconfigured() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "CORS misconfigured with wildcard origin");
        response.put("cors_header", "Access-Control-Allow-Origin: *");
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                .header("Access-Control-Allow-Headers", "*")
                .header("Access-Control-Allow-Credentials", "true")
                .body(response);
    }

    // VULN 12: CSRF Vulnerable - No CSRF Token
    @PostMapping("/csrf/vulnerable")
    public ResponseEntity<Map<String, Object>> csrfVulnerable(@RequestBody Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();
        String action = body.get("action");
        response.put("action", action);
        response.put("message", "CSRF vulnerable - no token required");
        response.put("status", "completed");
        return ResponseEntity.ok(response);
    }

    // VULN 13: HTTP Strict Transport Security (HSTS) Missing
    @GetMapping("/hsts/missing")
    public ResponseEntity<Map<String, Object>> hstsMissing() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "HSTS header missing");
        response.put("should_have", "Strict-Transport-Security: max-age=31536000; includeSubDomains");
        return ResponseEntity.ok(response);
    }

    // VULN 14: Clickjacking - X-Frame-Options Missing
    @GetMapping("/clickjacking")
    public ResponseEntity<Map<String, Object>> clickjacking() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This page can be embedded in iframes (clickjacking vulnerable)");
        response.put("missing_header", "X-Frame-Options: DENY or SAMEORIGIN");
        return ResponseEntity.ok(response);
    }

    // VULN 15: Content Type Sniffing
    @GetMapping("/content/sniffing")
    public ResponseEntity<Map<String, Object>> contentTypeSniffing() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Content-Type sniffing vulnerable");
        return ResponseEntity.ok()
                .header("X-Content-Type-Options", "nosniff")
                .body(response);
    }

    // VULN 16: Cookie Security Issues
    @GetMapping("/cookie/insecure")
    public ResponseEntity<String> cookieInsecure(@CookieValue(value = "session", defaultValue = "none") String session) {
        return ResponseEntity.ok()
                .header("Set-Cookie", "session=insecure-session-id; Path=/; HttpOnly=false; Secure=false; SameSite=None")
                .body("Insecure cookie set");
    }

    // VULN 17: Debug Information Exposure
    @GetMapping("/debug/info")
    public ResponseEntity<Map<String, Object>> debugInfo() {
        Map<String, Object> response = new HashMap<>();
        response.put("debug_mode", true);
        response.put("java_version", System.getProperty("java.version"));
        response.put("os_name", System.getProperty("os.name"));
        response.put("os_version", System.getProperty("os.version"));
        response.put("user_name", System.getProperty("user.name"));
        response.put("user_home", System.getProperty("user.home"));
        response.put("user_dir", System.getProperty("user.dir"));
        response.put("class_path", System.getProperty("java.class.path"));
        response.put("message", "Debug information exposed");
        return ResponseEntity.ok(response);
    }

    // VULN 18: Error Message with Stack Trace
    @GetMapping("/error/trace")
    public ResponseEntity<Map<String, Object>> errorTrace(@RequestParam String input) {
        Map<String, Object> response = new HashMap<>();
        try {
            int result = Integer.parseInt(input);
            response.put("result", result);
        } catch (Exception e) {
            response.put("error", e.getMessage());
            response.put("stack_trace", e.getStackTrace());
            response.put("message", "Stack trace exposed in error");
        }
        return ResponseEntity.ok(response);
    }

    // VULN 19: Session ID in URL
    @GetMapping("/session/url")
    public ResponseEntity<Map<String, Object>> sessionInUrl(@RequestParam String sessionId) {
        Map<String, Object> response = new HashMap<>();
        response.put("session_id", sessionId);
        response.put("message", "Session ID exposed in URL");
        return ResponseEntity.ok(response);
    }

    // VULN 20: Autocomplete Enabled on Password Field
    @GetMapping("/autocomplete/form")
    public ResponseEntity<String> autocompleteForm() {
        String html = """
                <html>
                <body>
                <h2>Login Form with Autocomplete Enabled</h2>
                <form action="/api/vuln/login" method="post">
                    <label>Username:</label>
                    <input type="text" name="username" autocomplete="on"><br>
                    <label>Password:</label>
                    <input type="password" name="password" autocomplete="on"><br>
                    <button type="submit">Login</button>
                </form>
                </body>
                </html>
                """;
        return ResponseEntity.ok()
                .header("Content-Type", "text/html")
                .body(html);
    }

    // VULN 21: HTTP Response Splitting
    @GetMapping("/response/splitting")
    public ResponseEntity<String> responseSplitting(@RequestParam String redirect) {
        return ResponseEntity.ok()
                .header("Location", redirect)
                .body("Redirect response");
    }

    // VULN 22: Server Side Request Forgery (SSRF)
    @GetMapping("/ssrf")
    public ResponseEntity<Map<String, Object>> ssrf(@RequestParam String url) {
        Map<String, Object> response = new HashMap<>();
        try {
            java.net.URL targetUrl = new java.net.URL(url);
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) targetUrl.openConnection();
            conn.setRequestMethod("GET");
            int responseCode = conn.getResponseCode();
            response.put("requested_url", url);
            response.put("response_code", responseCode);
            response.put("message", "SSRF vulnerable endpoint");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return ResponseEntity.ok(response);
    }

    // VULN 23: XML External Entity (XXE)
    @PostMapping("/xxe")
    public ResponseEntity<Map<String, Object>> xxe(@RequestBody String xmlData) {
        Map<String, Object> response = new HashMap<>();
        try {
            javax.xml.parsers.DocumentBuilderFactory factory = 
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            factory.setExpandEntityReferences(true);
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            builder.parse(new java.io.ByteArrayInputStream(xmlData.getBytes()));
            response.put("message", "XXE vulnerable - parsed XML");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return ResponseEntity.ok(response);
    }

    // VULN 24: JSON Injection
    @PostMapping("/json/injection")
    public ResponseEntity<Map<String, Object>> jsonInjection(@RequestBody String jsonData) {
        Map<String, Object> response = new HashMap<>();
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            Object obj = mapper.readValue(jsonData, Object.class);
            response.put("parsed_json", obj);
            response.put("message", "JSON injection vulnerable");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return ResponseEntity.ok(response);
    }

    // VULN 25: LDAP Injection
    @GetMapping("/ldap/injection")
    public ResponseEntity<Map<String, Object>> ldapInjection(@RequestParam String username) {
        Map<String, Object> response = new HashMap<>();
        String ldapQuery = "(uid=" + username + ")";
        response.put("ldap_query", ldapQuery);
        response.put("message", "LDAP injection vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 26: Host Header Injection
    @GetMapping("/host/injection")
    public ResponseEntity<Map<String, Object>> hostInjection(HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        String host = request.getHeader("Host");
        response.put("host_header", host);
        response.put("message", "Host header injection vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 27: User-Agent Injection
    @GetMapping("/useragent/injection")
    public ResponseEntity<Map<String, Object>> userAgentInjection(HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        String userAgent = request.getHeader("User-Agent");
        response.put("user_agent", userAgent);
        response.put("message", "User-Agent injection vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 28: Referer Header Injection
    @GetMapping("/referer/injection")
    public ResponseEntity<Map<String, Object>> refererInjection(HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        String referer = request.getHeader("Referer");
        response.put("referer", referer);
        response.put("message", "Referer header injection vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 29: Email Header Injection
    @PostMapping("/email/injection")
    public ResponseEntity<Map<String, Object>> emailInjection(@RequestBody Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();
        String to = body.get("to");
        String subject = body.get("subject");
        String email = "To: " + to + "\nSubject: " + subject + "\n\nEmail body";
        response.put("email_headers", email);
        response.put("message", "Email header injection vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 30: Format String Injection
    @GetMapping("/format/injection")
    public ResponseEntity<Map<String, Object>> formatInjection(@RequestParam String input) {
        Map<String, Object> response = new HashMap<>();
        String formatted = String.format("User input: %s", input);
        response.put("formatted", formatted);
        response.put("message", "Format string injection vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 31: Buffer Overflow (simulation)
    @GetMapping("/buffer/overflow")
    public ResponseEntity<Map<String, Object>> bufferOverflow(@RequestParam String input) {
        Map<String, Object> response = new HashMap<>();
        char[] buffer = new char[100];
        if (input.length() > 100) {
            input.getChars(0, 100, buffer, 0);
            response.put("warning", "Input truncated to prevent buffer overflow");
        } else {
            input.getChars(0, input.length(), buffer, 0);
        }
        response.put("input_length", input.length());
        response.put("message", "Buffer overflow vulnerable (simulated)");
        return ResponseEntity.ok(response);
    }

    // VULN 32: Integer Overflow
    @GetMapping("/integer/overflow")
    public ResponseEntity<Map<String, Object>> integerOverflow(@RequestParam int value) {
        Map<String, Object> response = new HashMap<>();
        long result = (long) value * 1000000;
        response.put("input", value);
        response.put("result", result);
        response.put("message", "Integer overflow vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 33: Race Condition
    @GetMapping("/race/condition")
    public ResponseEntity<Map<String, Object>> raceCondition(@RequestParam String id) {
        Map<String, Object> response = new HashMap<>();
        // Simulated race condition - checking and using a resource
        if (id != null && !id.isEmpty()) {
            response.put("resource_id", id);
            response.put("message", "Race condition vulnerable (simulated)");
        }
        return ResponseEntity.ok(response);
    }

    // VULN 34: Insecure Direct Object Reference (IDOR)
    @GetMapping("/idor")
    public ResponseEntity<Map<String, Object>> idor(@RequestParam String userId) {
        Map<String, Object> response = new HashMap<>();
        response.put("user_id", userId);
        response.put("username", "user_" + userId);
        response.put("email", "user_" + userId + "@example.com");
        response.put("message", "IDOR vulnerable - can access any user data");
        return ResponseEntity.ok(response);
    }

    // VULN 35: Privilege Escalation
    @PostMapping("/privilege/escalation")
    public ResponseEntity<Map<String, Object>> privilegeEscalation(@RequestBody Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();
        String role = body.get("role");
        response.put("previous_role", "user");
        response.put("new_role", role);
        response.put("admin", true);
        response.put("message", "Privilege escalation vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 36: Authentication Bypass
    @PostMapping("/auth/bypass")
    public ResponseEntity<Map<String, Object>> authBypass(@RequestBody Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();
        String username = body.get("username");
        response.put("authenticated", true);
        response.put("username", username);
        response.put("session_token", "bypass-token-" + System.currentTimeMillis());
        response.put("message", "Authentication bypass vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 37: Weak Password Policy
    @PostMapping("/password/weak")
    public ResponseEntity<Map<String, Object>> weakPassword(@RequestBody Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();
        String password = body.get("password");
        response.put("password_accepted", true);
        response.put("password_strength", "weak");
        response.put("message", "Weak password policy - accepts any password");
        return ResponseEntity.ok(response);
    }

    // VULN 38: Password in URL
    @GetMapping("/password/url")
    public ResponseEntity<Map<String, Object>> passwordInUrl(@RequestParam String password) {
        Map<String, Object> response = new HashMap<>();
        response.put("password", password);
        response.put("message", "Password exposed in URL");
        return ResponseEntity.ok(response);
    }

    // VULN 39: Sensitive Data in GET
    @GetMapping("/sensitive/get")
    public ResponseEntity<Map<String, Object>> sensitiveInGet(
            @RequestParam String creditCard,
            @RequestParam String ssn) {
        Map<String, Object> response = new HashMap<>();
        response.put("credit_card", creditCard);
        response.put("ssn", ssn);
        response.put("message", "Sensitive data transmitted via GET");
        return ResponseEntity.ok(response);
    }

    // VULN 40: Unencrypted Sensitive Data
    @PostMapping("/sensitive/unencrypted")
    public ResponseEntity<Map<String, Object>> sensitiveUnencrypted(@RequestBody Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();
        String data = body.get("sensitive_data");
        response.put("stored_data", data);
        response.put("encrypted", false);
        response.put("message", "Sensitive data stored unencrypted");
        return ResponseEntity.ok(response);
    }

    // VULN 41: Cache Control Missing
    @GetMapping("/cache/missing")
    public ResponseEntity<Map<String, Object>> cacheMissing() {
        Map<String, Object> response = new HashMap<>();
        response.put("sensitive_data", "This should not be cached");
        response.put("message", "Cache-Control header missing");
        return ResponseEntity.ok(response);
    }

    // VULN 42: Pragma Header Missing
    @GetMapping("/pragma/missing")
    public ResponseEntity<Map<String, Object>> pragmaMissing() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Pragma: no-cache header missing");
        return ResponseEntity.ok(response);
    }

    // VULN 43: ETag Header Missing
    @GetMapping("/etag/missing")
    public ResponseEntity<Map<String, Object>> etagMissing() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "ETag header missing for cache validation");
        return ResponseEntity.ok(response);
    }

    // VULN 44: Timestamp Disclosure
    @GetMapping("/timestamp/disclosure")
    public ResponseEntity<Map<String, Object>> timestampDisclosure() {
        Map<String, Object> response = new HashMap<>();
        response.put("server_time", System.currentTimeMillis());
        response.put("server_date", new java.util.Date());
        response.put("message", "Timestamp disclosure");
        return ResponseEntity.ok(response);
    }

    // VULN 45: ASP.NET Version Disclosure
    @GetMapping("/aspnet/version")
    public ResponseEntity<String> aspNetVersion() {
        return ResponseEntity.ok()
                .header("X-AspNet-Version", "4.0.30319")
                .header("X-AspNetMvc-Version", "5.1")
                .body("ASP.NET version disclosed");
    }

    // VULN 46: PHP Version Disclosure
    @GetMapping("/php/version")
    public ResponseEntity<String> phpVersion() {
        return ResponseEntity.ok()
                .header("X-Powered-By", "PHP/7.4.3")
                .body("PHP version disclosed");
    }

    // VULN 47: Python Version Disclosure
    @GetMapping("/python/version")
    public ResponseEntity<String> pythonVersion() {
        return ResponseEntity.ok()
                .header("Server", "Python/3.8.0")
                .body("Python version disclosed");
    }

    // VULN 48: Database Version Disclosure
    @GetMapping("/database/version")
    public ResponseEntity<Map<String, Object>> databaseVersion() {
        Map<String, Object> response = new HashMap<>();
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
            DatabaseMetaData meta = conn.getMetaData();
            response.put("database_product_name", meta.getDatabaseProductName());
            response.put("database_version", meta.getDatabaseProductVersion());
            response.put("driver_name", meta.getDriverName());
            response.put("driver_version", meta.getDriverVersion());
            response.put("message", "Database version disclosed");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return ResponseEntity.ok(response);
    }

    // VULN 49: Directory Listing Enabled
    @GetMapping("/directory/listing")
    public ResponseEntity<Map<String, Object>> directoryListing(@RequestParam String path) {
        Map<String, Object> response = new HashMap<>();
        File dir = new File(path);
        if (dir.exists() && dir.isDirectory()) {
            String[] files = dir.list();
            response.put("directory", path);
            response.put("files", files);
            response.put("message", "Directory listing enabled");
        } else {
            response.put("error", "Directory not found");
        }
        return ResponseEntity.ok(response);
    }

    // VULN 50: Default Account
    @PostMapping("/default/account")
    public ResponseEntity<Map<String, Object>> defaultAccount(@RequestBody Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();
        String username = body.get("username");
        String password = body.get("password");
        
        if ("admin".equals(username) && "admin123".equals(password)) {
            response.put("authenticated", true);
            response.put("message", "Default account login successful");
        } else {
            response.put("authenticated", false);
            response.put("message", "Invalid credentials");
        }
        return ResponseEntity.ok(response);
    }

    // VULN 51: Backup File Disclosure
    @GetMapping("/backup/file")
    public ResponseEntity<Map<String, Object>> backupFile(@RequestParam String filename) {
        Map<String, Object> response = new HashMap<>();
        String backupFile = filename + ".bak";
        response.put("backup_file", backupFile);
        response.put("message", "Backup file disclosure vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 52: Config File Disclosure
    @GetMapping("/config/file")
    public ResponseEntity<Map<String, Object>> configFile(@RequestParam String filename) {
        Map<String, Object> response = new HashMap<>();
        String[] configFiles = {"web.config", "web.xml", "application.properties", ".env", "config.yml"};
        response.put("config_files", configFiles);
        response.put("message", "Config file disclosure vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 53: Source Code Disclosure
    @GetMapping("/source/disclosure")
    public ResponseEntity<Map<String, Object>> sourceDisclosure(@RequestParam String file) {
        Map<String, Object> response = new HashMap<>();
        String sourceFile = file + ".java";
        response.put("source_file", sourceFile);
        response.put("message", "Source code disclosure vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 54: Comment Disclosure
    @GetMapping("/comment/disclosure")
    public ResponseEntity<String> commentDisclosure() {
        String html = """
                <html>
                <body>
                <!-- TODO: Remove this debug endpoint in production -->
                <!-- DEBUG: Database password is admin123 -->
                <!-- FIXME: SQL injection vulnerability in line 42 -->
                <h1>Comment Disclosure</h1>
                </body>
                </html>
                """;
        return ResponseEntity.ok()
                .header("Content-Type", "text/html")
                .body(html);
    }

    // VULN 55: ViewState Parameter
    @GetMapping("/viewstate/parameter")
    public ResponseEntity<Map<String, Object>> viewStateParameter() {
        Map<String, Object> response = new HashMap<>();
        response.put("__VIEWSTATE", "/wEPDwULLTE1MjkyODc2MDNkZBYCAgMPZBYCAgEPDxYCHgRUZXh0BQRhZG1pbg8PZGZk");
        response.put("message", "ViewState parameter exposed");
        return ResponseEntity.ok(response);
    }

    // VULN 56: EventValidation Parameter
    @GetMapping("/eventvalidation/parameter")
    public ResponseEntity<Map<String, Object>> eventValidationParameter() {
        Map<String, Object> response = new HashMap<>();
        response.put("__EVENTVALIDATION", "/wEdAAYv8Mz9z7/7");
        response.put("message", "EventValidation parameter exposed");
        return ResponseEntity.ok(response);
    }

    // VULN 57: Hidden Field
    @GetMapping("/hidden/field")
    public ResponseEntity<String> hiddenField() {
        String html = """
                <html>
                <body>
                <form>
                    <input type="hidden" name="user_id" value="12345">
                    <input type="hidden" name="role" value="admin">
                    <input type="hidden" name="price" value="100">
                    <button type="submit">Submit</button>
                </form>
                </body>
                </html>
                """;
        return ResponseEntity.ok()
                .header("Content-Type", "text/html")
                .body(html);
    }

    // VULN 58: Form without CSRF Token
    @GetMapping("/form/nocsrf")
    public ResponseEntity<String> formNoCsrf() {
        String html = """
                <html>
                <body>
                <form action="/api/vuln/submit" method="post">
                    <input type="text" name="username">
                    <input type="password" name="password">
                    <button type="submit">Login</button>
                </form>
                </body>
                </html>
                """;
        return ResponseEntity.ok()
                .header("Content-Type", "text/html")
                .body(html);
    }

    // VULN 59: HTTP Verb Tampering
    @RequestMapping(value = "/verb/tampering", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE})
    public ResponseEntity<Map<String, Object>> verbTampering() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "HTTP verb tampering - accepts multiple verbs");
        return ResponseEntity.ok(response);
    }

    // VULN 60: Parameter Pollution
    @GetMapping("/parameter/pollution")
    public ResponseEntity<Map<String, Object>> parameterPollution(@RequestParam String id) {
        Map<String, Object> response = new HashMap<>();
        response.put("id", id);
        response.put("message", "Parameter pollution vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 61: Force Browsing
    @GetMapping("/admin/dashboard")
    public ResponseEntity<Map<String, Object>> forceBrowsingAdmin() {
        Map<String, Object> response = new HashMap<>();
        response.put("admin_panel", true);
        response.put("users", new String[]{"admin", "user1", "user2"});
        response.put("message", "Admin panel accessible without authentication");
        return ResponseEntity.ok(response);
    }

    // VULN 62: Predictable Resource Location
    @GetMapping("/backup/{id}")
    public ResponseEntity<Map<String, Object>> predictableResource(@PathVariable String id) {
        Map<String, Object> response = new HashMap<>();
        response.put("backup_id", id);
        response.put("backup_url", "/backups/backup_" + id + ".zip");
        response.put("message", "Predictable resource location");
        return ResponseEntity.ok(response);
    }

    // VULN 63: Subdomain Takeover
    @GetMapping("/subdomain/takeover")
    public ResponseEntity<Map<String, Object>> subdomainTakeover() {
        Map<String, Object> response = new HashMap<>();
        response.put("cname", "staging.example.com");
        response.put("status", "CNAME points to non-existent resource");
        response.put("message", "Subdomain takeover vulnerable");
        return ResponseEntity.ok(response);
    }

    // VULN 64: SSL/TLS Weak Cipher
    @GetMapping("/ssl/weak")
    public ResponseEntity<Map<String, Object>> sslWeak() {
        Map<String, Object> response = new HashMap<>();
        response.put("ssl_version", "TLS 1.0");
        response.put("cipher_suite", "RC4-MD5");
        response.put("message", "Weak SSL/TLS configuration");
        return ResponseEntity.ok(response);
    }

    // VULN 65: Self-Signed Certificate
    @GetMapping("/certificate/selfsigned")
    public ResponseEntity<Map<String, Object>> selfSignedCertificate() {
        Map<String, Object> response = new HashMap<>();
        response.put("certificate", "self-signed");
        response.put("issuer", "Unknown");
        response.put("message", "Self-signed certificate in use");
        return ResponseEntity.ok(response);
    }

    // VULN 66: Mixed Content
    @GetMapping("/mixed/content")
    public ResponseEntity<String> mixedContent() {
        String html = """
                <html>
                <body>
                <script src="http://example.com/script.js"></script>
                <img src="http://example.com/image.jpg">
                </body>
                </html>
                """;
        return ResponseEntity.ok()
                .header("Content-Type", "text/html")
                .body(html);
    }

    // VULN 67: Cross-Origin Resource Sharing (CORS) Abuse
    @GetMapping("/cors/abuse")
    public ResponseEntity<Map<String, Object>> corsAbuse(HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        String origin = request.getHeader("Origin");
        response.put("origin", origin);
        response.put("access_control_allow_origin", "*");
        response.put("message", "CORS abuse vulnerable");
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                .header("Access-Control-Allow-Headers", "*")
                .body(response);
    }

    // VULN 68: JSONP Vulnerability
    @GetMapping("/jsonp/vulnerable")
    public ResponseEntity<String> jsonpVulnerable(@RequestParam String callback) {
        String json = "{\"data\": \"sensitive information\"}";
        String jsonp = callback + "(" + json + ");";
        return ResponseEntity.ok()
                .header("Content-Type", "application/javascript")
                .body(jsonp);
    }

    // VULN 69: WebSocket Security
    @GetMapping("/websocket/insecure")
    public ResponseEntity<Map<String, Object>> websocketInsecure() {
        Map<String, Object> response = new HashMap<>();
        response.put("websocket_url", "ws://example.com/socket");
        response.put("message", "Insecure WebSocket (ws:// instead of wss://)");
        return ResponseEntity.ok(response);
    }

    // VULN 70: GraphQL Introspection
    @GetMapping("/graphql/introspection")
    public ResponseEntity<Map<String, Object>> graphqlIntrospection() {
        Map<String, Object> response = new HashMap<>();
        response.put("schema", "Full GraphQL schema exposed via introspection");
        response.put("query", "{ __schema { types { name } } }");
        response.put("message", "GraphQL introspection enabled");
        return ResponseEntity.ok(response);
    }
}
