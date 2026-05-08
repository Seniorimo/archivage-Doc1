package com.example.archivage_Doc.Controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/test/devsecops")
public class DevSecOpsDemoVulnerableController {

    // INTENTIONAL VULN - SONARQUBE/GITLEAKS DEMO ONLY.
    // This controller is not business code. It exists to make SAST/DAST/secret
    // scanners produce visible findings during the PFE DevSecOps demonstration.
    private static final String DEMO_DB_PASSWORD = "Password123!";
    private static final String DEMO_JWT_SECRET = "devsecops-demo-jwt-secret-123456";

    @GetMapping("/sqli")
    public ResponseEntity<String> sqlInjection(@RequestParam String username) throws Exception {
        Connection connection = DriverManager.getConnection("jdbc:h2:mem:demo", "sa", DEMO_DB_PASSWORD);
        Statement statement = connection.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        ResultSet resultSet = statement.executeQuery(query);
        return ResponseEntity.ok("Executed vulnerable query: " + query + " / result=" + resultSet);
    }

    @GetMapping("/cmd")
    public ResponseEntity<String> commandInjection(@RequestParam String host) throws Exception {
        Process process = Runtime.getRuntime().exec("ping -c 1 " + host);
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return ResponseEntity.ok(output);
    }

    @GetMapping("/path")
    public ResponseEntity<String> pathTraversal(@RequestParam String file) throws Exception {
        File target = new File("/app/uploads/" + file);
        return ResponseEntity.ok("Demo file path: " + target.getCanonicalPath());
    }

    @GetMapping("/crypto")
    public ResponseEntity<Map<String, String>> weakCrypto(@RequestParam String value) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] digest = md5.digest(value.getBytes(StandardCharsets.UTF_8));
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        Map<String, String> response = new HashMap<>();
        response.put("md5-length", String.valueOf(digest.length));
        response.put("cipher", cipher.getAlgorithm());
        response.put("demo-secret", DEMO_JWT_SECRET);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/xxe")
    public ResponseEntity<String> xxe(@RequestParam String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setExpandEntityReferences(true);
        factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        return ResponseEntity.ok("Parsed XML with intentionally unsafe parser configuration");
    }
}
