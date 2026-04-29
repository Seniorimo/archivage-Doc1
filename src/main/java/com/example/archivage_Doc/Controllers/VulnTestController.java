package com.example.archivage_Doc.Controllers;

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
}
