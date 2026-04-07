package com.example.archivage_Doc.Controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;

@RestController
public class SimpleTestController {

    // 🚩  forgotten password detected by SonarQube
    private static final String DB_PASS = "admin_super_secret_123!";

    @GetMapping("/hello")
    public String hello() {
        return "Hello, World!";
    }

    @GetMapping("/test-vuln")
    public String testVulnerability(@RequestParam("username") String username) {
        StringBuilder result = new StringBuilder();
        
        try {
            //🚩 fake connection to the database 
            Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/testdb", "root", DB_PASS);
            Statement statement = connection.createStatement();
            
            // 🚩 SQL Injection vulnerability to make SonarQube be alerted
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            ResultSet rs = statement.executeQuery(query);
            
            if (rs.next()) {
                result.append("User found!");
            }
            
            connection.close();
        } catch (Exception e) {
            result.append("Database error occurred.");
        }
        
        return result.toString();
    }
}