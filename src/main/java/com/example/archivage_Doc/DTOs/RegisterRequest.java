package com.example.archivage_Doc.DTOs;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String username;
    private String password;
    private String departmentCode = "DEFAULT";
    private Boolean useAlternativeMethod;
    private String createType;
    private String role;
    
    @Override
    public String toString() {
        return "RegisterRequest{" +
                "username='" + username + '\'' +
                ", departmentCode='" + departmentCode + '\'' +
                ", role='" + role + '\'' +
                ", useAlternativeMethod=" + useAlternativeMethod +
                ", createType='" + createType + '\'' +
                ", password='[PROTECTED]'" +
                '}';
    }
} 