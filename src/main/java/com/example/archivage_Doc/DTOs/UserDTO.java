package com.example.archivage_Doc.DTOs;

import com.example.archivage_Doc.Enums.DepartmentLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {
    private Long id;
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private DepartmentLevel level;
    private Long departmentId;
    private String departmentName;
    private LocalDateTime createdAt;
    private Set<String> permissions;
    private Boolean isActive;
    private Boolean isAdmin;
    private String phoneNumber;
}

