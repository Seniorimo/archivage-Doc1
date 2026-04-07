package com.example.archivage_Doc.DTOs;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DepartmentDTO {
    private Long id;
    private String name;
    private String description;
    private UserDTO manager;
    private Integer employeeCount;
    private Integer documentCount;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
} 