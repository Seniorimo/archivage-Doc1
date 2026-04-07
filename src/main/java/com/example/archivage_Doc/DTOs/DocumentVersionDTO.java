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
public class DocumentVersionDTO {
    private Long id;
    private Long documentId;
    private Integer versionNumber;
    private String filePath;
    private Long fileSize;
    private String changeDescription;
    private UserDTO createdBy;
    private LocalDateTime createdAt;
    private Boolean isCurrent;
} 