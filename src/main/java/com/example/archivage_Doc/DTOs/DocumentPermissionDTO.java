package com.example.archivage_Doc.DTOs;

import com.example.archivage_Doc.Enums.DocumentPermission;
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
public class DocumentPermissionDTO {
    private Long id;
    private Long documentId;
    private UserDTO user;
    private Set<DocumentPermission> permissions;
    private LocalDateTime grantedAt;
    private LocalDateTime expiresAt;
    private UserDTO grantedBy;
} 