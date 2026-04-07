package com.example.archivage_Doc.DTOs;

import com.example.archivage_Doc.Enums.DocumentPermission;
import com.example.archivage_Doc.Enums.RequestStatus;
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
public class DocumentAccessRequestDTO {
    private Long id;
    private DocumentDTO document;
    private UserDTO requester;
    private Set<DocumentPermission> requestedPermissions;
    private String justification;
    private LocalDateTime expirationRequested;
    private RequestStatus status;
    private UserDTO reviewedBy;
    private LocalDateTime reviewedAt;
    private String reviewComments;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
} 