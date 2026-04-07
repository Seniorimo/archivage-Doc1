package com.example.archivage_Doc.DTOs;

import com.example.archivage_Doc.Enums.DocumentStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DocumentDTO {
    private Long id;
    private String title;
    private String description;
    private String fileName;
    private String mimeType;
    private Long fileSize;
    private Boolean isPublic;
    private DocumentStatus status;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private UserDTO creator;
    private DepartmentDTO department;
    private Set<TagDTO> tags;
    private List<DocumentVersionDTO> versions;
    private Set<DocumentPermissionDTO> userPermissions;
    private Integer currentVersion;
    private Long totalComments;
    private Boolean canEdit;
    private Boolean canDelete;
    private Boolean canArchive;
    private Boolean canShare;
    private Boolean canComment;
    private Boolean canDownload;
} 