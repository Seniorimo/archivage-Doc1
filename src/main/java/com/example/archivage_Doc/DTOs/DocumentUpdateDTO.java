package com.example.archivage_Doc.DTOs;

import com.example.archivage_Doc.Enums.DocumentStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DocumentUpdateDTO {
    private String title;
    private String description;
    private Boolean isPublic;
    private DocumentStatus status;
    private Long departmentId;
    private Set<Long> tagsToAdd;
    private Set<Long> tagsToRemove;
} 