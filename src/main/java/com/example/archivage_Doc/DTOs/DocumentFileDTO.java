package com.example.archivage_Doc.DTOs;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.core.io.Resource;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DocumentFileDTO {
    private String filename;
    private String mimeType;
    private Long size;
    private Resource resource;
} 