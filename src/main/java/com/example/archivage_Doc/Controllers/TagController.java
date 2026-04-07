package com.example.archivage_Doc.Controllers;

import com.example.archivage_Doc.DTOs.TagDTO;
import com.example.archivage_Doc.Entities.Tag;
import com.example.archivage_Doc.Repositories.TagRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/tags")
@RequiredArgsConstructor
@Slf4j
public class TagController {

    private final TagRepository tagRepository;

    @GetMapping
    @Operation(summary = "Récupérer tous les tags")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Liste des tags récupérée avec succès")
    })
    public ResponseEntity<List<TagDTO>> getAllTags() {
        log.info("Récupération de tous les tags");
        
        List<TagDTO> tags = tagRepository.findAll().stream()
                .map(tag -> mapToDTO(tag))
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(tags);
    }
    
    private TagDTO mapToDTO(Tag tag) {
        return TagDTO.builder()
                .id(tag.getId())
                .name(tag.getName())
                .description(tag.getDescription())
                .build();
    }
} 