package com.example.archivage_Doc.Controllers;

import java.util.List;
import java.util.Set;

import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.example.archivage_Doc.DTOs.AccessRequestDTO;
import com.example.archivage_Doc.DTOs.AccessRequestDecisionDTO;
import com.example.archivage_Doc.DTOs.CommentDTO;
import com.example.archivage_Doc.DTOs.DocumentAccessDTO;
import com.example.archivage_Doc.DTOs.DocumentAccessRequestDTO;
import com.example.archivage_Doc.DTOs.DocumentCommentDTO;
import com.example.archivage_Doc.DTOs.DocumentDTO;
import com.example.archivage_Doc.DTOs.DocumentFileDTO;
import com.example.archivage_Doc.DTOs.DocumentShareDTO;
import com.example.archivage_Doc.DTOs.DocumentUpdateDTO;
import com.example.archivage_Doc.DTOs.DocumentVersionDTO;
import com.example.archivage_Doc.Enums.AuditAction;
import com.example.archivage_Doc.Enums.DocumentStatus;
import com.example.archivage_Doc.Enums.RequestStatus;
import com.example.archivage_Doc.Services.AuditService;
import com.example.archivage_Doc.Services.DocumentService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/documents")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Documents", description = "API pour la gestion des documents")
public class DocumentController {
    private final DocumentService documentService;
    private final AuditService auditService;

    /**
     * Récupérer tous les documents visibles par l'utilisateur
     */
    @GetMapping
    @Operation(summary = "Récupérer tous les documents accessibles à l'utilisateur")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Liste des documents récupérée avec succès"),
        @ApiResponse(responseCode = "403", description = "Non autorisé")
    })
    public ResponseEntity<List<DocumentDTO>> getAllDocuments(
            @RequestParam(required = false) String search,
            @RequestParam(required = false) DocumentStatus status,
            @RequestParam(required = false) Set<Long> tags,
            @RequestParam(required = false) String department) {
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        List<DocumentDTO> documents = documentService.getAllAccessibleDocuments(
                username, search, status, tags, department);
        
        return ResponseEntity.ok(documents);
    }

    /**
     * Récupérer un document par son ID
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('DOCUMENT_READ')")
    @Operation(summary = "Obtenir un document par son ID")
    public ResponseEntity<DocumentDTO> getDocument(
            @PathVariable Long id,
            Authentication authentication) {
        
        String username = authentication.getName();
        DocumentDTO document = documentService.getDocumentById(id, username);
        
        // Audit de la consultation du document
        auditService.logDocumentAction(
            AuditAction.DOCUMENT_VIEW,
            username,
            id,
            "Consultation du document: " + document.getTitle(),
            "SUCCÈS"
        );
        
        return ResponseEntity.ok(document);
    }

    /**
     * Créer un nouveau document
     */
    @PostMapping
    @PreAuthorize("hasAuthority('DOCUMENT_WRITE')")
    @Operation(summary = "Créer un nouveau document")
    public ResponseEntity<DocumentDTO> createDocument(
            @RequestParam("file") MultipartFile file,
            @RequestParam("title") String title,
            @RequestParam("description") String description,
            @RequestParam(value = "departmentId", required = false) Long departmentId,
            @RequestParam(value = "tags", required = false) Set<Long> tags,
            @RequestParam(value = "isPublic", required = false) Boolean isPublic,
            Authentication authentication) {
        
        String username = authentication.getName();
        
        DocumentDTO documentDTO = DocumentDTO.builder()
                .title(title)
                .description(description)
                .isPublic(isPublic)
                .build();
        
        DocumentDTO createdDoc = documentService.createDocument(documentDTO, file, username, departmentId, tags);
        
        // Audit de la création du document
        auditService.logDocumentAction(
            AuditAction.DOCUMENT_CREATE,
            username,
            createdDoc.getId(),
            "Création du document: " + title,
            "SUCCÈS"
        );
        
        return ResponseEntity.ok(createdDoc);
    }

    /**
     * Mettre à jour un document existant
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('DOCUMENT_WRITE')")
    @Operation(summary = "Mettre à jour un document")
    public ResponseEntity<DocumentDTO> updateDocument(
            @PathVariable Long id,
            @RequestBody DocumentUpdateDTO updateDTO,
            Authentication authentication) {
        
        String username = authentication.getName();
        DocumentDTO updatedDoc = documentService.updateDocument(id, updateDTO, username);
        
        // Audit de la modification du document
        auditService.logDocumentAction(
            AuditAction.DOCUMENT_UPDATE,
            username,
            id,
            "Modification du document: " + updatedDoc.getTitle(),
            "SUCCÈS"
        );
        
        return ResponseEntity.ok(updatedDoc);
    }

    /**
     * Télécharger un document
     */
    @GetMapping("/{id}/download")
    @PreAuthorize("hasAuthority('DOCUMENT_READ')")
    @Operation(summary = "Télécharger un document")
    public ResponseEntity<Resource> downloadDocument(
            @PathVariable Long id,
            Authentication authentication) {
        
        String username = authentication.getName();
        DocumentFileDTO fileDTO = documentService.getDocumentFile(id, username);
        
        // Audit du téléchargement du document
        auditService.logDocumentAction(
            AuditAction.DOCUMENT_DOWNLOAD,
            username,
            id,
            "Téléchargement du document: " + fileDTO.getFilename(),
            "SUCCÈS"
        );
        
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileDTO.getFilename() + "\"");
        
        return ResponseEntity.ok()
                .headers(headers)
                .contentLength(fileDTO.getSize())
                .contentType(MediaType.parseMediaType(fileDTO.getMimeType()))
                .body(fileDTO.getResource());
    }

    /**
     * Ajouter une nouvelle version d'un document
     */
    @PostMapping("/{id}/versions")
    @Operation(summary = "Ajouter une nouvelle version à un document")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Version ajoutée avec succès"),
        @ApiResponse(responseCode = "400", description = "Données invalides"),
        @ApiResponse(responseCode = "403", description = "Non autorisé"),
        @ApiResponse(responseCode = "404", description = "Document non trouvé")
    })
    public ResponseEntity<DocumentVersionDTO> addVersion(
            @PathVariable Long id,
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "changeDescription", required = false) String changeDescription) {
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        DocumentVersionDTO versionDTO = documentService.addDocumentVersion(
                id, file, changeDescription, username);
        
        return ResponseEntity.status(201).body(versionDTO);
    }

    /**
     * Archiver un document
     */
    @PostMapping("/{id}/archive")
    @PreAuthorize("hasAuthority('DOCUMENT_ARCHIVE')")
    @Operation(summary = "Archiver un document")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Document archivé avec succès"),
        @ApiResponse(responseCode = "403", description = "Non autorisé"),
        @ApiResponse(responseCode = "404", description = "Document non trouvé")
    })
    public ResponseEntity<DocumentDTO> archiveDocument(@PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        DocumentDTO archivedDocument = documentService.archiveDocument(id, username);
        
        return ResponseEntity.ok(archivedDocument);
    }

    /**
     * Supprimer un document
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('DOCUMENT_DELETE')")
    @Operation(summary = "Supprimer un document")
    public ResponseEntity<Void> deleteDocument(
            @PathVariable Long id,
            Authentication authentication) {
        
        String username = authentication.getName();
        documentService.deleteDocument(id, username);
        
        // Audit de la suppression du document
        auditService.logDocumentAction(
            AuditAction.DOCUMENT_DELETE,
            username,
            id,
            "Suppression du document",
            "SUCCÈS"
        );
        
        return ResponseEntity.noContent().build();
    }

    /**
     * Partager un document avec un autre utilisateur
     */
    @PostMapping("/{id}/share")
    @Operation(summary = "Partager un document avec un autre utilisateur")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Document partagé avec succès"),
        @ApiResponse(responseCode = "400", description = "Données invalides"),
        @ApiResponse(responseCode = "403", description = "Non autorisé"),
        @ApiResponse(responseCode = "404", description = "Document ou utilisateur non trouvé")
    })
    public ResponseEntity<DocumentAccessDTO> shareDocument(
            @PathVariable Long id,
            @RequestBody DocumentShareDTO shareDTO) {
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        DocumentAccessDTO accessDTO = documentService.shareDocument(
                id, shareDTO.getUserId(), shareDTO.getPermissions(), shareDTO.getExpiresAt(), username);
        
        return ResponseEntity.ok(accessDTO);
    }

    /**
     * Demander l'accès à un document
     */
    @PostMapping("/{id}/request-access")
    @Operation(summary = "Demander l'accès à un document")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Demande d'accès soumise avec succès"),
        @ApiResponse(responseCode = "400", description = "Données invalides"),
        @ApiResponse(responseCode = "403", description = "Non autorisé"),
        @ApiResponse(responseCode = "404", description = "Document non trouvé")
    })
    public ResponseEntity<DocumentAccessRequestDTO> requestAccess(
            @PathVariable Long id,
            @RequestBody AccessRequestDTO requestDTO) {
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        DocumentAccessRequestDTO accessRequest = documentService.requestDocumentAccess(
                id, requestDTO.getPermissions(), requestDTO.getJustification(), 
                requestDTO.getExpirationRequested(), username);
        
        return ResponseEntity.status(201).body(accessRequest);
    }

    /**
     * Récupérer toutes les demandes d'accès (pour les administrateurs et managers)
     */
    @GetMapping("/access-requests")
    @PreAuthorize("hasAuthority('USER_MANAGE')")
    @Operation(summary = "Récupérer toutes les demandes d'accès")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Demandes d'accès récupérées avec succès"),
        @ApiResponse(responseCode = "403", description = "Non autorisé")
    })
    public ResponseEntity<List<DocumentAccessRequestDTO>> getAllAccessRequests(
            @RequestParam(required = false) RequestStatus status,
            @RequestParam(required = false) String department) {
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        List<DocumentAccessRequestDTO> accessRequests = 
                documentService.getAllAccessRequests(username, status, department);
        
        return ResponseEntity.ok(accessRequests);
    }

    /**
     * Traiter une demande d'accès (approuver/rejeter)
     */
    @PutMapping("/access-requests/{requestId}")
    @PreAuthorize("hasAuthority('USER_MANAGE')")
    @Operation(summary = "Traiter une demande d'accès")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Demande d'accès traitée avec succès"),
        @ApiResponse(responseCode = "400", description = "Données invalides"),
        @ApiResponse(responseCode = "403", description = "Non autorisé"),
        @ApiResponse(responseCode = "404", description = "Demande d'accès non trouvée")
    })
    public ResponseEntity<DocumentAccessRequestDTO> processAccessRequest(
            @PathVariable Long requestId,
            @RequestBody AccessRequestDecisionDTO decisionDTO) {
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        DocumentAccessRequestDTO processedRequest = documentService.processAccessRequest(
                requestId, decisionDTO.getStatus(), decisionDTO.getComments(), username);
        
        return ResponseEntity.ok(processedRequest);
    }

    /**
     * Ajouter un commentaire à un document
     */
    @PostMapping("/{id}/comments")
    @Operation(summary = "Ajouter un commentaire à un document")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Commentaire ajouté avec succès"),
        @ApiResponse(responseCode = "400", description = "Données invalides"),
        @ApiResponse(responseCode = "403", description = "Non autorisé"),
        @ApiResponse(responseCode = "404", description = "Document non trouvé")
    })
    public ResponseEntity<DocumentCommentDTO> addComment(
            @PathVariable Long id,
            @RequestBody CommentDTO commentDTO) {
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        DocumentCommentDTO createdComment = documentService.addComment(
                id, commentDTO.getContent(), commentDTO.getParentCommentId(), username);
        
        return ResponseEntity.status(201).body(createdComment);
    }

    /**
     * Récupérer les commentaires d'un document
     */
    @GetMapping("/{id}/comments")
    @Operation(summary = "Récupérer les commentaires d'un document")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Commentaires récupérés avec succès"),
        @ApiResponse(responseCode = "403", description = "Non autorisé"),
        @ApiResponse(responseCode = "404", description = "Document non trouvé")
    })
    public ResponseEntity<List<DocumentCommentDTO>> getComments(@PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        List<DocumentCommentDTO> comments = documentService.getDocumentComments(id, username);
        
        return ResponseEntity.ok(comments);
    }
} 