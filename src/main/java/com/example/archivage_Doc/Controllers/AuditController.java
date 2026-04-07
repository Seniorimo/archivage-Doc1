package com.example.archivage_Doc.Controllers;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.archivage_Doc.Entities.AuditLog;
import com.example.archivage_Doc.Enums.AuditAction;
import com.example.archivage_Doc.Services.AuditService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Contrôleur pour la gestion des logs d'audit
 * Accès restreint aux administrateurs
 */
@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Audit", description = "API pour la gestion des logs d'audit de sécurité")
public class AuditController {
    
    private final AuditService auditService;
    
    /**
     * Recherche des logs d'audit avec des filtres
     */
    @GetMapping("/logs")
    @PreAuthorize("hasAuthority('ADMIN_CREATE')")
    @Operation(summary = "Rechercher des logs d'audit avec filtres")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Logs d'audit récupérés avec succès"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    public ResponseEntity<Map<String, Object>> searchAuditLogs(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) AuditAction action,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortField,
            @RequestParam(defaultValue = "desc") String sortOrder) {
        
        log.info("Recherche de logs d'audit - Filtres: username={}, action={}, resourceType={}, resourceId={}, période={} à {}, status={}, page={}, size={}",
                username, action, resourceType, resourceId, startDate, endDate, status, page, size);
        
        // Préparer la pagination et le tri
        Sort sort = "asc".equalsIgnoreCase(sortOrder) ? 
                Sort.by(sortField).ascending() : 
                Sort.by(sortField).descending();
        
        PageRequest pageRequest = PageRequest.of(page, size, sort);
        
        // Effectuer la recherche
        Page<AuditLog> logs = auditService.searchAuditLogs(
                username, action, resourceType, resourceId, startDate, endDate, status, pageRequest);
        
        // Préparer la réponse
        Map<String, Object> response = new HashMap<>();
        response.put("logs", logs.getContent());
        response.put("currentPage", logs.getNumber());
        response.put("totalItems", logs.getTotalElements());
        response.put("totalPages", logs.getTotalPages());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Obtenir un résumé des activités récentes sur le système
     */
    @GetMapping("/summary")
    @PreAuthorize("hasAuthority('ADMIN_CREATE') or hasAuthority('USER_MANAGE')")
    @Operation(summary = "Obtenir un résumé des activités récentes")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Résumé récupéré avec succès"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    public ResponseEntity<Map<String, Object>> getActivitySummary() {
        // Date de début pour les statistiques (dernières 24h)
        LocalDateTime yesterday = LocalDateTime.now().minusDays(1);
        
        // Créer une requête paginée pour obtenir les derniers logs
        PageRequest pageRequest = PageRequest.of(0, 10, Sort.by("createdAt").descending());
        
        // Récupérer les dernières activités
        Page<AuditLog> recentLogs = auditService.searchAuditLogs(
                null, null, null, null, yesterday, null, null, pageRequest);
        
        Map<String, Object> summary = new HashMap<>();
        summary.put("recentActivities", recentLogs.getContent());
        
        // Ajouter d'autres statistiques pertinentes si nécessaire
        
        return ResponseEntity.ok(summary);
    }
} 