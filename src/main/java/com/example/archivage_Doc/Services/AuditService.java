package com.example.archivage_Doc.Services;

import java.time.LocalDateTime;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.example.archivage_Doc.Entities.AuditLog;
import com.example.archivage_Doc.Enums.AuditAction;
import com.example.archivage_Doc.Repositories.AuditLogRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service pour gérer les logs d'audit de sécurité
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuditService {
    
    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper;
    
    /**
     * Enregistre une action dans les logs d'audit
     * 
     * @param action Type d'action réalisée
     * @param username Nom d'utilisateur qui a effectué l'action
     * @param resourceType Type de ressource concernée (document, utilisateur, etc.)
     * @param resourceId Identifiant de la ressource concernée
     * @param description Description détaillée de l'action
     * @param status Statut de l'action (succès, échec)
     * @param additionalData Données supplémentaires (objet sérialisé en JSON)
     * @return L'entrée de log créée
     */
    public AuditLog logAction(
            AuditAction action,
            String username,
            String resourceType,
            String resourceId,
            String description,
            String status,
            Object additionalData) {
        
        try {
            AuditLog.AuditLogBuilder builder = AuditLog.builder()
                    .action(action)
                    .username(username)
                    .resourceType(resourceType)
                    .resourceId(resourceId)
                    .description(description)
                    .status(status);
            
            // Récupérer les informations de la requête HTTP si disponible
            try {
                ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
                if (attrs != null) {
                    HttpServletRequest request = attrs.getRequest();
                    builder.ipAddress(getClientIp(request))
                           .userAgent(request.getHeader("User-Agent"))
                           .sessionId(request.getSession(false) != null ? request.getSession().getId() : null);
                }
            } catch (Exception e) {
                log.warn("Impossible de récupérer les informations de la requête: {}", e.getMessage());
            }
            
            // Sérialiser les données supplémentaires en JSON
            if (additionalData != null) {
                try {
                    builder.additionalData(objectMapper.writeValueAsString(additionalData));
                } catch (Exception e) {
                    log.warn("Impossible de sérialiser les données additionnelles: {}", e.getMessage());
                }
            }
            
            // Créer et sauvegarder le log
            AuditLog auditLog = builder.build();
            auditLogRepository.save(auditLog);
            
            // Logger en plus dans le système de log standard
            log.info("AUDIT: {} - User: {} - Resource: {}:{} - Status: {} - Description: {}", 
                    action, username, resourceType, resourceId, status, description);
            
            return auditLog;
        } catch (Exception e) {
            log.error("Erreur lors de l'enregistrement de l'audit: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Version simplifiée pour enregistrer une action de base
     */
    public AuditLog logAction(AuditAction action, String username, String description, String status) {
        try {
            return logAction(action, username, null, null, description, status, null);
        } catch (Exception e) {
            // Logger l'erreur mais ne pas la propager
            log.error("Erreur lors de l'enregistrement de l'audit: {}. L'opération continue.", e.getMessage());
            // Toujours logger en console même si la sauvegarde en base échoue
            log.info("AUDIT FALLBACK: {} - User: {} - Status: {} - Description: {}", 
                    action, username, status, description);
            return null;
        }
    }
    
    /**
     * Enregistre une action liée à un document
     */
    public AuditLog logDocumentAction(AuditAction action, String username, Long documentId, String description, String status) {
        try {
            return logAction(action, username, "DOCUMENT", documentId.toString(), description, status, null);
        } catch (Exception e) {
            // Logger l'erreur mais ne pas la propager pour éviter que les échecs d'audit n'impactent les opérations principales
            log.error("Erreur lors de l'enregistrement de l'audit pour le document {}: {}. L'opération continue.", 
                    documentId, e.getMessage());
            // Toujours logger en console même si la sauvegarde en base échoue
            log.info("AUDIT FALLBACK: {} - User: {} - Document: {} - Status: {} - Description: {}", 
                    action, username, documentId, status, description);
            return null;
        }
    }
    
    /**
     * Enregistre une action liée à un utilisateur
     */
    public AuditLog logUserAction(AuditAction action, String username, Long targetUserId, String description, String status) {
        try {
            return logAction(action, username, "USER", targetUserId.toString(), description, status, null);
        } catch (Exception e) {
            // Logger l'erreur mais ne pas la propager
            log.error("Erreur lors de l'enregistrement de l'audit pour l'utilisateur {}: {}. L'opération continue.", 
                    targetUserId, e.getMessage());
            // Toujours logger en console même si la sauvegarde en base échoue
            log.info("AUDIT FALLBACK: {} - User: {} - Target User: {} - Status: {} - Description: {}", 
                    action, username, targetUserId, status, description);
            return null;
        }
    }
    
    /**
     * Enregistre une tentative d'authentification
     */
    public AuditLog logAuthAction(AuditAction action, String username, String description, String status) {
        try {
            return logAction(action, username, "AUTH", null, description, status, null);
        } catch (Exception e) {
            // Logger l'erreur mais ne pas la propager
            log.error("Erreur lors de l'enregistrement de l'audit d'authentification: {}. L'opération continue.", e.getMessage());
            // Toujours logger en console même si la sauvegarde en base échoue
            log.info("AUDIT FALLBACK: {} - User: {} - Status: {} - Description: {}", 
                    action, username, status, description);
            return null;
        }
    }
    
    /**
     * Recherche les logs d'audit avec des filtres
     */
    public Page<AuditLog> searchAuditLogs(
            String username,
            AuditAction action,
            String resourceType,
            String resourceId,
            LocalDateTime startDate,
            LocalDateTime endDate,
            String status,
            Pageable pageable) {
        
        return auditLogRepository.searchAuditLogs(
                username, action, resourceType, resourceId, startDate, endDate, status, pageable);
    }
    
    /**
     * Récupère l'adresse IP réelle du client
     */
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_CLIENT_IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        
        // Si l'IP contient plusieurs adresses (chaîne de proxies), prendre la première
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        
        return ip;
    }
} 