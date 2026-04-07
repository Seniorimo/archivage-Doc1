package com.example.archivage_Doc.Repositories;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.archivage_Doc.Entities.AuditLog;
import com.example.archivage_Doc.Enums.AuditAction;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    
    // Recherche paginée des logs par action
    Page<AuditLog> findByAction(AuditAction action, Pageable pageable);
    
    // Recherche paginée des logs par utilisateur
    Page<AuditLog> findByUsername(String username, Pageable pageable);
    
    // Recherche paginée des logs par type de ressource
    Page<AuditLog> findByResourceType(String resourceType, Pageable pageable);
    
    // Recherche paginée des logs par ID de ressource
    Page<AuditLog> findByResourceId(String resourceId, Pageable pageable);
    
    // Recherche paginée des logs par période (entre deux dates)
    Page<AuditLog> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate, Pageable pageable);
    
    // Recherche paginée des logs par IP
    Page<AuditLog> findByIpAddress(String ipAddress, Pageable pageable);
    
    // Recherche paginée des logs avec filtres combinés (utilisateur, action, période)
    @Query("SELECT a FROM AuditLog a WHERE " +
            "(:username IS NULL OR a.username = :username) AND " +
            "(:action IS NULL OR a.action = :action) AND " +
            "(:resourceType IS NULL OR a.resourceType = :resourceType) AND " +
            "(:resourceId IS NULL OR a.resourceId = :resourceId) AND " +
            "(:startDate IS NULL OR a.createdAt >= :startDate) AND " +
            "(:endDate IS NULL OR a.createdAt <= :endDate) AND " +
            "(:status IS NULL OR a.status = :status)")
    Page<AuditLog> searchAuditLogs(
            @Param("username") String username,
            @Param("action") AuditAction action,
            @Param("resourceType") String resourceType,
            @Param("resourceId") String resourceId,
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate,
            @Param("status") String status,
            Pageable pageable);
    
    // Compte les événements d'échec d'authentification pour un utilisateur dans une période donnée
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE " +
            "a.username = :username AND " +
            "a.action = com.example.archivage_Doc.Enums.AuditAction.LOGIN_FAILURE AND " +
            "a.createdAt >= :since")
    long countLoginFailuresSince(@Param("username") String username, @Param("since") LocalDateTime since);
} 