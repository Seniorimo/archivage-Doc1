package com.example.archivage_Doc.Repositories;

import com.example.archivage_Doc.Entities.DocumentAccess;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DocumentAccessRepository extends JpaRepository<DocumentAccess, Long> {
    
    /**
     * Trouver tous les accès pour un document
     */
    List<DocumentAccess> findByDocumentId(Long documentId);
    
    /**
     * Trouver tous les accès pour un utilisateur
     */
    List<DocumentAccess> findByUserId(Long userId);
    
    /**
     * Trouver tous les accès pour un document et un utilisateur
     */
    Optional<DocumentAccess> findByDocumentIdAndUserId(Long documentId, Long userId);
    
    /**
     * Trouver tous les accès accordés par un utilisateur
     */
    List<DocumentAccess> findByGrantedBy(Long grantedBy);
    
    /**
     * Vérifier si un utilisateur a un accès avec une permission spécifique à un document
     */
    @Query("SELECT COUNT(da) > 0 FROM DocumentAccess da " +
           "WHERE da.document.id = :documentId " +
           "AND da.user.id = :userId " +
           "AND :permission MEMBER OF da.permissions " +
           "AND (da.expiresAt IS NULL OR da.expiresAt > CURRENT_TIMESTAMP)")
    boolean hasUserPermission(
            @Param("documentId") Long documentId, 
            @Param("userId") Long userId, 
            @Param("permission") String permission);
} 