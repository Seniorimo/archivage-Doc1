package com.example.archivage_Doc.Repositories;

import com.example.archivage_Doc.Entities.DocumentVersion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DocumentVersionRepository extends JpaRepository<DocumentVersion, Long> {
    
    /**
     * Trouver toutes les versions d'un document, triées par numéro de version décroissant
     */
    List<DocumentVersion> findByDocumentIdOrderByVersionNumberDesc(Long documentId);
    
    /**
     * Trouver une version spécifique d'un document
     */
    Optional<DocumentVersion> findByDocumentIdAndVersionNumber(Long documentId, Integer versionNumber);
    
    /**
     * Trouver la dernière version d'un document
     */
    @Query("SELECT dv FROM DocumentVersion dv " +
           "WHERE dv.document.id = :documentId " +
           "ORDER BY dv.versionNumber DESC")
    List<DocumentVersion> findLatestByDocumentId(@Param("documentId") Long documentId);
    
    /**
     * Compter le nombre de versions d'un document
     */
    long countByDocumentId(Long documentId);
} 