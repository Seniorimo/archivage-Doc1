package com.example.archivage_Doc.Repositories;

import com.example.archivage_Doc.Entities.Document;
import com.example.archivage_Doc.Enums.DocumentStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;

@Repository
public interface DocumentRepository extends JpaRepository<Document, Long> {
    
    /**
     * Trouver tous les documents accessibles à un utilisateur avec filtres optionnels
     */
    @Query(value = "SELECT DISTINCT d FROM Document d " +
            "LEFT JOIN d.documentAccesses da " +
            "LEFT JOIN d.tags t " +
            "WHERE (d.creator.id = :userId OR " +
            "      (d.isPublic = true AND d.department.id = " +
            "       (SELECT u.department.id FROM User u WHERE u.id = :userId)) OR " +
            "      (da.user.id = :userId AND (da.expiresAt IS NULL OR da.expiresAt > CURRENT_TIMESTAMP))) " +
            "AND (d.status <> 'DELETED') " +
            "AND (:search IS NULL OR " +
            "     (LOWER(d.title) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
            "      LOWER(d.description) LIKE LOWER(CONCAT('%', :search, '%')))) " +
            "AND (:status IS NULL OR d.status = :status) " +
            "AND (:tags IS NULL OR t.id IN :tags) " +
            "AND (:department IS NULL OR LOWER(d.department.name) = LOWER(:department))")
    List<Document> findAccessibleDocumentsByUser(
            @Param("userId") Long userId,
            @Param("search") String search,
            @Param("status") DocumentStatus status,
            @Param("tags") Set<Long> tags,
            @Param("department") String department);
    
    /**
     * Trouver tous les documents créés par un utilisateur
     */
    List<Document> findByCreatorId(Long creatorId);
    
    /**
     * Trouver tous les documents dans un département
     */
    List<Document> findByDepartmentId(Long departmentId);
    
    /**
     * Trouver tous les documents contenant des tags spécifiques
     */
    @Query("SELECT d FROM Document d JOIN d.tags t WHERE t.id IN :tagIds")
    List<Document> findByTagsIn(@Param("tagIds") Set<Long> tagIds);
    
    /**
     * Chercher des documents avec un terme de recherche
     */
    @Query("SELECT d FROM Document d WHERE " +
            "LOWER(d.title) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
            "LOWER(d.description) LIKE LOWER(CONCAT('%', :search, '%'))")
    List<Document> searchDocuments(@Param("search") String search);
    
    /**
     * Compter le nombre de documents dans un département
     */
    long countByDepartmentId(Long departmentId);
} 