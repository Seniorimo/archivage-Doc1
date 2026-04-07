package com.example.archivage_Doc.Repositories;

import com.example.archivage_Doc.Entities.DocumentComment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DocumentCommentRepository extends JpaRepository<DocumentComment, Long> {
    
    /**
     * Trouver tous les commentaires d'un document, triés par date de création décroissante
     */
    List<DocumentComment> findByDocumentIdOrderByCreatedAtDesc(Long documentId);
    
    /**
     * Trouver tous les commentaires racines (sans parent) d'un document, triés par date de création décroissante
     */
    List<DocumentComment> findByDocumentIdAndParentCommentIsNullOrderByCreatedAtDesc(Long documentId);
    
    /**
     * Trouver toutes les réponses à un commentaire, triées par date de création croissante
     */
    List<DocumentComment> findByParentCommentIdOrderByCreatedAtAsc(Long parentCommentId);
    
    /**
     * Trouver tous les commentaires créés par un utilisateur
     */
    List<DocumentComment> findByUserId(Long userId);
    
    /**
     * Compter le nombre de commentaires pour un document
     */
    long countByDocumentId(Long documentId);
    
    /**
     * Compter le nombre de réponses à un commentaire
     */
    long countByParentCommentId(Long parentCommentId);
} 