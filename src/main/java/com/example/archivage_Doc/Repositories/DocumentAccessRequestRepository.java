package com.example.archivage_Doc.Repositories;

import com.example.archivage_Doc.Entities.DocumentAccessRequest;
import com.example.archivage_Doc.Entities.User;
import com.example.archivage_Doc.Enums.RequestStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DocumentAccessRequestRepository extends JpaRepository<DocumentAccessRequest, Long> {
    
    /**
     * Trouver toutes les demandes d'accès à un document
     */
    List<DocumentAccessRequest> findByDocumentId(Long documentId);
    
    /**
     * Trouver toutes les demandes d'accès faites par un utilisateur
     */
    List<DocumentAccessRequest> findByRequesterId(Long requesterId);
    
    /**
     * Trouver toutes les demandes d'accès avec un statut spécifique
     */
    List<DocumentAccessRequest> findByStatus(RequestStatus status);
    
    /**
     * Trouver toutes les demandes d'accès examinées par un utilisateur
     */
    List<DocumentAccessRequest> findByReviewedBy(User reviewedBy);
    
    /**
     * Trouver toutes les demandes d'accès pour un département
     */
    @Query("SELECT dar FROM DocumentAccessRequest dar " +
           "WHERE dar.document.department.id = :departmentId")
    List<DocumentAccessRequest> findByDepartmentId(@Param("departmentId") Long departmentId);
    
    /**
     * Trouver toutes les demandes d'accès avec un statut spécifique pour un département
     */
    @Query("SELECT dar FROM DocumentAccessRequest dar " +
           "WHERE dar.status = :status " +
           "AND dar.document.department.id = :departmentId")
    List<DocumentAccessRequest> findByStatusAndDepartmentId(
            @Param("status") RequestStatus status, 
            @Param("departmentId") Long departmentId);
} 