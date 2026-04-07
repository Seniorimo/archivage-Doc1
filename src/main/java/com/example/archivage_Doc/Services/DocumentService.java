package com.example.archivage_Doc.Services;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

import org.springframework.web.multipart.MultipartFile;

import com.example.archivage_Doc.DTOs.DocumentAccessDTO;
import com.example.archivage_Doc.DTOs.DocumentAccessRequestDTO;
import com.example.archivage_Doc.DTOs.DocumentCommentDTO;
import com.example.archivage_Doc.DTOs.DocumentDTO;
import com.example.archivage_Doc.DTOs.DocumentFileDTO;
import com.example.archivage_Doc.DTOs.DocumentUpdateDTO;
import com.example.archivage_Doc.DTOs.DocumentVersionDTO;
import com.example.archivage_Doc.Enums.DocumentPermission;
import com.example.archivage_Doc.Enums.DocumentStatus;
import com.example.archivage_Doc.Enums.RequestStatus;

/**
 * Service pour la gestion des documents
 */
public interface DocumentService {

    /**
     * Récupérer tous les documents accessibles à un utilisateur
     */
    List<DocumentDTO> getAllAccessibleDocuments(String username, String search, 
            DocumentStatus status, Set<Long> tags, String department);
    
    /**
     * Récupérer un document par son ID
     */
    DocumentDTO getDocumentById(Long id, String username);
    
    /**
     * Créer un nouveau document
     */
    DocumentDTO createDocument(DocumentDTO documentDTO, MultipartFile file, 
            String username, Long departmentId, Set<Long> tags);
    
    /**
     * Mettre à jour un document existant
     */
    DocumentDTO updateDocument(Long id, DocumentUpdateDTO updateDTO, String username);
    
    /**
     * Récupérer le fichier d'un document
     */
    DocumentFileDTO getDocumentFile(Long id, String username);
    
    /**
     * Ajouter une nouvelle version à un document
     */
    DocumentVersionDTO addDocumentVersion(Long id, MultipartFile file, 
            String changeDescription, String username);
    
    /**
     * Archiver un document
     */
    DocumentDTO archiveDocument(Long id, String username);
    
    /**
     * Supprimer un document
     */
    void deleteDocument(Long id, String username);
    
    /**
     * Partager un document avec un autre utilisateur
     */
    DocumentAccessDTO shareDocument(Long documentId, Long userId, 
            Set<DocumentPermission> permissions, LocalDateTime expiresAt, String username);
    
    /**
     * Demander l'accès à un document
     */
    DocumentAccessRequestDTO requestDocumentAccess(Long documentId, 
            Set<DocumentPermission> permissions, String justification, 
            LocalDateTime expirationRequested, String username);
    
    /**
     * Récupérer toutes les demandes d'accès
     */
    List<DocumentAccessRequestDTO> getAllAccessRequests(String username, 
            RequestStatus status, String department);
    
    /**
     * Traiter une demande d'accès (approuver/rejeter)
     */
    DocumentAccessRequestDTO processAccessRequest(Long requestId, 
            RequestStatus status, String comments, String username);
    
    /**
     * Ajouter un commentaire à un document
     */
    DocumentCommentDTO addComment(Long documentId, String content, 
            Long parentCommentId, String username);
    
    /**
     * Récupérer les commentaires d'un document
     */
    List<DocumentCommentDTO> getDocumentComments(Long documentId, String username);
} 