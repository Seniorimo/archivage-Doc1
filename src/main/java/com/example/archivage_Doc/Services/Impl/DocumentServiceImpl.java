package com.example.archivage_Doc.Services.Impl;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import com.example.archivage_Doc.DTOs.DepartmentDTO;
import com.example.archivage_Doc.DTOs.DocumentAccessDTO;
import com.example.archivage_Doc.DTOs.DocumentAccessRequestDTO;
import com.example.archivage_Doc.DTOs.DocumentCommentDTO;
import com.example.archivage_Doc.DTOs.DocumentDTO;
import com.example.archivage_Doc.DTOs.DocumentFileDTO;
import com.example.archivage_Doc.DTOs.DocumentUpdateDTO;
import com.example.archivage_Doc.DTOs.DocumentVersionDTO;
import com.example.archivage_Doc.DTOs.TagDTO;
import com.example.archivage_Doc.DTOs.UserDTO;
import com.example.archivage_Doc.Entities.Department;
import com.example.archivage_Doc.Entities.Document;
import com.example.archivage_Doc.Entities.DocumentAccess;
import com.example.archivage_Doc.Entities.DocumentAccessRequest;
import com.example.archivage_Doc.Entities.DocumentComment;
import com.example.archivage_Doc.Entities.DocumentVersion;
import com.example.archivage_Doc.Entities.Tag;
import com.example.archivage_Doc.Entities.User;
import com.example.archivage_Doc.Enums.AuditAction;
import com.example.archivage_Doc.Enums.DocumentPermission;
import com.example.archivage_Doc.Enums.DocumentStatus;
import com.example.archivage_Doc.Enums.RequestStatus;
import com.example.archivage_Doc.Exceptions.AccessDeniedException;
import com.example.archivage_Doc.Exceptions.DocumentNotFoundException;
import com.example.archivage_Doc.Exceptions.FileStorageException;
import com.example.archivage_Doc.Exceptions.UserNotFoundException;
import com.example.archivage_Doc.Repositories.DepartmentRepository;
import com.example.archivage_Doc.Repositories.DocumentAccessRepository;
import com.example.archivage_Doc.Repositories.DocumentAccessRequestRepository;
import com.example.archivage_Doc.Repositories.DocumentCommentRepository;
import com.example.archivage_Doc.Repositories.DocumentRepository;
import com.example.archivage_Doc.Repositories.DocumentVersionRepository;
import com.example.archivage_Doc.Repositories.TagRepository;
import com.example.archivage_Doc.Repositories.UserRepository;
import com.example.archivage_Doc.Services.AuditService;
import com.example.archivage_Doc.Services.DocumentService;
import com.example.archivage_Doc.Services.FileStorageService;
import com.example.archivage_Doc.Services.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class DocumentServiceImpl implements DocumentService {

    private final DocumentRepository documentRepository;
    private final UserRepository userRepository;
    private final DepartmentRepository departmentRepository;
    private final TagRepository tagRepository;
    private final DocumentAccessRepository documentAccessRepository;
    private final DocumentVersionRepository documentVersionRepository;
    private final DocumentAccessRequestRepository documentAccessRequestRepository;
    private final DocumentCommentRepository documentCommentRepository;
    
    private final FileStorageService fileStorageService;
    private final UserService userService;
    private final AuditService auditService;
    
    @Override
    @Transactional(readOnly = true)
    public List<DocumentDTO> getAllAccessibleDocuments(String username, String search, 
            DocumentStatus status, Set<Long> tags, String department) {
        
        User user = getUserByUsername(username);
        
        // Récupérer tous les documents accessibles à l'utilisateur
        List<Document> documents = documentRepository.findAccessibleDocumentsByUser(
                user.getId(), StringUtils.hasText(search) ? search : null, 
                status, tags, department);
        
        return documents.stream()
                .map(doc -> convertToDocumentDTO(doc, user))
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public DocumentDTO getDocumentById(Long id, String username) {
        Document document = getDocumentById(id);
        User user = getUserByUsername(username);
        
        if (!document.hasUserPermission(user, DocumentPermission.READ)) {
            auditService.logDocumentAction(
                AuditAction.ACCESS_DENY,
                username,
                id,
                "Tentative d'accès non autorisé au document: " + document.getTitle(),
                "ÉCHEC"
            );
            throw new AccessDeniedException("Vous n'avez pas l'autorisation de consulter ce document");
        }
        
        // Audit de la consultation du document
        auditService.logDocumentAction(
            AuditAction.DOCUMENT_VIEW,
            username,
            id,
            "Consultation du document: " + document.getTitle(),
            "SUCCÈS"
        );
        
        return convertToDocumentDTO(document, user);
    }

    @Override
    @Transactional
    public DocumentDTO createDocument(DocumentDTO documentDTO, MultipartFile file, 
            String username, Long departmentId, Set<Long> tagIds) {
        
        User creator = getUserByUsername(username);
        
        // Déterminer le département en fonction du rôle de l'utilisateur
        Department department = null;
        boolean hasWritePermission = userService.hasPermission(username, "DOCUMENT_WRITE");
        
        // Si l'utilisateur n'a pas la permission d'écriture (c'est un simple employé),
        // utiliser son propre département quel que soit le départementId fourni
        if (!hasWritePermission) {
            // Récupérer le département de l'utilisateur
            department = creator.getDepartment();
            if (department == null) {
                throw new AccessDeniedException("Vous n'avez pas de département assigné et ne pouvez donc pas créer de document");
            }
            
            log.info("Employé {} forcé à utiliser son propre département {}", 
                    username, department.getName());
        } 
        // Sinon, utiliser le département fourni si présent
        else if (departmentId != null) {
            department = departmentRepository.findById(departmentId)
                    .orElseThrow(() -> new RuntimeException("Département non trouvé"));
        }
        
        // Stocker le fichier
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());
        String filePath;
        try {
            filePath = fileStorageService.storeFile(file);
        } catch (IOException e) {
            throw new FileStorageException("Impossible de stocker le fichier", e);
        }
        
        // Créer le document
        Document document = Document.builder()
                .title(documentDTO.getTitle())
                .description(documentDTO.getDescription())
                .filePath(filePath)
                .fileSize(file.getSize())
                .mimeType(file.getContentType())
                .status(DocumentStatus.ACTIVE)
                .creator(creator)
                .department(department)
                .isPublic(documentDTO.getIsPublic() != null ? documentDTO.getIsPublic() : false)
                .build();
        
        // Ajouter les tags si présents
        if (tagIds != null && !tagIds.isEmpty()) {
            List<Tag> tags = tagRepository.findAllById(tagIds);
            tags.forEach(document::addTag);
        }
        
        Document savedDocument = documentRepository.save(document);
        
        // Audit de la création du document
        auditService.logDocumentAction(
            AuditAction.DOCUMENT_CREATE,
            username,
            savedDocument.getId(),
            "Création du document: " + documentDTO.getTitle(),
            "SUCCÈS"
        );
        
        // Créer la première version
        DocumentVersion version = DocumentVersion.builder()
                .document(savedDocument)
                .versionNumber(1)
                .filePath(filePath)
                .fileSize(file.getSize())
                .changeDescription("Version initiale")
                .createdBy(creator)
                .build();
        
        savedDocument.addVersion(version);
        documentVersionRepository.save(version);
        
        return convertToDocumentDTO(savedDocument, creator);
    }

    @Override
    @Transactional
    public DocumentDTO updateDocument(Long id, DocumentUpdateDTO updateDTO, String username) {
        Document document = getDocumentById(id);
        User user = getUserByUsername(username);
        
        if (!document.hasUserPermission(user, DocumentPermission.WRITE)) {
            throw new AccessDeniedException("Vous n'avez pas l'autorisation de modifier ce document");
        }
        
        // Mettre à jour les propriétés du document
        if (StringUtils.hasText(updateDTO.getTitle())) {
            document.setTitle(updateDTO.getTitle());
        }
        
        if (updateDTO.getDescription() != null) {
            document.setDescription(updateDTO.getDescription());
        }
        
        if (updateDTO.getIsPublic() != null) {
            document.setIsPublic(updateDTO.getIsPublic());
        }
        
        if (updateDTO.getStatus() != null) {
            document.setStatus(updateDTO.getStatus());
            
            if (updateDTO.getStatus() == DocumentStatus.ARCHIVED) {
                document.setArchivedAt(LocalDateTime.now());
            }
        }
        
        if (updateDTO.getDepartmentId() != null) {
            Department department = departmentRepository.findById(updateDTO.getDepartmentId())
                    .orElseThrow(() -> new RuntimeException("Département non trouvé"));
            document.setDepartment(department);
        }
        
        // Gérer les tags
        if (updateDTO.getTagsToAdd() != null && !updateDTO.getTagsToAdd().isEmpty()) {
            List<Tag> tagsToAdd = tagRepository.findAllById(updateDTO.getTagsToAdd());
            tagsToAdd.forEach(document::addTag);
        }
        
        if (updateDTO.getTagsToRemove() != null && !updateDTO.getTagsToRemove().isEmpty()) {
            List<Tag> tagsToRemove = tagRepository.findAllById(updateDTO.getTagsToRemove());
            tagsToRemove.forEach(document::removeTag);
        }
        
        Document updatedDocument = documentRepository.save(document);
        
        // Audit de la modification du document
        auditService.logDocumentAction(
            AuditAction.DOCUMENT_UPDATE,
            username,
            id,
            "Modification du document: " + document.getTitle(),
            "SUCCÈS"
        );
        
        return convertToDocumentDTO(updatedDocument, user);
    }

    @Override
    @Transactional(readOnly = true)
    public DocumentFileDTO getDocumentFile(Long id, String username) {
        Document document = getDocumentById(id);
        User user = getUserByUsername(username);
        
        if (!document.hasUserPermission(user, DocumentPermission.DOWNLOAD)) {
            throw new AccessDeniedException("Vous n'avez pas l'autorisation de télécharger ce document");
        }
        
        DocumentVersion currentVersion = document.getCurrentVersion();
        if (currentVersion == null) {
            throw new RuntimeException("Aucune version disponible pour ce document");
        }
        
        try {
            Resource resource = fileStorageService.loadFileAsResource(currentVersion.getFilePath());
            
            return DocumentFileDTO.builder()
                    .filename(StringUtils.getFilename(currentVersion.getFilePath()))
                    .mimeType(document.getMimeType())
                    .size(currentVersion.getFileSize())
                    .resource(resource)
                    .build();
        } catch (IOException e) {
            throw new FileStorageException("Impossible de charger le fichier", e);
        }
    }

    @Override
    @Transactional
    public DocumentVersionDTO addDocumentVersion(Long id, MultipartFile file, 
            String changeDescription, String username) {
        
        Document document = getDocumentById(id);
        User user = getUserByUsername(username);
        
        if (!document.hasUserPermission(user, DocumentPermission.WRITE)) {
            throw new AccessDeniedException("Vous n'avez pas l'autorisation de modifier ce document");
        }
        
        // Stocker le nouveau fichier
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());
        String filePath;
        try {
            filePath = fileStorageService.storeFile(file);
        } catch (IOException e) {
            throw new FileStorageException("Impossible de stocker le fichier", e);
        }
        
        // Déterminer le numéro de version
        int versionNumber = 1;
        DocumentVersion latestVersion = document.getCurrentVersion();
        if (latestVersion != null) {
            versionNumber = latestVersion.getVersionNumber() + 1;
        }
        
        // Créer la nouvelle version
        DocumentVersion version = DocumentVersion.builder()
                .document(document)
                .versionNumber(versionNumber)
                .filePath(filePath)
                .fileSize(file.getSize())
                .changeDescription(changeDescription)
                .createdBy(user)
                .build();
        
        document.addVersion(version);
        
        // Mettre à jour le document
        document.setFilePath(filePath);
        document.setFileSize(file.getSize());
        document.setMimeType(file.getContentType());
        document.setUpdatedAt(LocalDateTime.now());
        
        documentRepository.save(document);
        version = documentVersionRepository.save(version);
        
        return convertToVersionDTO(version, true);
    }

    @Override
    @Transactional
    public DocumentDTO archiveDocument(Long id, String username) {
        Document document = getDocumentById(id);
        User user = getUserByUsername(username);
        
        if (!document.hasUserPermission(user, DocumentPermission.ARCHIVE)) {
            throw new AccessDeniedException("Vous n'avez pas l'autorisation d'archiver ce document");
        }
        
        document.setStatus(DocumentStatus.ARCHIVED);
        document.setArchivedAt(LocalDateTime.now());
        document = documentRepository.save(document);
        
        // Audit de la modification du document
        auditService.logDocumentAction(
            AuditAction.DOCUMENT_UPDATE,
            username,
            id,
            "Modification du document: " + document.getTitle(),
            "SUCCÈS"
        );
        
        return convertToDocumentDTO(document, user);
    }

    @Override
    @Transactional
    public void deleteDocument(Long id, String username) {
        Document document = getDocumentById(id);
        User user = getUserByUsername(username);
        
        if (!document.hasUserPermission(user, DocumentPermission.DELETE)) {
            throw new AccessDeniedException("Vous n'avez pas l'autorisation de supprimer ce document");
        }
        
        document.setStatus(DocumentStatus.DELETED);
        documentRepository.save(document);
        
        // Audit de la suppression du document
        auditService.logDocumentAction(
            AuditAction.DOCUMENT_DELETE,
            username,
            id,
            "Suppression du document: " + document.getTitle(),
            "SUCCÈS"
        );
    }

    @Override
    @Transactional
    public DocumentAccessDTO shareDocument(Long documentId, Long userId, 
            Set<DocumentPermission> permissions, LocalDateTime expiresAt, String username) {
        
        Document document = getDocumentById(documentId);
        User owner = getUserByUsername(username);
        User targetUser = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("Utilisateur non trouvé"));
        
        // Vérifier si l'utilisateur a la permission de partager ce document
        if (!document.hasUserPermission(owner, DocumentPermission.SHARE)) {
            throw new AccessDeniedException("Vous n'avez pas l'autorisation de partager ce document");
        }
        
        // Convertir les permissions de l'enum vers les strings
        Set<String> permissionStrings = permissions.stream()
                .map(DocumentPermission::getValue)
                .collect(Collectors.toSet());
        
        // Ajouter l'accès
        DocumentAccess access = document.addUserAccess(targetUser, permissionStrings, owner, expiresAt);
        access = documentAccessRepository.save(access);
        
        return DocumentAccessDTO.builder()
                .id(access.getId())
                .documentId(document.getId())
                .documentTitle(document.getTitle())
                .user(convertToUserDTO(targetUser))
                .permissions(permissions)
                .grantedAt(access.getGrantedAt())
                .expiresAt(access.getExpiresAt())
                .grantedBy(convertToUserDTO(owner))
                .isActive(access.getExpiresAt() == null || access.getExpiresAt().isAfter(LocalDateTime.now()))
                .build();
    }

    @Override
    @Transactional
    public DocumentAccessRequestDTO requestDocumentAccess(Long documentId, 
            Set<DocumentPermission> permissions, String justification, 
            LocalDateTime expirationRequested, String username) {
        
        Document document = getDocumentById(documentId);
        User requester = getUserByUsername(username);
        
        // Convertir les permissions de l'enum vers les strings
        Set<String> permissionStrings = permissions.stream()
                .map(DocumentPermission::getValue)
                .collect(Collectors.toSet());
        
        // Créer la demande d'accès
        DocumentAccessRequest request = DocumentAccessRequest.builder()
                .document(document)
                .requester(requester)
                .requestedPermissions(permissionStrings)
                .justification(justification)
                .expirationRequested(expirationRequested)
                .status(RequestStatus.PENDING)
                .build();
        
        request = documentAccessRequestRepository.save(request);
        
        return convertToAccessRequestDTO(request);
    }

    @Override
    @Transactional(readOnly = true)
    public List<DocumentAccessRequestDTO> getAllAccessRequests(String username, 
            RequestStatus status, String department) {
        
        User user = getUserByUsername(username);
        
        // Vérifier si l'utilisateur a la permission de gérer les utilisateurs
        if (!userService.hasPermission(username, "USER_MANAGE")) {
            throw new AccessDeniedException("Vous n'avez pas l'autorisation de voir les demandes d'accès");
        }
        
        List<DocumentAccessRequest> requests;
        
        // Si c'est un admin, il peut voir toutes les demandes
        if (userService.isAdmin(username)) {
            requests = status != null 
                ? documentAccessRequestRepository.findByStatus(status)
                : documentAccessRequestRepository.findAll();
        } else {
            // Sinon, seulement les demandes de son département
            Long departmentId = user.getDepartment() != null ? user.getDepartment().getId() : null;
            requests = status != null 
                ? documentAccessRequestRepository.findByStatusAndDepartmentId(status, departmentId)
                : documentAccessRequestRepository.findByDepartmentId(departmentId);
        }
        
        return requests.stream()
                .map(this::convertToAccessRequestDTO)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public DocumentAccessRequestDTO processAccessRequest(Long requestId, 
            RequestStatus status, String comments, String username) {
        
        User reviewer = getUserByUsername(username);
        
        // Vérifier si l'utilisateur a la permission de gérer les utilisateurs
        if (!userService.hasPermission(username, "USER_MANAGE")) {
            throw new AccessDeniedException("Vous n'avez pas l'autorisation de traiter les demandes d'accès");
        }
        
        DocumentAccessRequest request = documentAccessRequestRepository.findById(requestId)
                .orElseThrow(() -> new RuntimeException("Demande d'accès non trouvée"));
        
        // Mettre à jour la demande
        request.setStatus(status);
        request.setReviewComments(comments);
        request.setReviewedBy(reviewer);
        request.setReviewedAt(LocalDateTime.now());
        
        // Si la demande est approuvée, créer l'accès
        if (status == RequestStatus.APPROVED) {
            Document document = request.getDocument();
            User requester = request.getRequester();
            
            DocumentAccess access = document.addUserAccess(
                    requester, 
                    request.getRequestedPermissions(), 
                    reviewer,
                    request.getExpirationRequested());
            
            documentAccessRepository.save(access);
        }
        
        request = documentAccessRequestRepository.save(request);
        
        return convertToAccessRequestDTO(request);
    }

    @Override
    @Transactional
    public DocumentCommentDTO addComment(Long documentId, String content, 
            Long parentCommentId, String username) {
        
        Document document = getDocumentById(documentId);
        User user = getUserByUsername(username);
        
        // Vérifier si l'utilisateur a la permission de commenter
        if (!document.hasUserPermission(user, DocumentPermission.COMMENT)) {
            throw new AccessDeniedException("Vous n'avez pas l'autorisation de commenter ce document");
        }
        
        DocumentComment parentComment = null;
        if (parentCommentId != null) {
            parentComment = documentCommentRepository.findById(parentCommentId)
                    .orElseThrow(() -> new RuntimeException("Commentaire parent non trouvé"));
        }
        
        DocumentComment comment = document.addComment(user, content, parentComment);
        comment = documentCommentRepository.save(comment);
        
        return convertToCommentDTO(comment);
    }

    @Override
    @Transactional(readOnly = true)
    public List<DocumentCommentDTO> getDocumentComments(Long documentId, String username) {
        Document document = getDocumentById(documentId);
        User user = getUserByUsername(username);
        
        // Vérifier si l'utilisateur a la permission de lire le document
        if (!document.hasUserPermission(user, DocumentPermission.READ)) {
            throw new AccessDeniedException("Vous n'avez pas l'autorisation de consulter ce document");
        }
        
        // Récupérer les commentaires racines (sans parent)
        List<DocumentComment> rootComments = documentCommentRepository
                .findByDocumentIdAndParentCommentIsNullOrderByCreatedAtDesc(documentId);
        
        return rootComments.stream()
                .map(this::convertToCommentDTOWithReplies)
                .collect(Collectors.toList());
    }
    
    // Méthodes utilitaires privées
    
    private Document getDocumentById(Long id) {
        return documentRepository.findById(id)
                .orElseThrow(() -> new DocumentNotFoundException("Document non trouvé"));
    }
    
    private User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("Utilisateur non trouvé"));
    }
    
    private DocumentDTO convertToDocumentDTO(Document document, User currentUser) {
        DocumentVersion currentVersion = document.getCurrentVersion();
        
        return DocumentDTO.builder()
                .id(document.getId())
                .title(document.getTitle())
                .description(document.getDescription())
                .fileName(StringUtils.getFilename(document.getFilePath()))
                .mimeType(document.getMimeType())
                .fileSize(document.getFileSize())
                .isPublic(document.getIsPublic())
                .status(document.getStatus())
                .creator(convertToUserDTO(document.getCreator()))
                .department(document.getDepartment() != null ? convertToDepartmentDTO(document.getDepartment()) : null)
                .tags(document.getTags().stream().map(this::convertToTagDTO).collect(Collectors.toSet()))
                .currentVersion(currentVersion != null ? currentVersion.getVersionNumber() : null)
                .createdAt(document.getCreatedAt())
                .updatedAt(document.getUpdatedAt())
                .totalComments((long) document.getComments().size())
                .canEdit(document.hasUserPermission(currentUser, DocumentPermission.WRITE))
                .canDelete(document.hasUserPermission(currentUser, DocumentPermission.DELETE))
                .canArchive(document.hasUserPermission(currentUser, DocumentPermission.ARCHIVE))
                .canShare(document.hasUserPermission(currentUser, DocumentPermission.SHARE))
                .canComment(document.hasUserPermission(currentUser, DocumentPermission.COMMENT))
                .canDownload(document.hasUserPermission(currentUser, DocumentPermission.DOWNLOAD))
                .build();
    }
    
    private UserDTO convertToUserDTO(User user) {
        return UserDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .departmentId(user.getDepartment() != null ? user.getDepartment().getId() : null)
                .departmentName(user.getDepartment() != null ? user.getDepartment().getName() : null)
                .isAdmin(userService.isAdmin(user.getUsername()))
                .build();
    }
    
    private DepartmentDTO convertToDepartmentDTO(Department department) {
        return DepartmentDTO.builder()
                .id(department.getId())
                .name(department.getName())
                .description(department.getDescription())
                .createdAt(department.getCreatedAt())
                .build();
    }
    
    private TagDTO convertToTagDTO(Tag tag) {
        return TagDTO.builder()
                .id(tag.getId())
                .name(tag.getName())
                .description(tag.getDescription())
                .documentCount(tag.getDocuments().size())
                .build();
    }
    
    private DocumentVersionDTO convertToVersionDTO(DocumentVersion version, boolean isCurrent) {
        return DocumentVersionDTO.builder()
                .id(version.getId())
                .documentId(version.getDocument().getId())
                .versionNumber(version.getVersionNumber())
                .filePath(version.getFilePath())
                .fileSize(version.getFileSize())
                .changeDescription(version.getChangeDescription())
                .createdBy(convertToUserDTO(version.getCreatedBy()))
                .createdAt(version.getCreatedAt())
                .isCurrent(isCurrent)
                .build();
    }
    
    private DocumentAccessRequestDTO convertToAccessRequestDTO(DocumentAccessRequest request) {
        Set<DocumentPermission> permissions = request.getRequestedPermissions().stream()
                .map(DocumentPermission::valueOf)
                .collect(Collectors.toSet());
        
        return DocumentAccessRequestDTO.builder()
                .id(request.getId())
                .document(convertToDocumentDTO(request.getDocument(), request.getRequester()))
                .requester(convertToUserDTO(request.getRequester()))
                .requestedPermissions(permissions)
                .justification(request.getJustification())
                .expirationRequested(request.getExpirationRequested())
                .status(request.getStatus())
                .reviewedBy(request.getReviewedBy() != null ? convertToUserDTO(request.getReviewedBy()) : null)
                .reviewedAt(request.getReviewedAt())
                .reviewComments(request.getReviewComments())
                .createdAt(request.getCreatedAt())
                .updatedAt(request.getUpdatedAt())
                .build();
    }
    
    private DocumentCommentDTO convertToCommentDTO(DocumentComment comment) {
        return DocumentCommentDTO.builder()
                .id(comment.getId())
                .documentId(comment.getDocument().getId())
                .user(convertToUserDTO(comment.getUser()))
                .content(comment.getContent())
                .parentCommentId(comment.getParentComment() != null ? comment.getParentComment().getId() : null)
                .createdAt(comment.getCreatedAt())
                .updatedAt(comment.getUpdatedAt())
                .isEdited(comment.getIsEdited())
                .build();
    }
    
    private DocumentCommentDTO convertToCommentDTOWithReplies(DocumentComment comment) {
        DocumentCommentDTO dto = convertToCommentDTO(comment);
        
        // Récupérer les réponses à ce commentaire
        List<DocumentComment> replies = documentCommentRepository
                .findByParentCommentIdOrderByCreatedAtAsc(comment.getId());
        
        if (!replies.isEmpty()) {
            dto.setReplies(replies.stream()
                    .map(this::convertToCommentDTO)
                    .collect(Collectors.toList()));
        }
        
        return dto;
    }
} 