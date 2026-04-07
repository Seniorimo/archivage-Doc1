package com.example.archivage_Doc.Entities;

import com.example.archivage_Doc.Enums.DocumentPermission;
import com.example.archivage_Doc.Enums.DocumentStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "document")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Document {
    @Id 
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, length = 100)
    private String title;
    
    @Column(length = 500)
    private String description;
    
    @Column(name = "file_path", nullable = false)
    private String filePath;
    
    @Column(name = "file_size")
    private Long fileSize;
    
    @Column(name = "mime_type", length = 100)
    private String mimeType;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private DocumentStatus status;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "creator_id", nullable = false)
    private User creator;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "department_id")
    private Department department;
    
    @Column(name = "is_public", nullable = false)
    @Builder.Default
    private Boolean isPublic = false;
    
    @ManyToMany
    @JoinTable(
        name = "document_tag",
        joinColumns = @JoinColumn(name = "document_id"),
        inverseJoinColumns = @JoinColumn(name = "tag_id")
    )
    @Builder.Default
    private Set<Tag> tags = new HashSet<>();
    
    @OneToMany(mappedBy = "document", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<DocumentAccess> documentAccesses = new ArrayList<>();
    
    @OneToMany(mappedBy = "document", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("versionNumber DESC")
    @Builder.Default
    private List<DocumentVersion> versions = new ArrayList<>();
    
    @OneToMany(mappedBy = "document", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<DocumentComment> comments = new ArrayList<>();
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "archived_at")
    private LocalDateTime archivedAt;
    
    /**
     * Ajouter un tag au document
     */
    public void addTag(Tag tag) {
        this.tags.add(tag);
        tag.getDocuments().add(this);
    }
    
    /**
     * Supprimer un tag du document
     */
    public void removeTag(Tag tag) {
        this.tags.remove(tag);
        tag.getDocuments().remove(this);
    }
    
    /**
     * Ajouter une version au document
     */
    public void addVersion(DocumentVersion version) {
        this.versions.add(0, version);
        version.setDocument(this);
    }
    
    /**
     * Obtenir la version actuelle du document
     */
    public DocumentVersion getCurrentVersion() {
        if (this.versions.isEmpty()) {
            return null;
        }
        return this.versions.get(0);
    }
    
    /**
     * Ajouter un accès utilisateur au document
     */
    public DocumentAccess addUserAccess(User user, Set<String> permissions, User grantedBy, LocalDateTime expiresAt) {
        DocumentAccess access = DocumentAccess.builder()
                .document(this)
                .user(user)
                .permissions(permissions)
                .grantedBy(grantedBy.getId())
                .expiresAt(expiresAt)
                .build();
        
        this.documentAccesses.add(access);
        return access;
    }
    
    /**
     * Vérifier si un utilisateur a une permission spécifique sur ce document
     */
    public boolean hasUserPermission(User user, DocumentPermission permission) {
        // Le créateur a toutes les permissions
        if (user.getId().equals(this.creator.getId())) {
            return true;
        }
        
        // Si le document est public et que la permission est READ, autoriser
        if (this.isPublic && permission.equals(DocumentPermission.READ)) {
            return true;
        }
        
        // Vérifier si l'utilisateur est un manager ou admin et accorde READ
        if (permission.equals(DocumentPermission.READ)) {
            boolean isManagerOrAdmin = user.getUserRoles().stream()
                .anyMatch(role -> role.getLevel().name().equals("MANAGER") || role.getLevel().name().equals("ADMIN"));
            
            if (isManagerOrAdmin) {
                return true;
            }
            
            // Si le document appartient au même département que l'utilisateur
            if (this.department != null && user.getDepartment() != null && 
                this.department.getId().equals(user.getDepartment().getId())) {
                return true;
            }
        }
        
        // Vérifier les accès spécifiques
        return this.documentAccesses.stream()
                .filter(access -> access.getUser().getId().equals(user.getId()))
                .filter(access -> access.getExpiresAt() == null || 
                        access.getExpiresAt().isAfter(LocalDateTime.now()))
                .anyMatch(access -> access.hasPermission(permission.getValue()));
    }
    
    /**
     * Ajouter un commentaire au document
     */
    public DocumentComment addComment(User user, String content, DocumentComment parentComment) {
        DocumentComment comment = DocumentComment.builder()
                .document(this)
                .user(user)
                .content(content)
                .parentComment(parentComment)
                .isEdited(false)
                .build();
        
        this.comments.add(comment);
        return comment;
    }
} 