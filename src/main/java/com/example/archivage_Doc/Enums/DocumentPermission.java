package com.example.archivage_Doc.Enums;

/**
 * Permissions possibles pour les documents
 */
public enum DocumentPermission {
    READ("Lecture"),
    WRITE("Écriture"),
    DELETE("Suppression"),
    ARCHIVE("Archivage"),
    SHARE("Partage"),
    COMMENT("Commentaire"),
    DOWNLOAD("Téléchargement"),
    MANAGE_ACCESS("Gestion des accès");

    private final String description;

    DocumentPermission(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
    
    public String getValue() {
        return this.name();
    }
} 