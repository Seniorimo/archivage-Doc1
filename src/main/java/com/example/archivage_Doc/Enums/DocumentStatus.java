package com.example.archivage_Doc.Enums;

/**
 * Statuts possibles pour un document
 */
public enum DocumentStatus {
    DRAFT("Brouillon"),
    ACTIVE("Actif"),
    ARCHIVED("Archivé"),
    DELETED("Supprimé");

    private final String description;

    DocumentStatus(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
} 