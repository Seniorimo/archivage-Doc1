package com.example.archivage_Doc.Enums;

public enum Permission {
    DOCUMENT_READ("Lecture des documents"),
    DOCUMENT_WRITE("Écriture des documents"),
    DOCUMENT_DELETE("Suppression des documents"),
    DOCUMENT_ARCHIVE("Archivage des documents"),
    USER_MANAGE("Gestion des utilisateurs"),
    ADMIN_CREATE("Création d'administrateurs"),
    MANAGER_CREATE("Création de managers");

    private final String description;

    Permission(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}