package com.example.archivage_Doc.Enums;

/**
 * Statuts possibles pour une demande d'accès à un document
 */
public enum RequestStatus {
    PENDING("En attente"),
    APPROVED("Approuvée"),
    REJECTED("Rejetée"),
    CANCELLED("Annulée");

    private final String description;

    RequestStatus(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
} 