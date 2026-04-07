package com.example.archivage_Doc.Enums;

public enum DepartmentLevel {
    ADMIN("Administrateur"),
    MANAGER("Manager de département"),
    EMPLOYEE("Employé");

    private final String description;

    DepartmentLevel(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
} 