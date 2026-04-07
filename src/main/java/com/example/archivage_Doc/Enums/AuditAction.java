package com.example.archivage_Doc.Enums;

/**
 * Types d'actions qui seront enregistrées dans le système d'audit
 */
public enum AuditAction {
    // Actions d'authentification
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT,
    
    // Actions liées aux documents
    DOCUMENT_VIEW,
    DOCUMENT_CREATE,
    DOCUMENT_UPDATE,
    DOCUMENT_DELETE,
    DOCUMENT_DOWNLOAD,
    DOCUMENT_SHARE,
    
    // Actions liées aux accès
    ACCESS_REQUEST,
    ACCESS_GRANT,
    ACCESS_DENY,
    ACCESS_REVOKE,
    
    // Actions liées aux utilisateurs
    USER_CREATE,
    USER_UPDATE,
    USER_DELETE,
    USER_PASSWORD_CHANGE,
    
    // Actions sensibles d'administration
    ADMIN_ACTION,
    SETTINGS_CHANGE
} 