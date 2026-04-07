package com.example.archivage_Doc.Entities;

import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;

import com.example.archivage_Doc.Enums.AuditAction;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Entité pour stocker les logs d'audit de sécurité
 * Enregistre toutes les actions importantes effectuées dans le système
 */
@Entity
@Table(name = "audit_logs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Type d'action effectuée
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditAction action;
    
    // Utilisateur qui a effectué l'action
    @Column(name = "username", nullable = false)
    private String username;
    
    // Adresse IP de l'utilisateur
    @Column(name = "ip_address")
    private String ipAddress;
    
    // Identifiant de la ressource concernée (document, utilisateur, etc.)
    @Column(name = "resource_id")
    private String resourceId;
    
    // Type de ressource (document, utilisateur, etc.)
    @Column(name = "resource_type")
    private String resourceType;
    
    // Description détaillée de l'action
    @Column(name = "description", length = 1000)
    private String description;
    
    // Données supplémentaires (JSON)
    @Lob
    @Column(name = "additional_data")
    private String additionalData;
    
    // Statut de l'action (succès/échec)
    @Column(name = "status", nullable = false)
    private String status;
    
    // Date et heure de l'action
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    // Identifiant de session
    @Column(name = "session_id")
    private String sessionId;
    
    // User agent
    @Column(name = "user_agent", length = 500)
    private String userAgent;
} 