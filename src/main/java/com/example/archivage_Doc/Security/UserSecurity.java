package com.example.archivage_Doc.Security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.example.archivage_Doc.Entities.User;
import com.example.archivage_Doc.Enums.AuditAction;
import com.example.archivage_Doc.Repositories.UserRepository;
import com.example.archivage_Doc.Services.AuditService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserSecurity {
    
    private final UserRepository userRepository;
    private final AuditService auditService;
    
    /**
     * Vérifie si l'utilisateur authentifié est en train de modifier son propre profil
     * @param userId L'ID de l'utilisateur à modifier
     * @return true si c'est le même utilisateur, false sinon
     */
    public boolean isCurrentUser(Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getName())) {
            log.warn("Tentative d'accès sans authentification pour l'ID utilisateur: {}", userId);
            auditService.logUserAction(
                AuditAction.ACCESS_DENY,
                "anonymous",
                userId,
                "Tentative de modification de profil sans authentification",
                "ÉCHEC"
            );
            return false;
        }
        
        String username = auth.getName();
        log.info("Vérification des droits d'accès - Utilisateur: {} tente de modifier le profil ID: {}", username, userId);
        
        return userRepository.findByUsername(username)
            .map(user -> {
                boolean isCurrentUser = user.getId().equals(userId);
                if (!isCurrentUser) {
                    log.warn("Tentative de modification non autorisée - Utilisateur: {} tente de modifier le profil ID: {}", username, userId);
                    auditService.logUserAction(
                        AuditAction.ACCESS_DENY,
                        username,
                        userId,
                        "Tentative de modification d'un profil d'un autre utilisateur",
                        "ÉCHEC"
                    );
                } else {
                    log.info("Accès autorisé - L'utilisateur {} modifie son propre profil", username);
                    auditService.logUserAction(
                        AuditAction.ACCESS_GRANT,
                        username,
                        userId,
                        "Accès autorisé à la modification de son propre profil",
                        "SUCCÈS"
                    );
                }
                return isCurrentUser;
            })
            .orElse(false);
    }
} 