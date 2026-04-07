package com.example.archivage_Doc.Services;

import com.example.archivage_Doc.DTOs.UserDTO;
import com.example.archivage_Doc.Entities.User;

import java.util.List;
import java.util.Set;

/**
 * Service pour la gestion des utilisateurs
 */
public interface UserService {
    
    /**
     * Vérifier si un utilisateur a une permission spécifique
     */
    boolean hasPermission(String username, String permission);
    
    /**
     * Vérifier si un utilisateur est administrateur
     */
    boolean isAdmin(String username);
    
    /**
     * Vérifier si un utilisateur est manager
     */
    boolean isManager(String username);
    
    /**
     * Récupérer les permissions d'un utilisateur
     */
    Set<String> getUserPermissions(String username);
    
    /**
     * Récupérer un utilisateur par son nom d'utilisateur
     */
    User getUserByUsername(String username);
    
    /**
     * Récupérer tous les utilisateurs
     */
    List<UserDTO> getAllUsers();
    
    /**
     * Récupérer un utilisateur par son ID
     */
    UserDTO getUserById(Long id);
    
    /**
     * Récupérer le profil de l'utilisateur connecté
     */
    UserDTO getUserProfile(String username);
    
    /**
     * Mettre à jour un utilisateur
     */
    UserDTO updateUser(Long id, UserDTO userDTO, String currentUsername);
    
    /**
     * Supprimer un utilisateur
     */
    void deleteUser(Long id, String currentUsername);
}
