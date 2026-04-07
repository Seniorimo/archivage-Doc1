package com.example.archivage_Doc.Services;

import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

/**
 * Service pour le stockage et la récupération des fichiers
 */
public interface FileStorageService {
    
    /**
     * Stocker un fichier dans le système
     * @param file Fichier à stocker
     * @return Chemin d'accès au fichier stocké
     * @throws IOException En cas d'erreur d'entrée/sortie
     */
    String storeFile(MultipartFile file) throws IOException;
    
    /**
     * Charger un fichier depuis le système de stockage
     * @param filePath Chemin d'accès au fichier
     * @return Ressource représentant le fichier
     * @throws IOException En cas d'erreur d'entrée/sortie
     */
    Resource loadFileAsResource(String filePath) throws IOException;
    
    /**
     * Supprimer un fichier du système de stockage
     * @param filePath Chemin d'accès au fichier à supprimer
     * @return true si le fichier a été supprimé, false sinon
     */
    boolean deleteFile(String filePath);
} 