package com.example.archivage_Doc.Services.Impl;

import com.example.archivage_Doc.Config.FileStorageProperties;
import com.example.archivage_Doc.Exceptions.FileStorageException;
import com.example.archivage_Doc.Services.FileStorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

@Service
public class FileStorageServiceImpl implements FileStorageService {
    
    private final Path fileStorageLocation;
    
    @Autowired
    public FileStorageServiceImpl(FileStorageProperties fileStorageProperties) {
        this.fileStorageLocation = Paths.get(fileStorageProperties.getUploadDir())
                .toAbsolutePath().normalize();
        
        try {
            Files.createDirectories(this.fileStorageLocation);
        } catch (Exception ex) {
            throw new FileStorageException("Impossible de créer le répertoire de stockage des fichiers", ex);
        }
    }
    
    @Override
    public String storeFile(MultipartFile file) throws IOException {
        // Normaliser le nom de fichier
        String originalFilename = StringUtils.cleanPath(file.getOriginalFilename());
        
        // Vérifier si le nom de fichier contient des caractères invalides
        if (originalFilename.contains("..")) {
            throw new FileStorageException("Le nom de fichier contient un chemin invalide: " + originalFilename);
        }
        
        // Générer un nom de fichier unique pour éviter les conflits
        String uniqueFilename = UUID.randomUUID().toString() + "_" + originalFilename;
        
        // Copier le fichier dans le répertoire de stockage
        Path targetLocation = this.fileStorageLocation.resolve(uniqueFilename);
        Files.copy(file.getInputStream(), targetLocation, StandardCopyOption.REPLACE_EXISTING);
        
        return uniqueFilename;
    }
    
    @Override
    public Resource loadFileAsResource(String filePath) throws IOException {
        try {
            Path path = this.fileStorageLocation.resolve(filePath).normalize();
            Resource resource = new UrlResource(path.toUri());
            
            if (resource.exists()) {
                return resource;
            } else {
                throw new FileStorageException("Fichier non trouvé: " + filePath);
            }
        } catch (MalformedURLException ex) {
            throw new FileStorageException("Fichier non trouvé: " + filePath, ex);
        }
    }
    
    @Override
    public boolean deleteFile(String filePath) {
        try {
            Path path = this.fileStorageLocation.resolve(filePath).normalize();
            return Files.deleteIfExists(path);
        } catch (IOException ex) {
            throw new FileStorageException("Impossible de supprimer le fichier: " + filePath, ex);
        }
    }
} 