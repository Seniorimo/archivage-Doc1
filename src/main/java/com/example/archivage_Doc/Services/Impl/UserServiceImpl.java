package com.example.archivage_Doc.Services.Impl;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.archivage_Doc.DTOs.UserDTO;
import com.example.archivage_Doc.Entities.User;
import com.example.archivage_Doc.Entities.UserRole;
import com.example.archivage_Doc.Enums.AuditAction;
import com.example.archivage_Doc.Enums.DepartmentLevel;
import com.example.archivage_Doc.Enums.Permission;
import com.example.archivage_Doc.Exceptions.UserNotFoundException;
import com.example.archivage_Doc.Repositories.DepartmentRepository;
import com.example.archivage_Doc.Repositories.UserRepository;
import com.example.archivage_Doc.Repositories.UserRoleRepository;
import com.example.archivage_Doc.Services.AuditService;
import com.example.archivage_Doc.Services.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final DepartmentRepository departmentRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    
    @Override
    public boolean hasPermission(String username, String permission) {
        User user = getUserByUsername(username);
        
        // Les administrateurs ont toutes les permissions
        if (isAdmin(username)) {
            return true;
        }
        
        // Vérifier les rôles de l'utilisateur
        return userRoleRepository.findByUserId(user.getId()).stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(Permission::name)
                .anyMatch(perm -> perm.equals(permission));
    }
    
    @Override
    public boolean isAdmin(String username) {
        User user = getUserByUsername(username);
        
        return userRoleRepository.findByUserId(user.getId()).stream()
                .anyMatch(role -> role.getLevel() == DepartmentLevel.ADMIN);
    }
    
    @Override
    public boolean isManager(String username) {
        User user = getUserByUsername(username);
        
        return userRoleRepository.findByUserId(user.getId()).stream()
                .anyMatch(role -> role.getLevel() == DepartmentLevel.MANAGER);
    }
    
    @Override
    public Set<String> getUserPermissions(String username) {
        User user = getUserByUsername(username);
        
        return userRoleRepository.findByUserId(user.getId()).stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(Permission::name)
                .collect(Collectors.toSet());
    }
    
    @Override
    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("Utilisateur non trouvé: " + username));
    }
    
    @Override
    public List<UserDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::convertToUserDTO)
                .collect(Collectors.toList());
    }
    
    @Override
    public UserDTO getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("Utilisateur non trouvé avec ID: " + id));
        
        return convertToUserDTO(user);
    }
    
    @Override
    public UserDTO getUserProfile(String username) {
        User user = getUserByUsername(username);
        return convertToUserDTO(user);
    }
    
    @Override
    @Transactional
    public UserDTO updateUser(Long id, UserDTO userDTO, String currentUsername) {
        // Vérifier si l'utilisateur a le droit de modifier (admin ou lui-même)
        if (!isAdmin(currentUsername) && !userDTO.getUsername().equals(currentUsername)) {
            throw new RuntimeException("Non autorisé à modifier cet utilisateur");
        }
        
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("Utilisateur non trouvé avec ID: " + id));
        
        // Mettre à jour les champs autorisés
        if (userDTO.getFirstName() != null) {
            user.setFirstName(userDTO.getFirstName());
        }
        
        if (userDTO.getLastName() != null) {
            user.setLastName(userDTO.getLastName());
        }
        
        if (userDTO.getEmail() != null) {
            user.setEmail(userDTO.getEmail());
        }
        
        // Seul l'admin peut modifier ces champs
        if (isAdmin(currentUsername)) {
            if (userDTO.getIsActive() != null) {
                user.setEnabled(userDTO.getIsActive());
            }
        }
        
        user = userRepository.save(user);
        
        // Audit de la modification de l'utilisateur
        auditService.logUserAction(
            AuditAction.USER_UPDATE,
            currentUsername,
            id,
            "Modification des informations de l'utilisateur",
            "SUCCÈS"
        );
        
        return convertToUserDTO(user);
    }
    
    @Override
    @Transactional
    public void deleteUser(Long id, String currentUsername) {
        // Seul un admin peut supprimer un utilisateur
        if (!isAdmin(currentUsername)) {
            throw new RuntimeException("Non autorisé à supprimer cet utilisateur");
        }
        
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("Utilisateur non trouvé avec ID: " + id));
        
        // Désactiver l'utilisateur plutôt que de le supprimer
        user.setEnabled(false);
        userRepository.save(user);
        
        // Audit de la suppression de l'utilisateur
        auditService.logUserAction(
            AuditAction.USER_DELETE,
            currentUsername,
            id,
            "Suppression de l'utilisateur",
            "SUCCÈS"
        );
    }
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Utilisateur non trouvé: " + username));
    }
    
    // Méthode utilitaire pour convertir un User en UserDTO
    private UserDTO convertToUserDTO(User user) {
        Set<String> permissions = new HashSet<>();
        DepartmentLevel level = null;
        
        // Récupérer les permissions et le niveau de département
        List<UserRole> roles = userRoleRepository.findByUserId(user.getId());
        
        for (UserRole role : roles) {
            role.getPermissions().forEach(perm -> permissions.add(perm.name()));
            
            // Prendre le niveau le plus élevé
            if (level == null || role.getLevel().ordinal() < level.ordinal()) {
                level = role.getLevel();
            }
        }
        
        return UserDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .level(level)
                .departmentId(user.getDepartment() != null ? user.getDepartment().getId() : null)
                .departmentName(user.getDepartment() != null ? user.getDepartment().getName() : null)
                .permissions(permissions)
                .isActive(user.isEnabled())
                .isAdmin(level == DepartmentLevel.ADMIN)
                .build();
    }
} 