package com.example.archivage_Doc.Config;

import com.example.archivage_Doc.DTOs.RegisterRequest;
import com.example.archivage_Doc.Entities.Department;
import com.example.archivage_Doc.Entities.Role;
import com.example.archivage_Doc.Entities.User;
import com.example.archivage_Doc.Repositories.DepartmentRepository;
import com.example.archivage_Doc.Repositories.RoleRepository;
import com.example.archivage_Doc.Repositories.UserRepository;
import com.example.archivage_Doc.Services.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@Slf4j
public class DataInitializer {

    @Bean
    CommandLineRunner initData(
            RoleRepository roleRepository,
            UserRepository userRepository,
            DepartmentRepository departmentRepository,
            AuthService authService,
            PasswordEncoder passwordEncoder) {
        return args -> {
            // Créer le rôle USER s'il n'existe pas
            if (!roleRepository.findByName("ROLE_USER").isPresent()) {
                Role userRole = Role.builder()
                        .name("ROLE_USER")
                        .description("Role standard pour les utilisateurs")
                        .build();
                roleRepository.save(userRole);
            }

            // Créer le rôle ADMIN s'il n'existe pas
            if (!roleRepository.findByName("ROLE_ADMIN").isPresent()) {
                Role adminRole = Role.builder()
                        .name("ROLE_ADMIN")
                        .description("Role administrateur")
                        .build();
                roleRepository.save(adminRole);
            }
            
            // Créer le département par défaut s'il n'existe pas
            Department defaultDepartment = departmentRepository.findByCode("DEFAULT")
                    .orElseGet(() -> {
                        Department dept = Department.builder()
                                .name("Département par défaut")
                                .code("DEFAULT")
                                .description("Département par défaut pour les nouveaux utilisateurs")
                                .build();
                        return departmentRepository.save(dept);
                    });
            
            // Créer les autres départements s'ils n'existent pas
            String[][] departments = {
                {"IT", "IT", "Département IT"},
                {"RH", "Ressources Humaines", "Département des Ressources Humaines"},
                {"FINANCE", "Finance", "Département Finance"},
                {"MARKETING", "Marketing", "Département Marketing"}
            };
            
            for (String[] deptInfo : departments) {
                if (!departmentRepository.findByCode(deptInfo[0]).isPresent()) {
                    Department dept = Department.builder()
                            .code(deptInfo[0])
                            .name(deptInfo[1])
                            .description(deptInfo[2])
                            .build();
                    departmentRepository.save(dept);
                    log.info("Département {} créé avec succès", deptInfo[1]);
                }
            }
            
            // Créer un utilisateur admin par défaut
            if (!userRepository.findByUsername("admin").isPresent()) {
                log.info("Création de l'utilisateur admin par défaut");
                RegisterRequest registerRequest = new RegisterRequest();
                registerRequest.setUsername("admin");
                registerRequest.setPassword("admin123");
                registerRequest.setDepartmentCode("DEFAULT");
                
                try {
                    authService.registerAdmin(registerRequest);
                    log.info("Utilisateur admin créé avec succès");
                    
                    // Vérifier l'utilisateur créé et ses permissions
                    User admin = userRepository.findByUsername("admin").orElse(null);
                    if (admin != null) {
                        log.info("Admin trouvé avec ID: {}", admin.getId());
                        log.info("Nombre de rôles de l'admin: {}", admin.getUserRoles().size());
                        admin.getUserRoles().forEach(role -> {
                            log.info("Rôle admin: niveau={}, département={}, permissions={}",
                                role.getLevel(),
                                role.getDepartment().getCode(),
                                role.getPermissions().stream()
                                    .map(Enum::name)
                                    .collect(java.util.stream.Collectors.joining(", ")));
                        });
                    } else {
                        log.warn("L'utilisateur admin n'a pas été trouvé après création");
                    }
                } catch (Exception e) {
                    log.error("Erreur lors de la création de l'utilisateur admin: {}", e.getMessage());
                }
            } else {
                log.info("L'utilisateur admin existe déjà");
            }
        };
    }
} 