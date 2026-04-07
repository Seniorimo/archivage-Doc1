package com.example.archivage_Doc.Controllers;

import com.example.archivage_Doc.DTOs.DepartmentDTO;
import com.example.archivage_Doc.Entities.Department;
import com.example.archivage_Doc.Repositories.DepartmentRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/departments")
@RequiredArgsConstructor
@Slf4j
public class DepartmentController {
    private final DepartmentRepository departmentRepository;

    @GetMapping
    @Operation(summary = "Récupérer tous les départements")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Liste des départements récupérée"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    public ResponseEntity<List<DepartmentDTO>> getAllDepartments() {
        log.info("Récupération de tous les départements");
        List<Department> departments = departmentRepository.findAll();
        List<DepartmentDTO> departmentDTOs = departments.stream()
            .map(this::convertToDepartmentDTO)
            .collect(Collectors.toList());
        return ResponseEntity.ok(departmentDTOs);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Récupérer un département par son ID")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Département trouvé"),
        @ApiResponse(responseCode = "404", description = "Département non trouvé"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    @PreAuthorize("hasAnyAuthority('USER_MANAGE', 'DOCUMENT_WRITE')")
    public ResponseEntity<DepartmentDTO> getDepartmentById(@PathVariable Long id) {
        log.info("Récupération du département avec l'ID: {}", id);
        return departmentRepository.findById(id)
            .map(this::convertToDepartmentDTO)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @Operation(summary = "Créer un nouveau département")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Département créé"),
        @ApiResponse(responseCode = "400", description = "Données invalides"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    @PreAuthorize("hasAuthority('USER_MANAGE')")
    public ResponseEntity<DepartmentDTO> createDepartment(@RequestBody Department department) {
        log.info("Création d'un nouveau département: {}", department.getName());
        Department savedDepartment = departmentRepository.save(department);
        return ResponseEntity.ok(convertToDepartmentDTO(savedDepartment));
    }

    @PutMapping("/{id}")
    @Operation(summary = "Mettre à jour un département")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Département mis à jour"),
        @ApiResponse(responseCode = "404", description = "Département non trouvé"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    @PreAuthorize("hasAuthority('USER_MANAGE')")
    public ResponseEntity<DepartmentDTO> updateDepartment(@PathVariable Long id, @RequestBody Department department) {
        log.info("Mise à jour du département avec l'ID: {}", id);
        if (!departmentRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        department.setId(id);
        Department updatedDepartment = departmentRepository.save(department);
        return ResponseEntity.ok(convertToDepartmentDTO(updatedDepartment));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Supprimer un département")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "204", description = "Département supprimé"),
        @ApiResponse(responseCode = "404", description = "Département non trouvé"),
        @ApiResponse(responseCode = "403", description = "Accès non autorisé")
    })
    @PreAuthorize("hasAuthority('USER_MANAGE')")
    public ResponseEntity<Void> deleteDepartment(@PathVariable Long id) {
        log.info("Suppression du département avec l'ID: {}", id);
        if (!departmentRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        departmentRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    private DepartmentDTO convertToDepartmentDTO(Department department) {
        return DepartmentDTO.builder()
            .id(department.getId())
            .name(department.getName())
            .description(department.getDescription())
            .employeeCount(department.getUsers().size())
            .createdAt(department.getCreatedAt())
            .updatedAt(department.getUpdatedAt())
            .build();
    }
} 