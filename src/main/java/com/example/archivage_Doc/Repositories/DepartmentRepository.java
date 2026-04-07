package com.example.archivage_Doc.Repositories;

import com.example.archivage_Doc.Entities.Department;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DepartmentRepository extends JpaRepository<Department, Long> {
    
    /**
     * Trouver un département par son code
     */
    Optional<Department> findByCode(String code);
    
    /**
     * Trouver un département par son nom
     */
    Optional<Department> findByName(String name);
    
    /**
     * Trouver les départements dont le nom contient la recherche
     */
    List<Department> findByNameContainingIgnoreCase(String search);
    
    /**
     * Trouver les départements par manager
     */
    @Query("SELECT d FROM Department d JOIN UserRole ur ON d.id = ur.department.id " +
           "WHERE ur.user.id = :userId AND ur.level = 'MANAGER'")
    List<Department> findByManagerId(@Param("userId") Long userId);
    
    /**
     * Compter le nombre d'employés dans un département
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.department.id = :departmentId")
    long countEmployeesByDepartmentId(@Param("departmentId") Long departmentId);
} 