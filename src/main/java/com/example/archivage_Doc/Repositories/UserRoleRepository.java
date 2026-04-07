package com.example.archivage_Doc.Repositories;

import com.example.archivage_Doc.Entities.UserRole;
import com.example.archivage_Doc.Enums.DepartmentLevel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, Long> {
    
    /**
     * Trouver tous les rôles d'un utilisateur
     */
    List<UserRole> findByUserId(Long userId);
    
    /**
     * Trouver tous les rôles d'un utilisateur dans un département spécifique
     */
    List<UserRole> findByUserIdAndDepartmentId(Long userId, Long departmentId);
    
    /**
     * Trouver le rôle d'un utilisateur avec un niveau spécifique
     */
    Optional<UserRole> findByUserIdAndLevel(Long userId, DepartmentLevel level);
    
    /**
     * Vérifier si un utilisateur a un rôle de niveau spécifique
     */
    boolean existsByUserIdAndLevel(Long userId, DepartmentLevel level);
    
    /**
     * Trouver tous les utilisateurs avec un niveau spécifique
     */
    @Query("SELECT ur FROM UserRole ur WHERE ur.level = :level")
    List<UserRole> findByLevel(@Param("level") DepartmentLevel level);
    
    /**
     * Trouver tous les rôles dans un département spécifique
     */
    List<UserRole> findByDepartmentId(Long departmentId);
} 