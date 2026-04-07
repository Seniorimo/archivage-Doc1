package com.example.archivage_Doc.Repositories;

import com.example.archivage_Doc.Entities.Tag;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TagRepository extends JpaRepository<Tag, Long> {
    
    /**
     * Trouver un tag par son nom
     */
    Optional<Tag> findByName(String name);
    
    /**
     * Trouver les tags dont le nom contient la recherche
     */
    List<Tag> findByNameContainingIgnoreCase(String search);
    
    /**
     * Trouver les tags associés à un document
     */
    @Query("SELECT t FROM Tag t JOIN t.documents d WHERE d.id = :documentId")
    List<Tag> findByDocumentId(@Param("documentId") Long documentId);
    
    /**
     * Trouver les tags les plus utilisés (avec le nombre de documents)
     */
    @Query("SELECT t, COUNT(d) FROM Tag t JOIN t.documents d GROUP BY t ORDER BY COUNT(d) DESC")
    List<Object[]> findMostUsedTags(int limit);
} 