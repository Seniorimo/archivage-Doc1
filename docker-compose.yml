# Archivage_doc
arch_app
=======
# Système de Gestion de Documents

Ce projet est une application web complète pour la gestion de documents, composée d'un backend Spring Boot et d'un frontend Vite.js.

## Architecture du Projet

### Backend (Spring Boot)

Le backend est organisé en plusieurs packages principaux :

#### 1. Controllers (`com.example.archivage_Doc.Controllers`)
- `AuthController` : Gère l'authentification (login, register)
- `DocumentController` : Gère les opérations CRUD sur les documents
- `UserController` : Gère la gestion des utilisateurs
- `AuditController` : Gère l'accès aux logs d'audit

#### 2. Services (`com.example.archivage_Doc.Services`)
- `AuthService` : Implémente la logique d'authentification
- `DocumentService` : Gère la logique métier des documents
- `UserService` : Gère la logique métier des utilisateurs
- `AuditService` : Gère l'enregistrement des actions d'audit

#### 3. Security (`com.example.archivage_Doc.Security`)
- `JwtAuthenticationFilter` : Filtre les requêtes et valide les tokens JWT
- `SecurityConfig` : Configuration de la sécurité Spring Security
- `JwtService` : Gère la génération et validation des tokens JWT

#### 4. Models (`com.example.archivage_Doc.Models`)
- `User` : Modèle de données pour les utilisateurs
- `Document` : Modèle de données pour les documents
- `AuditLog` : Modèle de données pour les logs d'audit

#### 5. DTOs (`com.example.archivage_Doc.DTOs`)
- `LoginRequest` : Structure pour les requêtes de login
- `RegisterRequest` : Structure pour les requêtes d'inscription
- `DocumentDTO` : Structure pour le transfert de données des documents

#### 6. Enums (`com.example.archivage_Doc.Enums`)
- `Role` : Définit les rôles utilisateurs (ADMIN, MANAGER, EMPLOYEE)
- `AuditAction` : Définit les types d'actions auditées

### Frontend (Vite.js)

Le frontend est organisé en plusieurs dossiers principaux :

#### 1. Components (`src/components`)
- `Login.tsx` : Composant de connexion
- `Register.tsx` : Composant d'inscription
- `DocumentList.tsx` : Liste des documents
- `DocumentForm.tsx` : Formulaire de création/modification de document
- `AuditLogs.tsx` : Affichage des logs d'audit

#### 2. Services (`src/services`)
- `api.ts` : Service pour les appels API
- `auth.ts` : Service de gestion de l'authentification

#### 3. Contexts (`src/contexts`)
- `AuthContext.tsx` : Gestion du contexte d'authentification

#### 4. Types (`src/types`)
- `User.ts` : Types TypeScript pour les utilisateurs
- `Document.ts` : Types TypeScript pour les documents
- `AuditLog.ts` : Types TypeScript pour les logs d'audit

## Fonctionnalités Principales

### Authentification
- Inscription des utilisateurs avec différents rôles
- Connexion avec JWT
- Gestion des permissions basée sur les rôles

### Gestion des Documents
- Création, lecture, modification, suppression de documents
- Upload et téléchargement de fichiers
- Gestion des versions
- Partage de documents

### Audit
- Enregistrement automatique des actions importantes
- Consultation des logs par les administrateurs
- Filtrage et recherche dans les logs

## Sécurité

- Authentification JWT
- Protection des routes par rôles
- Validation des données
- Audit des actions sensibles

## Technologies Utilisées

### Backend
- Spring Boot
- Spring Security
- JWT
- Spring Data JPA
- PostgreSQL

### Frontend
- Vite.js
- React
- TypeScript
- Material-UI
- Axios

## Installation et Démarrage

### Backend
1. Installer Java 17+
2. Installer Maven
3. Configurer la base de données dans `application.properties`
4. Exécuter `mvn spring-boot:run`

### Frontend
1. Installer Node.js
2. Installer les dépendances : `npm install`
3. Démarrer le serveur de développement : `npm run dev`

## Configuration

### Base de données
- Modifier `application.properties` pour configurer la connexion à la base de données
- Les migrations sont gérées automatiquement par Hibernate

### JWT
- La clé secrète JWT est configurée dans `application.properties`
- La durée de validité des tokens est configurable

## Tests

### Backend
- Tests unitaires avec JUnit
- Tests d'intégration avec Spring Test

### Frontend
- Tests unitaires avec Jest
- Tests de composants avec React Testing Library 

