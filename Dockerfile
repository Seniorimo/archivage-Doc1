# ===========================================================================
# DOCKERFILE — archivage-doc (Spring Boot 17)
# Fix appliqué :
#   ✅ mkdir /app/uploads + chown -R spring:spring /app
#      → résout AccessDeniedException sur FileStorageServiceImpl
# ===========================================================================

FROM eclipse-temurin:17-jre-alpine

# ---------------------------------------------------------------------------
# METADATA (standard OCI)
# ---------------------------------------------------------------------------
LABEL maintainer="devops@company.com" \
      org.opencontainers.image.title="archivage-doc" \
      org.opencontainers.image.description="Application Spring Boot d'archivage documentaire" \
      org.opencontainers.image.base.name="eclipse-temurin:17-jre-alpine"

# ---------------------------------------------------------------------------
# UTILISATEUR NON-ROOT
# ---------------------------------------------------------------------------
RUN addgroup -S spring && adduser -S spring -G spring

WORKDIR /app

# ---------------------------------------------------------------------------
# FIX AccessDeniedException — créer uploads et donner les droits à spring
# Ce RUN s'exécute en ROOT (avant USER spring) → chown fonctionne
# ---------------------------------------------------------------------------
RUN mkdir -p /app/uploads && \
    chown -R spring:spring /app

# ---------------------------------------------------------------------------
# COPIE DU JAR
# ---------------------------------------------------------------------------
ARG JAR_FILE=target/*.jar
COPY --chown=spring:spring ${JAR_FILE} app.jar

USER spring:spring

EXPOSE 8090

# ---------------------------------------------------------------------------
# HEALTHCHECK — Spring Boot Actuator (/actuator/health)
# ---------------------------------------------------------------------------
HEALTHCHECK --interval=30s \
            --timeout=5s \
            --start-period=60s \
            --retries=3 \
  CMD wget --no-verbose --tries=1 --spider \
      http://localhost:8090/actuator/health || exit 1

# ---------------------------------------------------------------------------
# ENTRYPOINT — flags JVM container-aware
# ---------------------------------------------------------------------------
ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
