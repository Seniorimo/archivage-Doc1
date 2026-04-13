# ===========================================================================
# DOCKERFILE — archivage-doc (Spring Boot 17)
# Corrections apportées :
#   ✅ HEALTHCHECK via Spring Boot Actuator
#   ✅ Labels OCI standard (traçabilité & inventaire)
#   ✅ COPY --chown pour éviter un chown séparé (layer inutile)
#   ✅ JVM flags adaptés aux conteneurs (RAM, entropy, GC)
#   ✅ Non-root user maintenu (spring:spring)
#   ✅ JRE Alpine minimal (pas JDK) — surface d'attaque réduite
# ===========================================================================

FROM eclipse-temurin:17-jre-alpine

# ---------------------------------------------------------------------------
# METADATA (standard OCI — utilisée par Trivy, Syft, registries)
# ---------------------------------------------------------------------------
LABEL maintainer="devops@company.com" \
      org.opencontainers.image.title="archivage-doc" \
      org.opencontainers.image.description="Application Spring Boot d'archivage documentaire" \
      org.opencontainers.image.vendor="Company" \
      org.opencontainers.image.base.name="eclipse-temurin:17-jre-alpine"

# ---------------------------------------------------------------------------
# UTILISATEUR NON-ROOT
# ---------------------------------------------------------------------------
RUN addgroup -S spring && adduser -S spring -G spring

WORKDIR /app

# ---------------------------------------------------------------------------
# COPIE DU JAR — --chown évite un RUN chown séparé (optimise les layers)
# ---------------------------------------------------------------------------
ARG JAR_FILE=target/*.jar
COPY --chown=spring:spring ${JAR_FILE} app.jar

USER spring:spring

EXPOSE 8080

# ---------------------------------------------------------------------------
# HEALTHCHECK — Spring Boot Actuator (/actuator/health)
# ⚠️  Requiert spring-boot-starter-actuator dans le pom.xml
# --start-period=60s : laisse Spring Boot s'initialiser avant les checks
# ---------------------------------------------------------------------------
HEALTHCHECK --interval=30s \
            --timeout=5s \
            --start-period=60s \
            --retries=3 \
  CMD wget --no-verbose --tries=1 --spider \
      http://localhost:8080/actuator/health || exit 1

# ---------------------------------------------------------------------------
# ENTRYPOINT — flags JVM container-aware
#   -XX:+UseContainerSupport     : lit les cgroups Docker pour la RAM/CPU
#   -XX:MaxRAMPercentage=75.0    : utilise 75% de la RAM allouée au conteneur
#   -Djava.security.egd          : entropy rapide (évite le blocage au démarrage)
# ---------------------------------------------------------------------------
ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
