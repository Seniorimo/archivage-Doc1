# Runtime image for the Spring Boot application.
# The JAR is built by Maven before docker build.

FROM eclipse-temurin:17-jre-alpine

LABEL org.opencontainers.image.title="archivage-doc" \
      org.opencontainers.image.description="Spring Boot document archiving API" \
      org.opencontainers.image.base.name="eclipse-temurin:17-jre-alpine"

ARG APP_USER=spring
ARG APP_GROUP=spring
ARG JAR_FILE=target/*.jar

WORKDIR /app

RUN apk add --no-cache wget

RUN addgroup -S "${APP_GROUP}" \
    && adduser -S "${APP_USER}" -G "${APP_GROUP}" \
    && mkdir -p /app/uploads \
    && chown -R "${APP_USER}:${APP_GROUP}" /app

COPY --chown=${APP_USER}:${APP_GROUP} ${JAR_FILE} app.jar

USER ${APP_USER}:${APP_GROUP}

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8090/actuator/health || exit 1

ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
