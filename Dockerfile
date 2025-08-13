# =========================
# Build Stage (Maven + Java 21)
# =========================
FROM maven:3.9.9-eclipse-temurin-21 AS build

# Verify Java & Maven versions early to fail fast if wrong
RUN java -version && mvn -version

WORKDIR /app

# Cache dependencies first (faster builds)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code & build
COPY src ./src
RUN mvn clean package -DskipTests -P prod -B

# Verify JAR file exists
RUN ls -la /app/target/

# =========================
# Runtime Stage (Lightweight JRE)
# =========================
FROM eclipse-temurin:21-jre-alpine

# Security: Create non-root user
RUN addgroup -S spring && adduser -S spring -G spring
USER root
RUN apk add --no-cache curl
USER spring

WORKDIR /app

# Copy JAR from build stage
COPY --from=build --chown=spring:spring /app/target/*.jar api-gateway.jar

# Application port
EXPOSE 10007

# Run app
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar api-gateway.jar --spring.profiles.active=prod"]
