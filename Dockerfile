# =========================
# Build stage
# =========================
FROM maven:3.9.9-eclipse-temurin-21 AS build

WORKDIR /app

# Copy pom.xml first (for dependency caching)
COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .

# Download dependencies
RUN mvn dependency:go-offline

# Copy source code
COPY src src

# Build jar
RUN mvn clean package -DskipTests

# =========================
# Runtime stage
# =========================
FROM eclipse-temurin:21-jdk-jammy

WORKDIR /app

# JVM tuning for Render
ENV JAVA_TOOL_OPTIONS="-Xms256m -Xmx512m -Djava.net.preferIPv4Stack=true"

# Copy jar from build stage
COPY --from=build /app/target/*.jar app.jar

# Render uses port 8080
EXPOSE 8080

# Run app
ENTRYPOINT ["java","-jar","app.jar"]
