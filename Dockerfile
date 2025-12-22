# Use Java 21 (matches your Spring Boot setup)
FROM eclipse-temurin:21-jdk-jammy

# Set working directory
WORKDIR /app

# Copy jar
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} app.jar

# JVM tuning (important for Render)
ENV JAVA_TOOL_OPTIONS="-Xms256m -Xmx512m -Djava.net.preferIPv4Stack=true"

# Expose port (Render uses 8080)
EXPOSE 8080

# Start app
ENTRYPOINT ["java","-jar","app.jar"]
