# =====================================================================
# DOCKERFILE MULTIETAPA - SECURITY-SERVICE (LogiTrack) - Java 25
# =====================================================================

# Etapa 1: construcción con Maven y JDK 25
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /app

# Se copia primero el pom para aprovechar la caché de capas de Docker
COPY pom.xml .
RUN mvn -B -q dependency:go-offline

COPY src ./src
RUN mvn -B -q clean package -DskipTests

# Etapa 2: ejecución solo con el JRE 25 (sin código fuente ni Maven)
FROM eclipse-temurin:25-jre
WORKDIR /app

# Usuario sin privilegios para ejecutar la aplicación
RUN groupadd --system app && useradd --system --gid app --no-create-home app

COPY --from=build /app/target/*.jar app.jar
USER app

EXPOSE 8081

# Las credenciales (DB_PASSWORD, JWT_SECRET) NO van en la imagen: se inyectan como variables de entorno
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "app.jar"]
