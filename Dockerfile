# =====================================================================
# DOCKERFILE PARA SECURITY-SERVICE (Logitrack)
# =====================================================================

# Etapa 1: Construcción (Build) utilizando Maven con JDK 17
FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app

# Copiar los archivos de configuración y dependencias del proyecto
COPY pom.xml .
COPY src ./src

# Compilar y empaquetar el proyecto omitiendo las pruebas unitarias para agilizar
RUN mvn clean package -DskipTests

# Etapa 2: Ejecución (Runtime) con una imagen ligera de OpenJDK 17
FROM openjdk:17-jdk-slim
WORKDIR /app

# Copiar el archivo .jar generado desde la etapa de construcción anterior
COPY --from=build /app/target/security-service-0.0.1-SNAPSHOT.jar app.jar

# Exponer el puerto en el que corre el microservicio
EXPOSE 8081

# Comando de ejecución para arrancar la aplicación Spring Boot dentro del contenedor
ENTRYPOINT ["java", "-jar", "app.jar"]