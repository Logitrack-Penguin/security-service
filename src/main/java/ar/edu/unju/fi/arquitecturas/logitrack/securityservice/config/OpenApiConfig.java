package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuración de la documentación OpenAPI 3 / Swagger UI del microservicio.
 * Declara el esquema de seguridad "bearerAuth" para que desde Swagger UI se pueda
 * pegar el token JWT (botón "Authorize") y probar los endpoints protegidos.
 * <p>
 * Swagger UI queda disponible en {@code /swagger-ui.html}.
 * </p>
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@Configuration
public class OpenApiConfig {

    /**
     * Construye la definición OpenAPI con los datos generales del servicio y el esquema Bearer JWT.
     *
     * @return La especificación OpenAPI que publica springdoc.
     */
    @Bean
    public OpenAPI securityServiceOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("LogiTrack - security-service")
                        .description("Autenticación, registro de usuarios y emisión de tokens JWT")
                        .version("1.0.0"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")));
    }
}
