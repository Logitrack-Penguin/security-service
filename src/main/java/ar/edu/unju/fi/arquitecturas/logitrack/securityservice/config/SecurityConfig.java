package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.config;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.filter.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

/**
 * Clase de configuración principal para la seguridad web utilizando @Configuration
 * (anotación que indica que la clase contiene definiciones de beans y configuraciones de Spring),
 * @EnableWebSecurity (anotación para habilitar y personalizar la seguridad web de Spring Security)
 * y @EnableMethodSecurity (anotación que habilita @PreAuthorize para proteger métodos según el rol).
 * Define los beans (componentes gestionados por el contenedor de Spring) necesarios para el cifrado
 * de contraseñas, la gestión de autenticación y las reglas de filtrado HTTP mediante el SecurityFilterChain.
 *
 * @author Elías Maciel Villalva
 * @version 2.1
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /** Filtro personalizado que valida el token JWT en cada petición entrante. */
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Define el bean (componente administrado por el contenedor de Spring) para el cifrado
     * de contraseñas utilizando el algoritmo fuerte BCryptPasswordEncoder (función criptográfica
     * de hash unidireccional con sal aleatoria para máxima seguridad).
     *
     * @return Una instancia de PasswordEncoder (interfaz para codificación de credenciales) basada en BCrypt.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Define el AuthenticationManager (administrador de autenticación central encargado de procesar
     * y validar las credenciales de los usuarios) extrayendo la configuración global por defecto del sistema.
     *
     * @param authenticationConfiguration Configuración global de autenticación provista por Spring.
     * @return El administrador de autenticación listo para ser utilizado en el controlador de login.
     * @throws Exception Si ocurre algún error al obtener el gestor de autenticación.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Configura el SecurityFilterChain (cadena de filtros de seguridad HTTP) que intercepta
     * todas las peticiones web entrantes para aplicar reglas de acceso, desactivar protecciones
     * innecesarias para arquitecturas REST, devolver errores 401/403 en formato JSON y registrar
     * el filtro personalizado de JWT.
     *
     * @param http Objeto HttpSecurity (constructor DSL para configurar la seguridad web HTTP) provisto por Spring.
     * @return La cadena de filtros de seguridad configurada y lista para operar.
     * @throws Exception Si ocurre un error durante la configuración de las reglas HTTP.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Desactivar CSRF (Cross-Site Request Forgery, falsificación de peticiones en sitios cruzados):
                // al utilizar JWT en una API REST stateless no se mantienen cookies de sesión en el navegador.
                .csrf(csrf -> csrf.disable())

                // Reglas de autorización (permisos de acceso) para las rutas HTTP entrantes.
                .authorizeHttpRequests(auth -> auth
                        // Únicamente login y registro son públicos. El resto, incluido /me, exige un token válido.
                        .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/register").permitAll()
                        // /error debe ser accesible para que Spring pueda renderizar sus páginas de error.
                        .requestMatchers("/error").permitAll()
                        // Documentación OpenAPI / Swagger UI.
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        // Cualquier otra petición HTTP requiere que el usuario esté autenticado.
                        .anyRequest().authenticated()
                )

                // Política de sesiones STATELESS (sin estado): el servidor no crea ni almacena sesiones HTTP,
                // toda la identidad del usuario viaja en el token JWT.
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Respuestas JSON coherentes: 401 cuando falta o es inválido el token, 403 cuando no hay permisos.
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, e) ->
                                escribirError(response, 401, "Unauthorized", "Token ausente, inválido o expirado"))
                        .accessDeniedHandler((request, response, e) ->
                                escribirError(response, 403, "Forbidden", "No tenés permisos para acceder a este recurso"))
                )

                // Se agrega el filtro JWT antes del filtro por defecto de usuario y contraseña.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Escribe directamente en la respuesta HTTP un error en formato JSON. Se usa en los manejadores
     * de Spring Security, que actúan antes de llegar a los controladores y por eso no pasan por
     * el GlobalExceptionHandler.
     *
     * @param response Respuesta HTTP a completar.
     * @param status Código de estado HTTP (401 o 403).
     * @param error Nombre corto del error.
     * @param message Mensaje descriptivo para el cliente.
     * @throws IOException Si falla la escritura en la respuesta.
     */
    private static void escribirError(HttpServletResponse response, int status, String error, String message)
            throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(
                "{\"status\":" + status + ",\"error\":\"" + error + "\",\"message\":\"" + message + "\"}");
    }
}
