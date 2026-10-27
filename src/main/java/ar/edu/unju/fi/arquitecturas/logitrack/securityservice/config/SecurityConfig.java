package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Clase de configuración principal para Spring Security.
 * Define la cadena de filtros, el cifrado de contraseñas, el gestor de autenticación
 * y habilita la seguridad basada en anotaciones a nivel de métodos.
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity // <-- ¡Esta es la clave para que funcione @PreAuthorize!
public class SecurityConfig {

    /**
     * Define el bean para el cifrado de contraseñas utilizando BCrypt.
     *
     * @return PasswordEncoder basado en BCrypt.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Define el bean del AuthenticationManager necesario para autenticar credenciales.
     *
     * @param authConfig Configuración de autenticación de Spring.
     * @return AuthenticationManager configurado.
     * @throws Exception en caso de error al obtener el gestor.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * Configura la cadena de filtros de seguridad HTTP (SecurityFilterChain).
     *
     * @param http Objeto HttpSecurity para configurar reglas de acceso.
     * @return SecurityFilterChain configurado.
     * @throws Exception en caso de error de configuración.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Deshabilita CSRF ya que usamos tokens JWT sin estado
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Sin sesiones HTTP
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll() // Endpoints públicos de login y registro
                        .anyRequest().authenticated() // Cualquier otro endpoint requiere estar autenticado
                );

        return http.build();
    }
}