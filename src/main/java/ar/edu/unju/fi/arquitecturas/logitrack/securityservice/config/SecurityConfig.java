package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.config;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.filter.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Clase de configuración principal para la seguridad web utilizando @Configuration
 * y @EnableWebSecurity. Define los beans necesarios para el cifrado de contraseñas,
 * la gestión de autenticación, las reglas de filtrado HTTP mediante el SecurityFilterChain
 * y habilita la seguridad basada en anotaciones a nivel de métodos con @EnableMethodSecurity.
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity // <-- ¡Habilita @PreAuthorize a nivel de métodos!
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Define el bean para el cifrado de contraseñas utilizando el algoritmo fuerte BCryptPasswordEncoder.
     *
     * @return Una instancia de PasswordEncoder basada en BCrypt.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Define el AuthenticationManager encargado de procesar y validar las credenciales de los usuarios.
     *
     * @param authenticationConfiguration Configuración global de autenticación provista por Spring.
     * @return El administrador de autenticación.
     * @throws Exception Si ocurre algún error al obtener el gestor.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Configura el SecurityFilterChain que intercepta todas las peticiones web entrantes
     * para aplicar reglas de acceso, configurar estado stateless e integrar el filtro JWT.
     *
     * @param http Objeto HttpSecurity provisto por Spring.
     * @return La cadena de filtros de seguridad configurada.
     * @throws Exception Si ocurre un error durante la configuración.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Desactivar CSRF ya que usamos tokens JWT sin estado
                .csrf(csrf -> csrf.disable())

                // Configurar las reglas de autorización para las rutas HTTP entrantes
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )

                // Configurar la gestión de sesiones como STATELESS
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Agregar nuestro filtro JWT personalizado antes del filtro de autenticación por usuario/contraseña
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}