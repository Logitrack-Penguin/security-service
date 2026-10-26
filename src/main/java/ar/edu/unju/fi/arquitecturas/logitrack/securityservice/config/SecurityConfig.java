package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Clase de configuración global para la seguridad del microservicio.
 * Define los beans necesarios para el cifrado de credenciales y las políticas
 * de autenticación dentro del contexto de Spring Security.
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@Configuration
public class SecurityConfig {

    /**
     * Registra un bean de tipo PasswordEncoder utilizando el algoritmo BCrypt.
     * Es fundamental para realizar el hashing irreversible de las contraseñas
     * antes de almacenarlas en la base de datos y para compararlas de forma segura en el login.
     *
     * @return Una instancia de BCryptPasswordEncoder lista para ser inyectada.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}