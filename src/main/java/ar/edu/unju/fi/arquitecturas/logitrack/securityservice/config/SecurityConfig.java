package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.config;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.filter.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Clase de configuración principal para la seguridad web utilizando @Configuration
 * (anotación que indica que la clase contiene definiciones de beans y configuraciones de Spring)
 * y @EnableWebSecurity (anotación para habilitar y personalizar la seguridad web de Spring Security).
 * Define los beans (componentes gestionados por el contenedor de Spring) necesarios para el cifrado
 * de contraseñas, la gestión de autenticación y las reglas de filtrado HTTP mediante el SecurityFilterChain.
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

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
     * @return El administrador de autenticación listo para ser utilizado en los controladores de login.
     * @throws Exception Si ocurre algún error al obtener el gestor de autenticación.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Configura el SecurityFilterChain (cadena de filtros de seguridad HTTP) que intercepta
     * todas las peticiones web entrantes para aplicar reglas de acceso, desactivar protecciones
     * innecesarias para arquitecturas REST y registrar el filtro personalizado de JWT.
     *
     * @param http Objeto HttpSecurity (constructor DSL para configurar la seguridad web HTTP) provisto por Spring.
     * @return La cadena de filtros de seguridad configurada y lista para operar.
     * @throws Exception Si ocurre un error durante la configuración de las reglas HTTP.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Desactivar CSRF (Cross-Site Request Forgery, protección contra falsificación de peticiones en sitios cruzados)
                // ya que al utilizar JWT en arquitecturas REST stateless no se requiere mantener cookies de sesión en el navegador.
                .csrf(csrf -> csrf.disable())

                // Configurar las reglas de autorización (permisos de acceso) para las rutas HTTP entrantes.
                .authorizeHttpRequests(auth -> auth
                        // Permitir acceso público sin autenticación a todos los endpoints (rutas web) del prefijo de autenticación (/api/auth/**).
                        .requestMatchers("/api/auth/**").permitAll()
                        // Cualquier otra petición HTTP requerirá obligatoriamente que el usuario esté autenticado con un token válido.
                        .anyRequest().authenticated()
                )

                // Configurar la gestión de sesiones como STATELESS (sin estado, política donde el servidor no crea
                // ni almacena sesiones HTTP en memoria para los usuarios, delegando toda la persistencia de identidad al token JWT).
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Agregar nuestro filtro JWT personalizado (jwtAuthenticationFilter) antes de que se ejecute el filtro
                // por defecto de autenticación por usuario y contraseña (UsernamePasswordAuthenticationFilter).
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}