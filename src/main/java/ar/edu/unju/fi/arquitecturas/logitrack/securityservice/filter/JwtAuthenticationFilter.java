package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.filter;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro de seguridad (componente que intercepta las peticiones HTTP entrantes)
 * que se ejecuta una vez por cada solicitud (OncePerRequestFilter).
 * Se encarga de capturar el token JWT de la cabecera HTTP, validar su autenticidad
 * y establecer la sesión del usuario en el contexto de seguridad de Spring.
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * Intercepta la petición HTTP para verificar la presencia y validez de un token JWT
     * en la cabecera Authorization antes de que la solicitud llegue al controlador.
     *
     * @param request Petición HTTP recibida desde el cliente.
     * @param response Respuesta HTTP que se enviará de regreso.
     * @param filterChain Cadena de filtros de seguridad por donde fluye la petición.
     * @throws ServletException Si ocurre un error relacionado con el servlet.
     * @throws IOException Si ocurre un error de entrada/salida.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        // Validar si la cabecera Authorization existe y comienza con el prefijo "Bearer "
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            try {
                username = jwtUtil.extractUsername(jwt);
            } catch (Exception e) {
                logger.error("No se pudo extraer el username del token JWT: " + e.getMessage());
            }
        }

        // Si se obtuvo el username y el contexto de seguridad aún no tiene una autenticación activa
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // Validar el token utilizando el componente JwtUtil
            if (jwtUtil.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Establecer la autenticación oficial en el contexto de Spring Security
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // Continuar con el siguiente filtro en la cadena de ejecución
        filterChain.doFilter(request, response);
    }
}