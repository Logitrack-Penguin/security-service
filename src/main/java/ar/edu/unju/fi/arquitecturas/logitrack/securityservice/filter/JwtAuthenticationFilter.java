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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro de seguridad (componente que intercepta las peticiones HTTP entrantes)
 * que se ejecuta una vez por cada solicitud (OncePerRequestFilter).
 * Se encarga de capturar el token JWT de la cabecera HTTP, validar su autenticidad
 * y establecer la identidad del usuario en el contexto de seguridad de Spring.
 *
 * @author Elías Maciel Villalva
 * @version 2.0
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /** Utilidad para extraer datos y validar tokens JWT. */
    @Autowired
    private JwtUtil jwtUtil;

    /** Servicio que carga los datos del usuario desde la base de datos. */
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * Intercepta la petición HTTP para verificar la presencia y validez de un token JWT
     * en la cabecera Authorization antes de que la solicitud llegue al controlador.
     * Si el token es inválido, está vencido o pertenece a un usuario que ya no existe,
     * la petición continúa sin autenticar (y recibirá 401 si la ruta lo exige).
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

        String header = request.getHeader("Authorization");

        // Solo se procesa si existe la cabecera con el prefijo "Bearer " y aún no hay autenticación activa.
        if (header != null && header.startsWith("Bearer ")
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            String jwt = header.substring(7);
            try {
                String username = jwtUtil.extractUsername(jwt);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // Validar firma, vigencia y pertenencia del token.
                if (jwtUtil.validateToken(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Establecer la autenticación oficial en el contexto de Spring Security.
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            } catch (UsernameNotFoundException e) {
                logger.warn("Token de un usuario que ya no existe: " + e.getMessage());
            } catch (Exception e) {
                // Token mal formado, firma inválida o expirado.
                logger.warn("Token JWT rechazado: " + e.getMessage());
            }
        }

        // Continuar con el siguiente filtro en la cadena de ejecución.
        filterChain.doFilter(request, response);
    }
}
