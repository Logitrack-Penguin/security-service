package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.function.Function;

/**
 * Utilidad criptográfica para la generación, firma y validación de tokens JWT (JSON Web Tokens).
 * Utiliza la librería JJWT (v0.12.6) y una clave secreta estática compartida para permitir 
 * la validación de identidad entre los microservicios de la plataforma Logitrack.
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
@Slf4j
@Component
public class JwtUtil {

    /** Clave secreta estática inyectada desde las propiedades de configuración. */
    @Value("${logitrack.app.jwtSecret}")
    private String jwtSecret;

    /** Tiempo de expiración del token en milisegundos, inyectado desde la configuración. */
    @Value("${logitrack.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    /**
     * Obtiene y procesa la clave secreta criptográfica a partir del texto configurado
     * para adaptarla a los algoritmos de firma HMAC-SHA de JJWT.
     *
     * @return SecretKey firmada y lista para criptografía simétrica.
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Genera un token JWT estandarizado a partir de los detalles de sesión del usuario autenticado.
     *
     * @param userDetails Objeto UserDetails que contiene las credenciales y autoridades del usuario en Spring Security.
     * @return Token JWT firmado en formato String listo para ser devuelto en la respuesta HTTP.
     */
    public String generateToken(UserDetails userDetails) {
        log.debug("Generando token JWT para el usuario: {}", userDetails.getUsername());
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Extrae el nombre de usuario (subject) contenido dentro de las declaraciones (claims) del token JWT.
     *
     * @param token Cadena de texto que representa el token JWT.
     * @return Nombre de usuario asociado al token.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extrae una propiedad (claim) específica del token utilizando una función genérica de resolución.
     *
     * @param token Cadena de texto que representa el token JWT.
     * @param claimsResolver Función funcional para extraer el claim deseado del cuerpo del token.
     * @param <T> Tipo de dato devuelto por el claim.
     * @return El valor del claim extraído.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extrae todas las declaraciones (claims/cuerpo) del token JWT, verificando previamente
     * su integridad y su firma criptográfica mediante la clave secreta compartida.
     *
     * @param token Cadena de texto que representa el token JWT.
     * @return Objeto Claims que contiene toda la información útil almacenada en el token.
     * @throws JwtException si el token es inválido, ha expirado o su firma no coincide.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Valida la autenticidad y vigencia de un token JWT contrastándolo con los detalles del usuario.
     *
     * @param token Cadena de texto que representa el token JWT.
     * @param userDetails Objeto UserDetails del usuario actual para validar correspondencia.
     * @return true si el token es estructural y temporalmente válido y pertenece al usuario; false en caso contrario.
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            boolean isValid = username.equals(userDetails.getUsername()) && !isTokenExpired(token);
            if (!isValid) {
                log.warn("Token JWT inválido o expirado para el usuario: {}", username);
            }
            return isValid;
        } catch (JwtException | IllegalArgumentException e) {
            log.error("Fallo crítico al procesar y validar el token JWT: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Verifica si el token JWT ha superado su tiempo de vida configurado.
     *
     * @param token Cadena de texto que representa el token JWT.
     * @return true si la fecha de expiración del token es anterior a la fecha actual; false si sigue activo.
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extrae específicamente la fecha y hora de expiración del token JWT.
     *
     * @param token Cadena de texto que representa el token JWT.
     * @return Objeto Date con el límite de validez temporal del token.
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}