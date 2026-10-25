package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Componente (clase administrada por el contenedor de Spring) utilitario para la gestión integral de JSON Web Tokens (JWT).
 * Proporciona métodos para la generación, extracción de claims (datos almacenados en el payload), validación
 * de identidad y verificación de vigencia de los tokens de acceso.
 *
 * @author Logitrack PenguinD
 * @version 1.0
 */
@Component
public class JwtUtil {

    /** Llave secreta (clave criptográfica simétrica) generada automáticamente para el algoritmo HS256. */
    private final SecretKey secretKey = Jwts.SIG.HS256.key().build();

    /** Tiempo de expiración (vencimiento) configurado para los tokens en milisegundos (36000000ms equivalentes a 10 horas). */
    private final long jwtExpirationMs = 36000000;

    /**
     * Extrae el nombre de usuario (subject, identificador principal del propietario) contenido en los claims (datos) del token.
     *
     * @param token El token JWT del cual se extraerá el username.
     * @return El nombre de usuario asociado al token.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extrae la fecha de expiración (vencimiento) contenida en los claims del token.
     *
     * @param token El token JWT a evaluar.
     * @return La fecha y hora límite de validez del token.
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Método genérico (reutilizable para cualquier tipo de dato) para extraer un claim (información específica) aplicando una función de resolución (interfaz funcional).
     *
     * @param token El token JWT.
     * @param claimsResolver Expresión funcional para extraer el campo deseado de los claims.
     * @param <T> Tipo de dato del claim a retornar.
     * @return El valor del claim extraído.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Analiza y decodifica el token firmado utilizando la clave secreta para obtener todos sus claims (la carga útil o payload del token).
     *
     * @param token El token JWT firmado.
     * @return Objeto Claims que contiene la estructura de datos interna del token.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Verifica si el token ha superado su fecha de expiración (vencimiento).
     *
     * @param token El token JWT.
     * @return true si la fecha de expiración es anterior al momento actual, false en caso contrario.
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Genera un nuevo token JWT a partir de los datos del usuario autenticado (UserDetails).
     *
     * @param userDetails Objeto UserDetails que contiene las credenciales y roles del usuario.
     * @return Una cadena de texto (String) correspondiente al token JWT generado y firmado.
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    /**
     * Construye y firma digitalmente el token JWT estableciendo los claims (datos), el subject (sujeto),
     * la fecha de emisión y la fecha de expiración (vencimiento).
     *
     * @param claims Mapa (estructura de clave-valor) con información adicional a incluir en el payload.
     * @param subject El identificador principal (username) del usuario.
     * @return El token JWT compacto en formato String.
     */
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(secretKey)
                .compact();
    }

    /**
     * Valida la integridad del token comprobando que el username coincida
     * con el de UserDetails y que el token no se encuentre expirado (vencido).
     *
     * @param token El token JWT a validar.
     * @param userDetails La información del usuario cargada en el sistema.
     * @return true si el token es válido y pertenece al usuario, false en caso contrario.
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}