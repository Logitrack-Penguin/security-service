package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.util;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Rol;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

/**
 * Componente (clase administrada por el contenedor de Spring) utilitario para la gestión integral de
 * JSON Web Tokens (JWT). Genera tokens firmados con HS256 que incluyen el subject (username), el claim
 * "userId", el claim "roles" y el emisor (iss), de modo que shipment-service y courier-service puedan
 * autorizar verificando únicamente la firma y el emisor, sin consultar a security-service en cada solicitud.
 *
 * @author Elías Maciel Villalva
 * @version 2.1
 */
@Slf4j
@Component
public class JwtUtil {

    /**
     * Llave secreta (clave criptográfica simétrica) en formato Base64, inyectada por variable de
     * entorno (JWT_SECRET). No tiene valor por defecto: si falta, la aplicación no arranca.
     * Debe ser la misma en todos los microservicios que validen tokens.
     */
    @Value("${logitrack.jwt.secret}")
    private String jwtSecret;

    /** Tiempo de expiración (vencimiento) de los tokens en milisegundos (por defecto 1 hora). */
    @Value("${logitrack.jwt.expiration-ms:3600000}")
    private long jwtExpirationMs;

    /**
     * Emisor del token (claim "iss"). Los demás microservicios deben exigir este mismo valor
     * al validar, para rechazar tokens firmados por otro emisor.
     */
    @Value("${logitrack.jwt.issuer:logitrack-security-service}")
    private String issuer = "logitrack-security-service";

    /**
     * Decodifica la clave Base64 y construye la SecretKey utilizada para firmar y verificar tokens.
     *
     * @return La clave HMAC de firma.
     */
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    /**
     * Genera un nuevo token JWT firmado a partir de un usuario autenticado.
     *
     * @param usuario Entidad del usuario cuyos datos se incluyen en el token.
     * @return El token JWT compacto en formato String.
     */
    public String generateToken(Usuario usuario) {
        List<String> roles = usuario.getRoles().stream().map(Rol::name).sorted().toList();
        Date ahora = new Date();
        return Jwts.builder()
                .issuer(issuer)
                .subject(usuario.getUsername())
                .claim("userId", usuario.getId().toString())
                .claim("roles", roles)
                .issuedAt(ahora)
                .expiration(new Date(ahora.getTime() + jwtExpirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Extrae el nombre de usuario (subject, identificador principal del propietario) del token.
     *
     * @param token El token JWT.
     * @return El nombre de usuario asociado al token.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Método genérico (reutilizable para cualquier tipo de dato) para extraer un claim (dato del payload)
     * aplicando una función de resolución (interfaz funcional).
     *
     * @param token El token JWT.
     * @param claimsResolver Expresión funcional para extraer el campo deseado.
     * @param <T> Tipo de dato del claim a retornar.
     * @return El valor del claim extraído.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    /**
     * Analiza el token verificando su firma, su vigencia y su emisor, y devuelve su payload.
     * Lanza una JwtException si la firma no coincide, el token está mal formado, ya expiró
     * o fue emitido por otro emisor.
     *
     * @param token El token JWT firmado.
     * @return Los claims (carga útil) del token.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .requireIssuer(issuer)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Valida el token: comprueba la firma, la fecha de expiración y que el username
     * coincida con el del UserDetails cargado desde la base de datos.
     *
     * @param token El token JWT a validar.
     * @param userDetails La información del usuario cargada en el sistema.
     * @return true si el token es auténtico, está vigente y pertenece al usuario; false en caso contrario.
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            return extractUsername(token).equals(userDetails.getUsername());
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Token JWT inválido: {}", e.getMessage());
            return false;
        }
    }
}
