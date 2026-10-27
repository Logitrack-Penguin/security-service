package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.util;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Rol;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Usuario;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pruebas unitarias de JwtUtil: no necesitan base de datos ni contexto de Spring.
 * Verifican que un token válido se acepta y que uno alterado o expirado se rechaza.
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
class JwtUtilTest {

    private static final String SECRET = "Y2xhdmUtZGUtcHJ1ZWJhLWRlLWFsLW1lbm9zLTMyLWJ5dGVzIQ==";

    private JwtUtil jwtUtil;
    private Usuario usuario;
    private UserDetails userDetails;

    /** Prepara un JwtUtil con clave de prueba, un usuario y su UserDetails equivalente. */
    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "jwtSecret", SECRET);
        ReflectionTestUtils.setField(jwtUtil, "jwtExpirationMs", 60_000L);
        usuario = Usuario.builder().id(UUID.randomUUID()).username("maria")
                .email("maria@mail.com").password("x").roles(Set.of(Rol.CLIENTE)).build();
        userDetails = User.withUsername("maria").password("x").authorities("ROLE_CLIENTE").build();
    }

    /** Un token recién generado contiene el username y el userId, y es aceptado. */
    @Test
    void tokenGeneradoEsValidoYContieneClaims() {
        String token = jwtUtil.generateToken(usuario);

        assertEquals("maria", jwtUtil.extractUsername(token));
        assertEquals(usuario.getId().toString(), jwtUtil.extractClaim(token, c -> c.get("userId", String.class)));
        assertTrue(jwtUtil.validateToken(token, userDetails));
    }

    /** Si se modifica la firma del token, la validación debe fallar (integridad). */
    @Test
    void tokenAlteradoEsRechazado() {
        String token = jwtUtil.generateToken(usuario);
        String alterado = token.substring(0, token.length() - 2) + "xx";

        assertFalse(jwtUtil.validateToken(alterado, userDetails));
    }

    /** Un token con vigencia negativa ya nace vencido y debe ser rechazado (expiración). */
    @Test
    void tokenExpiradoEsRechazado() {
        ReflectionTestUtils.setField(jwtUtil, "jwtExpirationMs", -1000L);
        String token = jwtUtil.generateToken(usuario);

        assertFalse(jwtUtil.validateToken(token, userDetails));
    }
}
