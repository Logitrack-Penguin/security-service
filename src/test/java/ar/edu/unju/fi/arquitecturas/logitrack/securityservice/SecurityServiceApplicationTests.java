package ar.edu.unju.fi.arquitecturas.logitrack.securityservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Prueba de humo que verifica que el contexto completo de Spring arranca correctamente.
 * Usa el perfil "test" (H2 en memoria, clave JWT de prueba y Config Server deshabilitado),
 * por lo que no depende de MySQL ni de variables de entorno.
 *
 * @author Logitrack Penguin
 * @version 1.1
 */
@SpringBootTest
@ActiveProfiles("test")
class SecurityServiceApplicationTests {

    /** Verifica que todos los beans se crean sin errores. */
    @Test
    void contextLoads() {
    }
}
