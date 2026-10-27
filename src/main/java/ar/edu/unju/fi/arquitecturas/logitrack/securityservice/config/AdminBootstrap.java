package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.config;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Rol;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Usuario;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.repository.UsuarioRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Componente (clase administrada por el contenedor de Spring) que se ejecuta una vez al arrancar la
 * aplicación (CommandLineRunner) y crea un usuario ADMIN inicial. Solo actúa si se configuraron las
 * variables de entorno ADMIN_USERNAME y ADMIN_PASSWORD y si ese usuario todavía no existe.
 * Resuelve el problema de "quién crea al primer administrador" sin dejar credenciales en el código.
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
@Slf4j
@Component
public class AdminBootstrap implements CommandLineRunner {

    /** Repositorio para consultar y persistir usuarios. */
    @Autowired
    private UsuarioRepository usuarioRepository;

    /** Codificador BCrypt para cifrar la contraseña del administrador inicial. */
    @Autowired
    private PasswordEncoder encoder;

    /** Nombre de usuario del administrador inicial (vacío = no se crea ninguno). */
    @Value("${logitrack.bootstrap-admin.username:}")
    private String username;

    /** Contraseña en texto plano del administrador inicial, proveniente de una variable de entorno. */
    @Value("${logitrack.bootstrap-admin.password:}")
    private String password;

    /** Correo electrónico del administrador inicial. */
    @Value("${logitrack.bootstrap-admin.email:admin@logitrack.local}")
    private String email;

    /**
     * Crea el usuario ADMIN inicial si corresponde.
     *
     * @param args Argumentos de línea de comandos (no se utilizan).
     */
    @Override
    public void run(String... args) {
        // Sin credenciales configuradas no se hace nada.
        if (username.isBlank() || password.isBlank()) {
            return;
        }
        // Si el usuario o el email ya existen, no se vuelve a crear.
        if (usuarioRepository.existsByUsername(username) || usuarioRepository.existsByEmail(email)) {
            return;
        }
        Usuario admin = new Usuario();
        admin.setUsername(username);
        admin.setEmail(email);
        admin.setPassword(encoder.encode(password));
        admin.setRoles(Set.of(Rol.ADMIN));
        usuarioRepository.save(admin);
        log.info("Usuario ADMIN inicial '{}' creado.", username);
    }
}
