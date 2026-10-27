package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.controller;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.JwtResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.LoginRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.RegistroRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.UserResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Rol;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Usuario;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.repository.UsuarioRepository;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.util.JwtUtil;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Controlador REST (componente encargado de exponer endpoints web para recibir peticiones HTTP
 * y retornar respuestas JSON) para la gestión de autenticación, registro y consulta del usuario actual.
 * Los errores se resuelven de forma centralizada en el GlobalExceptionHandler.
 *
 * @author Elías Maciel Villalva
 * @version 2.0
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    /** Administrador de autenticación de Spring Security que valida las credenciales. */
    @Autowired
    private AuthenticationManager authenticationManager;

    /** Repositorio de acceso a los usuarios persistidos. */
    @Autowired
    private UsuarioRepository usuarioRepository;

    /** Codificador de contraseñas (BCrypt). */
    @Autowired
    private PasswordEncoder encoder;

    /** Utilidad para generar y validar tokens JWT. */
    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Endpoint (punto de entrada HTTP) para autenticar a un usuario en el sistema.
     * Valida las credenciales mediante el gestor de autenticación y retorna un token JWT
     * que incluye el id y los roles del usuario.
     *
     * @param request DTO con el nombre de usuario y la contraseña.
     * @return Respuesta HTTP 200 (OK) con el JwtResponse; 401 si las credenciales son incorrectas.
     */
    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@Valid @RequestBody LoginRequest request) {
        // Lanza AuthenticationException (401) si las credenciales no son correctas.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        Usuario usuario = usuarioRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas"));

        String jwt = jwtUtil.generateToken(usuario);
        List<String> roles = usuario.getRoles().stream().map(Rol::name).sorted().toList();

        log.info("Login exitoso para el usuario: {}", usuario.getUsername());
        return ResponseEntity.ok(new JwtResponse(jwt, usuario.getId().toString(), usuario.getUsername(), roles));
    }

    /**
     * Endpoint para registrar un nuevo usuario. Verifica que el username y el email no estén en uso,
     * cifra la contraseña con BCrypt y persiste el usuario. Si no se envían roles se asigna CLIENTE.
     * Crear un usuario con rol ADMIN solo está permitido si quien realiza la petición ya es ADMIN.
     *
     * @param request DTO con username, password, email y roles solicitados.
     * @return Respuesta HTTP 201 (Created) con el usuario creado; 409 si ya existe; 403 si intenta crear un ADMIN sin serlo.
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegistroRequest request) {
        // Validar la unicidad del nombre de usuario y del correo electrónico.
        if (usuarioRepository.existsByUsername(request.getUsername())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El nombre de usuario ya está en uso");
        }
        if (usuarioRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El correo electrónico ya está en uso");
        }

        // Convertir los nombres de rol recibidos a la enumeración Rol.
        Set<Rol> roles = parseRoles(request.getRoles());

        // Evitar la escalada de privilegios: un registro público no puede crear administradores.
        if (roles.contains(Rol.ADMIN) && !callerIsAdmin()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Solo un administrador puede crear usuarios ADMIN");
        }

        // Crear la entidad y cifrar la contraseña con BCrypt antes de persistir.
        Usuario usuario = new Usuario();
        usuario.setUsername(request.getUsername());
        usuario.setEmail(request.getEmail());
        usuario.setPassword(encoder.encode(request.getPassword()));
        usuario.setRoles(roles);
        usuarioRepository.save(usuario);

        log.info("Usuario '{}' registrado con roles {}", usuario.getUsername(), roles);
        return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.from(usuario));
    }

    /**
     * Endpoint que devuelve la información del usuario dueño del token (consulta del usuario autenticado).
     *
     * @param authentication Autenticación actual, inyectada por Spring Security.
     * @return Respuesta HTTP 200 con id, username, email y roles; 404 si el usuario ya no existe.
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(Authentication authentication) {
        Usuario usuario = usuarioRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
        return ResponseEntity.ok(UserResponse.from(usuario));
    }

    /**
     * Ejemplo de autorización basada en roles: solo accesible para ADMIN.
     * hasRole agrega automáticamente el prefijo ROLE_ (la autoridad real es ROLE_ADMIN).
     *
     * @return Mensaje de bienvenida al panel de administración.
     */
    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminDashboard() {
        return ResponseEntity.ok("Bienvenido al panel de administración de Logitrack.");
    }

    /**
     * Ejemplo de autorización basada en roles: accesible para ADMIN y REPARTIDOR.
     *
     * @return Mensaje con el listado de envíos asignados.
     */
    @GetMapping("/repartidor/envios")
    @PreAuthorize("hasAnyRole('ADMIN', 'REPARTIDOR')")
    public ResponseEntity<String> enviosRepartidor() {
        return ResponseEntity.ok("Listado de envíos asignados.");
    }

    /**
     * Convierte los nombres de rol recibidos (sin importar mayúsculas) en valores de la enumeración Rol.
     *
     * @param nombres Nombres de rol enviados por el cliente; si es nulo o vacío se asigna CLIENTE.
     * @return Conjunto de roles válidos.
     * @throws ResponseStatusException 400 si algún nombre no corresponde a un rol existente.
     */
    private Set<Rol> parseRoles(Set<String> nombres) {
        Set<Rol> roles = new HashSet<>();
        if (nombres == null || nombres.isEmpty()) {
            roles.add(Rol.CLIENTE);
            return roles;
        }
        for (String nombre : nombres) {
            try {
                roles.add(Rol.valueOf(nombre.trim().toUpperCase()));
            } catch (IllegalArgumentException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Rol inválido: '" + nombre + "'. Valores permitidos: " + Arrays.toString(Rol.values()));
            }
        }
        return roles;
    }

    /**
     * Indica si quien realiza la petición actual está autenticado y tiene el rol ADMIN.
     *
     * @return true si el solicitante es administrador, false en caso contrario.
     */
    private boolean callerIsAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.isAuthenticated()
                && auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }
}
