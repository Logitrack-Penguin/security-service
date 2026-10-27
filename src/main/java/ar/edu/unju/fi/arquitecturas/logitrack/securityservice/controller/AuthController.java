package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.controller;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.JwtResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.LoginRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.RegistroRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.UserResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service.AuthService;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service.UsuarioService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * Controlador REST para la autenticación, el registro y la consulta del usuario autenticado.
 * Solo traduce HTTP ↔ DTOs: la lógica de negocio vive en {@link AuthService} y {@link UsuarioService},
 * y los errores se resuelven de forma centralizada en el GlobalExceptionHandler.
 *
 * @author Elías Maciel Villalva
 * @version 3.0
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Autenticación", description = "Login, registro y datos del usuario autenticado")
public class AuthController {

    /** Servicio con la lógica de login y registro. */
    private final AuthService authService;

    /** Servicio de consulta de usuarios. */
    private final UsuarioService usuarioService;

    /**
     * Autentica a un usuario y devuelve un token JWT que incluye su id y sus roles.
     *
     * @param request DTO con el nombre de usuario y la contraseña.
     * @return 200 (OK) con el JwtResponse; 400 si faltan datos; 401 si las credenciales son incorrectas.
     */
    @PostMapping("/login")
    @Operation(summary = "Iniciar sesión y obtener un token JWT")
    public ResponseEntity<JwtResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * Registra un nuevo usuario. Sin token solo se puede crear un CLIENTE; con un token de ADMIN
     * se pueden crear usuarios ADMIN o REPARTIDOR.
     *
     * @param request DTO con username, password, email y roles solicitados.
     * @param authentication Autenticación actual (puede ser nula si la petición no trae token).
     * @return 201 (Created) con el usuario creado; 400 si los datos son inválidos; 403 si pide un rol
     *         no permitido; 409 si el username o el email ya existen.
     */
    @PostMapping("/register")
    @Operation(summary = "Registrar un usuario",
            description = "Público para CLIENTE. Para ADMIN o REPARTIDOR se requiere un token de ADMIN.")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegistroRequest request,
                                                 Authentication authentication) {
        UserResponse creado = authService.registrar(request, esAdmin(authentication));
        return ResponseEntity.status(HttpStatus.CREATED).body(creado);
    }

    /**
     * Devuelve la información del usuario dueño del token.
     *
     * @param authentication Autenticación actual, inyectada por Spring Security.
     * @return 200 con id, username, email y roles; 401 sin token válido; 404 si el usuario ya no existe.
     */
    @GetMapping("/me")
    @Operation(summary = "Consultar el usuario autenticado")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<UserResponse> me(Authentication authentication) {
        return ResponseEntity.ok(usuarioService.obtenerPorUsername(authentication.getName()));
    }

    /**
     * Indica si la autenticación recibida corresponde a un usuario con rol ADMIN.
     *
     * @param authentication Autenticación de la petición actual (puede ser nula).
     * @return {@code true} si está autenticado y tiene la autoridad ROLE_ADMIN.
     */
    private boolean esAdmin(Authentication authentication) {
        return authentication != null && authentication.isAuthenticated()
                && authentication.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
    }
}
