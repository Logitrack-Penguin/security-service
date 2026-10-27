package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.controller;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.JwtResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.LoginRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.RegistroRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.UserResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Rol;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Usuario;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.repository.UsuarioRepository;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Controlador REST (componente encargado de exponer endpoints web para recibir peticiones HTTP
 * y retornar respuestas JSON) para la gestión de autenticación, registro y acceso de usuarios.
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Endpoint (punto de entrada HTTP) para autenticar a un usuario en el sistema.
     * Recibe las credenciales (username y password), valida su autenticidad mediante el gestor
     * de autenticación y retorna un token JWT junto con los roles correspondientes.
     *
     * @param loginRequest Objeto DTO que contiene el nombre de usuario y la contraseña.
     * @return Una respuesta HTTP 200 (OK) con el objeto JwtResponse que incluye el token de acceso.
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        log.info("Intento de inicio de sesión recibido para el usuario: {}", loginRequest.getUsername());
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String jwt = jwtUtil.generateToken(userDetails);

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());
            log.info("Autenticación exitosa para el usuario: {}. Token JWT generado correctamente.", loginRequest.getUsername());
            return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(), roles));
        } catch (Exception e) {
            log.error("Fallo en la autenticación para el usuario {}: {}", loginRequest.getUsername(), e.getMessage());
            throw e;
        }
    }

    /**
     * Endpoint para registrar un nuevo usuario en el sistema.
     * Recibe los datos de registro, verifica la disponibilidad del username, cifra la contraseña
     * utilizando BCrypt y persiste el nuevo registro con sus respectivos roles en la base de datos.
     *
     * @param registroRequest Objeto DTO con el username, password y los roles solicitados.
     * @return Una respuesta HTTP indicando el éxito del registro o un mensaje de error si ya existe.
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegistroRequest registroRequest) {
        log.info("Solicitud de registro recibida para el nuevo usuario: {}", registroRequest.getUsername());
        // Validar si el nombre de usuario ya se encuentra registrado en el sistema.
        if (usuarioRepository.existsByUsername(registroRequest.getUsername())) {
            log.warn("Intento de registro fallido: el nombre de usuario '{}' ya se encuentra en uso.", registroRequest.getUsername());
            return ResponseEntity
                    .badRequest()
                    .body("Error: ¡El nombre de usuario ya está en uso!");
        }
        if (usuarioRepository.existsByEmail(registroRequest.getEmail())) {
            log.warn("Intento de registro fallido: el correo electrónico '{}' ya se encuentra registrado.", registroRequest.getEmail());
            return ResponseEntity
                    .badRequest()
                    .body("Error: ¡El correo electrónico ya está en uso!");
        }

        // Crear una nueva entidad Usuario y cifrar su contraseña utilizando el PasswordEncoder (BCrypt).
        Usuario usuario = new Usuario();
        usuario.setUsername(registroRequest.getUsername());
        usuario.setEmail(registroRequest.getEmail());
        usuario.setPassword(encoder.encode(registroRequest.getPassword()));

        Set<String> strRoles = registroRequest.getRoles();
        Set<Rol> roles = new HashSet<>();

        // Validar y asignar los roles correspondientes al usuario.
        if (strRoles == null || strRoles.isEmpty()) {
            roles.add(Rol.CLIENTE);
        } else {
            strRoles.forEach(role -> {
                switch (role.toLowerCase()) {
                    case "ADMIN":
                        roles.add(Rol.ADMIN);
                        break;
                    case "CLIENTE":
                        roles.add(Rol.CLIENTE);
                        break;
                    case "REPARTIDOR":
                        roles.add(Rol.REPARTIDOR);
                        break;
                    default:
                        roles.add(Rol.CLIENTE); // Rol por defecto por seguridad
                }
            });
        }

        usuario.setRoles(roles);

        // Guardar el usuario en la base de datos a través del repositorio.
        usuarioRepository.save(usuario);
        log.info("Usuario '{}' registrado y persistido exitosamente en la base de datos.", registroRequest.getUsername());
        return ResponseEntity.ok("¡Usuario registrado exitosamente!");
    }
    /**
     * Permite al usuario autenticado consultar su propia información de perfil
     * a partir del token JWT enviado en la cabecera de la petición.
     *
     * @return ResponseEntity con los datos del usuario (username, email, roles).
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUserProfile() {
        log.info("Solicitud recibida para consultar el perfil del usuario actual (/me)");

        // Obtiene la autenticación actual del contexto de seguridad de Spring
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("Intento de acceso a /me sin credenciales válidas en el contexto.");
            return ResponseEntity.status(401).body("Error: No autorizado");
        }

        String username = authentication.getName();

        // Busca el usuario en la base de datos
        Usuario usuario = usuarioRepository.findByUsername(username)
                .orElse(null);

        if (usuario == null) {
            log.error("Usuario con username '{}' no encontrado en la base de datos.", username);
            return ResponseEntity.status(404).body("Error: Usuario no encontrado");
        }

        // Mapea los roles del usuario a formato String
        Set<String> roles = usuario.getRoles().stream()
                .map(rol -> rol.name())
                .collect(Collectors.toSet());

        UserResponse response = new UserResponse(usuario.getUsername(), usuario.getEmail(), roles);

        log.info("Perfil devuelto exitosamente para el usuario: {}", username);
        return ResponseEntity.ok(response);
    }
}