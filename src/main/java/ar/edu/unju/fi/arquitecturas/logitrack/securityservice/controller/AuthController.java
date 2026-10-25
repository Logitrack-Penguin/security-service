package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.controller;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.JwtResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.LoginRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.RegistroRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Rol;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Usuario;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.repository.UsuarioRepository;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.util.JwtUtil;
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

        return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(), roles));
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

        // Validar si el nombre de usuario ya se encuentra registrado en el sistema.
        if (usuarioRepository.existsByUsername(registroRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body("Error: ¡El nombre de usuario ya está en uso!");
        }

        // Crear una nueva entidad Usuario y cifrar su contraseña utilizando el PasswordEncoder (BCrypt).
        Usuario usuario = new Usuario();
        usuario.setUsername(registroRequest.getUsername());
        usuario.setPassword(encoder.encode(registroRequest.getPassword()));

        Set<String> strRoles = registroRequest.getRoles();
        Set<Rol> roles = new HashSet<>();

        // Validar y asignar los roles correspondientes al usuario.
        if (strRoles == null) {
            Rol adminRole = Rol.ADMIN; // O el rol por defecto que prefieras en tu modelo
            roles.add(adminRole);
        } else {
            strRoles.forEach(role -> {
                switch (role.toLowerCase()) {
                    case "admin":
                        roles.add(Rol.ADMIN);
                        break;
                    default:
                        roles.add(Rol.ADMIN); // Rol por defecto por seguridad
                }
            });
        }

        usuario.setRoles(roles);

        // Guardar el usuario en la base de datos a través del repositorio.
        usuarioRepository.save(usuario);

        return ResponseEntity.ok("¡Usuario registrado exitosamente!");
    }
}