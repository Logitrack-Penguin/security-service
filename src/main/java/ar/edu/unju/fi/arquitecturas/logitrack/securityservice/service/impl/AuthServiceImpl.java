package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service.impl;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.JwtResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.LoginRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.RegistroRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.UserResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Rol;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Usuario;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.repository.UsuarioRepository;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service.AuthService;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Implementación de {@link AuthService}. Concentra las reglas de negocio de autenticación
 * y registro, que antes estaban dentro de AuthController.
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    /** Administrador de autenticación de Spring Security que valida las credenciales. */
    private final AuthenticationManager authenticationManager;

    /** Repositorio de acceso a los usuarios persistidos. */
    private final UsuarioRepository usuarioRepository;

    /** Codificador BCrypt para cifrar las contraseñas antes de guardarlas. */
    private final PasswordEncoder encoder;

    /** Utilidad para emitir los tokens JWT firmados. */
    private final JwtUtil jwtUtil;

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional(readOnly = true)
    public JwtResponse login(LoginRequest request) {
        // Lanza AuthenticationException (traducida a 401) si las credenciales no son correctas.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        Usuario usuario = usuarioRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new BadCredentialsException("Credenciales inválidas"));

        String jwt = jwtUtil.generateToken(usuario);
        List<String> roles = usuario.getRoles().stream().map(Rol::name).sorted().toList();

        log.info("Login exitoso para el usuario: {}", usuario.getUsername());
        return new JwtResponse(jwt, usuario.getId().toString(), usuario.getUsername(), roles);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public UserResponse registrar(RegistroRequest request, boolean solicitanteEsAdmin) {
        if (usuarioRepository.existsByUsername(request.getUsername())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El nombre de usuario ya está en uso");
        }
        if (usuarioRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El correo electrónico ya está en uso");
        }

        Set<Rol> roles = resolverRoles(parseRoles(request.getRoles()), solicitanteEsAdmin);

        Usuario usuario = new Usuario();
        usuario.setUsername(request.getUsername());
        usuario.setEmail(request.getEmail());
        usuario.setPassword(encoder.encode(request.getPassword()));
        usuario.setRoles(roles);
        Usuario guardado = usuarioRepository.save(usuario);

        log.info("Usuario '{}' registrado con roles {}", guardado.getUsername(), roles);
        return UserResponse.from(guardado);
    }

    /**
     * Aplica la regla de alta de roles: si no se pide ninguno se asigna CLIENTE; un registro
     * público solo puede quedarse con CLIENTE; ADMIN y REPARTIDOR requieren que el solicitante sea ADMIN.
     * Así se evita que cualquiera se registre como repartidor y actualice estados de envíos.
     *
     * @param solicitados Roles pedidos (vacío si no se envió ninguno).
     * @param solicitanteEsAdmin {@code true} si quien registra es ADMIN.
     * @return Los roles definitivos a asignar.
     * @throws ResponseStatusException 403 si un usuario que no es ADMIN pide un rol distinto de CLIENTE.
     */
    private Set<Rol> resolverRoles(Set<Rol> solicitados, boolean solicitanteEsAdmin) {
        if (solicitados.isEmpty()) {
            return EnumSet.of(Rol.CLIENTE);
        }
        boolean pideRolPrivilegiado = solicitados.stream().anyMatch(rol -> rol != Rol.CLIENTE);
        if (pideRolPrivilegiado && !solicitanteEsAdmin) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Solo un administrador puede asignar los roles ADMIN o REPARTIDOR");
        }
        return solicitados;
    }

    /**
     * Convierte los nombres de rol recibidos (sin importar mayúsculas) en valores de la enumeración Rol.
     *
     * @param nombres Nombres de rol enviados por el cliente; puede ser nulo o vacío.
     * @return Conjunto de roles válidos (vacío si no se envió ninguno).
     * @throws ResponseStatusException 400 si algún nombre no corresponde a un rol existente.
     */
    private Set<Rol> parseRoles(Set<String> nombres) {
        Set<Rol> roles = EnumSet.noneOf(Rol.class);
        if (nombres == null) {
            return roles;
        }
        for (String nombre : nombres) {
            try {
                roles.add(Rol.valueOf(nombre.trim().toUpperCase()));
            } catch (IllegalArgumentException | NullPointerException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Rol inválido: '" + nombre + "'. Valores permitidos: " + Arrays.toString(Rol.values()));
            }
        }
        return roles;
    }
}
