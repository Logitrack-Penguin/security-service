package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service.impl;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.client.ShipmentClienteClient;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.client.ShipmentClienteClient.ClienteShipment;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.client.ShipmentClienteClient.ClienteShipmentRequest;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
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

    /** Crea o busca el cliente en shipment-service al registrar una cuenta CLIENTE. */
    private final ShipmentClienteClient shipmentClienteClient;

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public JwtResponse login(LoginRequest request) {
        // Lanza AuthenticationException (traducida a 401) si las credenciales no son correctas.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        Usuario usuario = usuarioRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new BadCredentialsException("Credenciales inválidas"));
        completarDniDeCliente(usuario);

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
        // El DNI vincula la cuenta con su cliente (shipment) o con su ficha de repartidor (courier).
        String dni;
        if (roles.contains(Rol.CLIENTE)) {
            dni = vincularCliente(request);
        } else if (roles.contains(Rol.REPARTIDOR)) {
            dni = dniDeRepartidor(request);
        } else {
            dni = null;
        }

        Usuario usuario = new Usuario();
        usuario.setUsername(request.getUsername());
        usuario.setEmail(request.getEmail());
        usuario.setPassword(encoder.encode(request.getPassword()));
        usuario.setRoles(roles);
        usuario.setDni(dni);
        Usuario guardado = usuarioRepository.save(usuario);

        log.info("Usuario '{}' registrado con roles {}", guardado.getUsername(), roles);
        return UserResponse.from(guardado);
    }

    /**
     * Crea el cliente en shipment-service, o lo vincula si ya existe con el mismo email, y devuelve
     * su DNI. Se llama después de validar username y email, para no dejar clientes huérfanos si el
     * registro igual iba a fallar.
     *
     * @param request Petición de registro con los datos del cliente.
     * @return El DNI que queda guardado en el usuario.
     * @throws ResponseStatusException 400 si faltan datos del cliente; 409 si el DNI ya tiene cuenta
     *                                 o pertenece a un cliente con otro email; 503 si shipment-service
     *                                 no responde (en ese caso no se crea el usuario).
     */
    /**
     * Las cuentas CLIENTE creadas antes de LT4-40 no tienen DNI, y sin DNI en el token shipment-service
     * no les muestra ningún envío. Al iniciar sesión se busca en shipment el cliente con el mismo
     * email (el mismo criterio que vincula una cuenta nueva con un cliente existente) y se guarda su
     * DNI, que va en el token desde este mismo login. Si no hay cliente con ese email, si el DNI ya
     * es de otra cuenta o si shipment no responde, el login sigue igual, sin DNI.
     *
     * @param usuario Usuario que acaba de autenticarse.
     */
    private void completarDniDeCliente(Usuario usuario) {
        if (usuario.getDni() != null || !usuario.getRoles().contains(Rol.CLIENTE)) {
            return;
        }
        shipmentClienteClient.buscarPorEmail(usuario.getEmail())
                .filter(cliente -> mismoEmail(cliente.email(), usuario.getEmail()))
                .map(ClienteShipment::dni)
                .filter(dni -> !usuarioRepository.existsByDni(dni))
                .ifPresent(dni -> {
                    usuario.setDni(dni);
                    usuarioRepository.save(usuario);
                    log.info("Cuenta '{}' vinculada al cliente con DNI {} al iniciar sesión",
                            usuario.getUsername(), dni);
                });
    }

    private String vincularCliente(RegistroRequest request) {
        List<String> faltantes = new ArrayList<>();
        if (estaVacio(request.getDni())) faltantes.add("dni: El DNI es obligatorio para una cuenta de cliente");
        if (estaVacio(request.getNombre())) faltantes.add("nombre: El nombre es obligatorio para una cuenta de cliente");
        if (estaVacio(request.getApellido())) faltantes.add("apellido: El apellido es obligatorio para una cuenta de cliente");
        if (estaVacio(request.getTelefono())) faltantes.add("telefono: El teléfono es obligatorio para una cuenta de cliente");
        if (!faltantes.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, String.join("; ", faltantes));
        }

        String dni = request.getDni().trim();
        if (usuarioRepository.existsByDni(dni)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Ese DNI ya tiene una cuenta");
        }

        Optional<ClienteShipment> existente = shipmentClienteClient.obtener(dni);
        if (existente.isPresent()) {
            // Cliente cargado antes (por un ADMIN o en los datos iniciales): solo se vincula si es
            // la misma persona, es decir, si tiene el mismo email que la cuenta.
            if (!mismoEmail(existente.get().email(), request.getEmail())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Ese DNI ya está registrado con otro email");
            }
            log.info("Cuenta vinculada al cliente existente con DNI {}", dni);
        } else {
            shipmentClienteClient.crear(new ClienteShipmentRequest(dni, request.getNombre().trim(),
                    request.getApellido().trim(), request.getEmail().trim(), request.getTelefono().trim()));
            log.info("Cliente con DNI {} creado en shipment-service", dni);
        }
        return dni;
    }

    /**
     * Valida el DNI de una cuenta REPARTIDOR. La ficha del repartidor la crea antes el frontend en
     * courier-service (alta unificada); acá solo se guarda el mismo DNI para que viaje en el token
     * y courier sepa qué repartidor es el usuario logueado (errores 3 y 4 de LT4-40).
     *
     * @param request Petición de registro.
     * @return El DNI que queda guardado en el usuario.
     * @throws ResponseStatusException 400 si falta el DNI; 409 si ya tiene una cuenta.
     */
    private String dniDeRepartidor(RegistroRequest request) {
        if (estaVacio(request.getDni())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "dni: El DNI es obligatorio para una cuenta de repartidor");
        }
        String dni = request.getDni().trim();
        if (usuarioRepository.existsByDni(dni)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Ese DNI ya tiene una cuenta");
        }
        return dni;
    }

    private static boolean estaVacio(String valor) {
        return valor == null || valor.isBlank();
    }

    private static boolean mismoEmail(String a, String b) {
        return a != null && b != null
                && a.trim().toLowerCase(Locale.ROOT).equals(b.trim().toLowerCase(Locale.ROOT));
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
