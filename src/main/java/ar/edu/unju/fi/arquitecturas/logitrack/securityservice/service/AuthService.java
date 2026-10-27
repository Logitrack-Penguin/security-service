package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.JwtResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.LoginRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.RegistroRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.UserResponse;

/**
 * Contrato de la lógica de negocio de autenticación: inicio de sesión y registro de usuarios.
 * Separa estas reglas del controlador para respetar el diseño en capas
 * (Controller → Service → Repository).
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
public interface AuthService {

    /**
     * Autentica a un usuario con sus credenciales y emite un token JWT firmado.
     *
     * @param request Credenciales (username y contraseña).
     * @return Respuesta con el token, el id, el username y los roles del usuario.
     * @throws org.springframework.security.core.AuthenticationException Si las credenciales son incorrectas (401).
     */
    JwtResponse login(LoginRequest request);

    /**
     * Registra un nuevo usuario aplicando las reglas de unicidad y de asignación de roles.
     * El registro público solo puede obtener el rol CLIENTE; los roles ADMIN y REPARTIDOR
     * únicamente pueden ser otorgados por un usuario ADMIN.
     *
     * @param request Datos del nuevo usuario.
     * @param solicitanteEsAdmin {@code true} si quien realiza la petición está autenticado como ADMIN.
     * @return Representación pública del usuario creado (sin contraseña).
     * @throws org.springframework.web.server.ResponseStatusException 409 si el username o el email ya existen,
     *         400 si algún rol no existe y 403 si se pide un rol no permitido.
     */
    UserResponse registrar(RegistroRequest request, boolean solicitanteEsAdmin);
}
