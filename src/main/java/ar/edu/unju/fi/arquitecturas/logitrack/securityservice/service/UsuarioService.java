package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.UserResponse;

import java.util.List;

/**
 * Contrato de las consultas sobre usuarios registrados.
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
public interface UsuarioService {

    /**
     * Obtiene la información pública de un usuario a partir de su username.
     *
     * @param username Nombre de usuario (normalmente, el dueño del token actual).
     * @return Datos públicos del usuario.
     * @throws org.springframework.web.server.ResponseStatusException 404 si el usuario no existe.
     */
    UserResponse obtenerPorUsername(String username);

    /**
     * Lista todos los usuarios registrados, sin exponer contraseñas.
     *
     * @return Lista de usuarios en su representación pública.
     */
    List<UserResponse> listar();
}
