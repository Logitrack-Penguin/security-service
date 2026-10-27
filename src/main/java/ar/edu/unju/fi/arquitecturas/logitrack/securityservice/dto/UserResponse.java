package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Rol;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Usuario;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Objeto de Transferencia de Datos (DTO) con la información pública de un usuario.
 * Nunca incluye la contraseña ni su hash.
 *
 * @author Elías Maciel Villalva
 * @version 2.0
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserResponse {

    /** Identificador único (UUID) del usuario en formato texto. */
    private String id;

    /** Nombre de usuario (username). */
    private String username;

    /** Correo electrónico del usuario. */
    private String email;

    /** Nombres de los roles asignados (por ejemplo, ADMIN, CLIENTE, REPARTIDOR). */
    private Set<String> roles;

    /**
     * Convierte una entidad Usuario en su representación pública.
     *
     * @param usuario Entidad persistida.
     * @return DTO sin datos sensibles.
     */
    public static UserResponse from(Usuario usuario) {
        Set<String> roles = usuario.getRoles().stream().map(Rol::name).collect(Collectors.toSet());
        return new UserResponse(usuario.getId().toString(), usuario.getUsername(), usuario.getEmail(), roles);
    }
}
