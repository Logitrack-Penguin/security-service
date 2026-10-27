package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * Objeto de Transferencia de Datos (DTO) que encapsula la estructura de la respuesta
 * devuelta al cliente tras un inicio de sesión exitoso, incluyendo el token JWT y los datos principales.
 *
 * @author Elías Maciel Villalva
 * @version 2.0
 */
@Getter
@Setter
public class JwtResponse {

    /** Token JWT (JSON Web Token, credencial digital firmada criptográficamente) de acceso. */
    private String token;

    /** Tipo de token (por defecto utiliza el esquema de autenticación "Bearer"). */
    private String type = "Bearer";

    /** Identificador único (UUID) del usuario autenticado. */
    private String userId;

    /** Nombre de usuario autenticado en el sistema. */
    private String username;

    /** Lista con los nombres de los roles asignados al usuario (ADMIN, CLIENTE, REPARTIDOR). */
    private List<String> roles;

    /**
     * Constructor principal para inicializar la respuesta del token.
     *
     * @param token El token JWT generado.
     * @param userId El identificador del usuario.
     * @param username El nombre de usuario.
     * @param roles Los roles del usuario.
     */
    public JwtResponse(String token, String userId, String username, List<String> roles) {
        this.token = token;
        this.userId = userId;
        this.username = username;
        this.roles = roles;
    }
}
