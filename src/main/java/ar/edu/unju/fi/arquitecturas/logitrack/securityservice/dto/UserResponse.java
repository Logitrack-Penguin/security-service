package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.Set;

/**
 * DTO que encapsula la información pública del usuario autenticado
 * para ser devuelta en el endpoint /me.
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserResponse {

    /** Identificador único o nombre de usuario. */
    private String username;

    /** Correo electrónico del usuario. */
    private String email;

    /** Conjunto de roles o perfiles que posee el usuario. */
    private Set<String> roles;
}