package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Objeto de Transferencia de Datos (DTO, diseño para encapsular y transportar
 * datos entre diferentes capas de la aplicación) que encapsula las credenciales
 * de acceso enviadas por el cliente al intentar iniciar sesión.
 *
 * @author Elías Maciel Villalva
 * @version 2.0
 */
@Getter
@Setter
@NoArgsConstructor
public class LoginRequest {

    /** Nombre de usuario (username) ingresado para la autenticación. Es obligatorio. */
    @NotBlank(message = "El username es obligatorio")
    private String username;

    /** Contraseña en texto plano (password) enviada por el cliente. Es obligatoria. */
    @NotBlank(message = "La contraseña es obligatoria")
    private String password;
}
