package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

/**
 * Objeto de Transferencia de Datos (DTO, diseño para encapsular y transportar
 * datos entre diferentes capas de la aplicación) que encapsula la información
 * enviada por el cliente para registrar un nuevo usuario en el sistema.
 * Los datos se validan con Bean Validation (anotaciones de jakarta.validation).
 *
 * @author Elías Maciel Villalva
 * @version 2.0
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RegistroRequest {

    /** Nombre de usuario (username, identificador único de acceso) para la nueva cuenta. */
    @NotBlank(message = "El username es obligatorio")
    @Size(min = 3, max = 50, message = "El username debe tener entre 3 y 50 caracteres")
    private String username;

    /**
     * Contraseña en texto plano (password) que será cifrada antes de almacenarse en la base de datos.
     * El máximo es 72 porque BCrypt solo utiliza los primeros 72 bytes.
     */
    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 8, max = 72, message = "La contraseña debe tener entre 8 y 72 caracteres")
    private String password;

    /** Correo electrónico (email) único del usuario. */
    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El email no tiene un formato válido")
    @Size(max = 100, message = "El email no puede superar los 100 caracteres")
    private String email;

    /**
     * Conjunto (Set, colección de elementos únicos sin duplicados) de nombres de rol solicitados
     * (ADMIN, CLIENTE o REPARTIDOR). Si no se envía ninguno, se asigna CLIENTE.
     */
    private Set<String> roles;
}
