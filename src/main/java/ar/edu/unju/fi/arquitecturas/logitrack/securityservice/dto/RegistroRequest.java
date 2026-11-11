package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
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

    // ---------- Datos del cliente (obligatorios cuando la cuenta es CLIENTE) ----------
    // Con ellos security-service crea (o vincula) el cliente en shipment-service y guarda el DNI
    // en el usuario. Los formatos copian ClienteRequestDto de shipment-service.

    /** DNI del cliente: 8 dígitos. */
    @Pattern(regexp = "\\d{8}", message = "El DNI debe tener 8 dígitos")
    private String dni;

    /** Nombre del cliente: solo letras, entre 3 y 30 caracteres. */
    @Size(min = 3, max = 30, message = "El nombre debe tener entre 3 y 30 caracteres")
    @Pattern(regexp = "[\\p{L} ]+", message = "El nombre solo puede contener letras")
    private String nombre;

    /** Apellido del cliente: solo letras. */
    @Pattern(regexp = "[\\p{L} ]+", message = "El apellido solo puede contener letras")
    private String apellido;

    /** Teléfono del cliente: 10 dígitos. */
    @Pattern(regexp = "\\d{10}", message = "El teléfono debe tener 10 dígitos")
    private String telefono;

    /**
     * Registro sin datos de cliente (por ejemplo, un REPARTIDOR creado por un administrador).
     *
     * @param username Nombre de usuario.
     * @param password Contraseña en texto plano.
     * @param email    Correo electrónico.
     * @param roles    Roles solicitados (puede ser nulo).
     */
    public RegistroRequest(String username, String password, String email, Set<String> roles) {
        this(username, password, email, roles, null, null, null, null);
    }
}
