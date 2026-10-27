package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

/**
 * Objeto de Transferencia de Datos (DTO, diseño para encapsular y transportar
 * datos entre diferentes capas de la aplicación) que encapsula la información
 * enviada por el cliente para registrar un nuevo usuario en el sistema.
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RegistroRequest {

    /**
     * Nombre de usuario (username, identificador único de acceso) para la nueva cuenta.
     */
    private String username;

    /**
     * Contraseña en texto plano (password) que será cifrada antes de almacenarse en la base de datos.
     */
    private String password;

    /**
     * Correo electrónico obligatorio del usuario.
     */
    private String email;

    /**
     * Conjunto (Set, colección de elementos únicos sin duplicados) de roles asignados al usuario.
     */
    private Set<String> roles;
}