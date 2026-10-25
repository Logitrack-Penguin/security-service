package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto;

/**
 * Objeto de Transferencia de Datos (DTO, diseño para encapsular y transportar
 * datos entre diferentes capas de la aplicación) que encapsula las credenciales
 * de acceso enviadas por el cliente al intentar iniciar sesión.
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
public class LoginRequest {

    /** Nombre de usuario (username) ingresado para la autenticación. */
    private String username;

    /** Contraseña en texto plano (password) enviada por el cliente. */
    private String password;

    /** Obtiene el nombre de usuario. */
    public String getUsername() {
        return username;
    }

    /** Establece el nombre de usuario. */
    public void setUsername(String username) {
        this.username = username;
    }

    /** Obtiene la contraseña. */
    public String getPassword() {
        return password;
    }

    /** Establece la contraseña. */
    public void setPassword(String password) {
        this.password = password;
    }
}