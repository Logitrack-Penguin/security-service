package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto;

import java.util.List;

/**
 * Objeto de Transferencia de Datos (DTO) que encapsula la estructura de la respuesta
 * devuelta al cliente tras un inicio de sesión exitoso, incluyendo el token JWT y los datos principales.
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
public class JwtResponse {

    /** Token JWT (JSON Web Token, credencial digital firmada criptográficamente) de acceso. */
    private String token;

    /** Tipo de token (por defecto utiliza el esquema de autenticación "Bearer"). */
    private String type = "Bearer";

    /** Nombre de usuario autenticado en el sistema. */
    private String username;

    /** Lista con los nombres de los roles asignados al usuario. */
    private List<String> roles;

    /**
     * Constructor principal para inicializar la respuesta del token.
     *
     * @param token El token JWT generado.
     * @param username El nombre de usuario.
     * @param roles Los roles del usuario.
     */
    public JwtResponse(String token, String username, List<String> roles) {
        this.token = token;
        this.username = username;
        this.roles = roles;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}