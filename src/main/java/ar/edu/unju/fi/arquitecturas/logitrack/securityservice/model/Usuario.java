package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
import java.util.UUID;

/**
 * Entidad JPA que representa la tabla 'usuarios' en la base de datos de seguridad.
 * Almacena las credenciales de autenticación y los roles asociados
 * a cada usuario del sistema de forma persistente.
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "usuarios")
public class Usuario {

    /** Identificador único universal (UUID) autogenerado para cada usuario registrado. */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(updatable = false, nullable = false, columnDefinition = "VARCHAR(36)")
    private UUID id;

    /** Nombre de usuario único para el inicio de sesión. */
    @Column(unique = true, nullable = false, length = 50)
    private String username;

    /** Correo electrónico único del usuario para notificaciones y contacto. */
    @Column(unique = true, nullable = false, length = 100)
    private String email;

    /** Contraseña protegida mediante un algoritmo de cifrado irreversible (BCrypt). */
    @Column(nullable = false)
    private String password;

    /**
     * Colección de roles de seguridad asociados al usuario.
     * Se mapea en una tabla secundaria llamada 'usuario_roles' de manera ansiosa (EAGER).
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "usuario_roles", joinColumns = @JoinColumn(name = "usuario_id"))
    @Column(name = "rol")
    private Set<Rol> roles;
}