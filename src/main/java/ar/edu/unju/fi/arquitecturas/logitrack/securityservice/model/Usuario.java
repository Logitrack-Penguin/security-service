package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.Set;
import java.util.UUID;

/**
 * Entidad JPA que representa la tabla 'usuarios' en la base de datos de seguridad.
 * Almacena las credenciales de autenticación y los roles asociados a cada usuario
 * del sistema. Hereda de {@link EntidadAuditable} las fechas de creación y modificación.
 * <p>
 * Se usan {@code @Getter} y {@code @Setter} en lugar de {@code @Data} porque {@code @Data}
 * genera equals/hashCode/toString sobre todos los campos, lo que en entidades JPA provoca
 * problemas con colecciones perezosas y expone el hash de la contraseña en los logs.
 * </p>
 *
 * @author Logitrack Penguin
 * @version 2.0
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@Entity
@Table(name = "usuarios")
public class Usuario extends EntidadAuditable {

    /**
     * Identificador único universal (UUID) autogenerado para cada usuario registrado.
     * Se guarda como texto (VARCHAR 36) de forma explícita para que el formato sea el mismo
     * en MySQL y en la base H2 de los tests.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(updatable = false, nullable = false, length = 36)
    private UUID id;

    /** Nombre de usuario único para el inicio de sesión. */
    @Column(unique = true, nullable = false, length = 50)
    private String username;

    /** Correo electrónico único del usuario para notificaciones y contacto. */
    @Column(unique = true, nullable = false, length = 100)
    private String email;

    /** Contraseña protegida mediante un algoritmo de hash irreversible (BCrypt). */
    @Column(nullable = false)
    private String password;

    /**
     * Colección de roles de seguridad asociados al usuario.
     * Se mapea en una tabla secundaria llamada 'usuario_roles' de manera ansiosa (EAGER),
     * ya que los roles se necesitan siempre al autenticar.
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "usuario_roles", joinColumns = @JoinColumn(name = "usuario_id"))
    @Column(name = "rol")
    private Set<Rol> roles;
}
