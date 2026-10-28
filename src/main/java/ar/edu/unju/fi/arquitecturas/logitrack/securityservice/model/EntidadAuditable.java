package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * Clase abstracta que provee los campos de auditoría (fecha de creación y de última modificación)
 * reutilizables por todas las entidades del microservicio. Sigue la misma convención que
 * shipment-service para que todas las entidades de LogiTrack queden auditadas de forma uniforme.
 * <p>
 * Al estar anotada con {@link MappedSuperclass}, sus columnas se heredan en la tabla de cada
 * subclase sin generar una tabla propia. Los valores los completa automáticamente
 * {@link AuditingEntityListener}, que requiere {@code @EnableJpaAuditing} (ver JpaAuditingConfig).
 * </p>
 *
 * @author Logitrack Penguin
 * @version 1.0
 * @see AuditingEntityListener
 */
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@SuperBuilder
public abstract class EntidadAuditable {

    /** Fecha y hora en que la entidad fue creada. Se asigna una sola vez y no se modifica. */
    @CreatedDate
    @Column(name = "fecha_creacion", nullable = false, updatable = false)
    private LocalDateTime fechaCreacion;

    /** Fecha y hora de la última modificación de la entidad. */
    @LastModifiedDate
    @Column(name = "fecha_ultima_modificacion")
    private LocalDateTime ultimaModificacion;
}
