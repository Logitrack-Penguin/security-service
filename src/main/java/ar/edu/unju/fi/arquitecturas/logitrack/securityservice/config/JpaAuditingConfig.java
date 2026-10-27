package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * Configuración que habilita la auditoría automática de JPA ({@code @CreatedDate} y
 * {@code @LastModifiedDate}) para las entidades que extienden EntidadAuditable.
 * <p>
 * Se declara en una clase aparte (y no en la clase principal) para que los tests de
 * porciones de la aplicación, como {@code @WebMvcTest}, no intenten levantar JPA.
 * </p>
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@Configuration
@EnableJpaAuditing
public class JpaAuditingConfig {
}
