package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model;

/**
 * Enumeración que define los roles de seguridad autorizados dentro del microservicio
 * para el control de acceso basado en roles (RBAC). Cumple con los requerimientos
 * obligatorios establecidos por la cátedra.
 *
 * @author Logitrack Penguin.
 * @version 1.0
 */
public enum Rol {

    /** Rol con privilegios administrativos totales sobre el sistema. */
    ADMIN,

    /** Rol estándar asignado a los clientes finales que consumen la plataforma. */
    CLIENTE,

    /** Rol asignado a los operadores o repartidores encargados de la logística. */
    REPARTIDOR
}