package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto;

/**
 * Formato único (record, clase inmutable de datos) con el que la API informa cualquier error.
 *
 * @param status Código de estado HTTP.
 * @param error Nombre corto del error HTTP (por ejemplo, "Bad Request").
 * @param message Mensaje descriptivo para el cliente.
 * @param timestamp Momento en que ocurrió el error, en formato ISO-8601.
 * @author Elías Maciel Villalva
 * @version 1.0
 */
public record ApiError(int status, String error, String message, String timestamp) {
}
