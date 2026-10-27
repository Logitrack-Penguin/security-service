package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.exception;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.ApiError;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.stream.Collectors;

/**
 * Manejador global de excepciones (@RestControllerAdvice, componente que intercepta las excepciones
 * lanzadas por cualquier controlador) que traduce cada error a una respuesta JSON uniforme (ApiError)
 * con el código HTTP correspondiente.
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Datos de entrada que no cumplen las validaciones (@Valid).
     *
     * @param ex Excepción con el detalle de los campos inválidos.
     * @return Respuesta 400 con la lista de campos y motivos.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex) {
        String detalle = ex.getBindingResult().getFieldErrors().stream()
                .map(e -> e.getField() + ": " + e.getDefaultMessage())
                .sorted()
                .collect(Collectors.joining("; "));
        return build(HttpStatus.BAD_REQUEST, detalle);
    }

    /**
     * Cuerpo de la petición vacío o con JSON mal formado.
     *
     * @param ex Excepción de lectura del cuerpo.
     * @return Respuesta 400.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException ex) {
        return build(HttpStatus.BAD_REQUEST, "El cuerpo de la petición es inválido o está vacío");
    }

    /**
     * Fallo de autenticación (por ejemplo, credenciales incorrectas en el login).
     *
     * @param ex Excepción de autenticación.
     * @return Respuesta 401 con un mensaje genérico que no revela si falló el usuario o la contraseña.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiError> handleAuthentication(AuthenticationException ex) {
        return build(HttpStatus.UNAUTHORIZED, "Credenciales inválidas");
    }

    /**
     * Usuario autenticado sin el rol requerido (lanzada por @PreAuthorize).
     *
     * @param ex Excepción de acceso denegado.
     * @return Respuesta 403.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> handleAccessDenied(AccessDeniedException ex) {
        return build(HttpStatus.FORBIDDEN, "No tenés permisos para acceder a este recurso");
    }

    /**
     * Errores de negocio lanzados explícitamente con un código HTTP (409 por duplicados, 400 por rol inválido, etc.).
     *
     * @param ex Excepción con el estado y el motivo.
     * @return Respuesta con el estado indicado por la excepción.
     */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ApiError> handleStatus(ResponseStatusException ex) {
        return build(ex.getStatusCode(), ex.getReason());
    }

    /**
     * Construye la respuesta de error con el formato uniforme.
     *
     * @param status Código de estado HTTP.
     * @param message Mensaje descriptivo.
     * @return Respuesta HTTP con el ApiError como cuerpo.
     */
    private ResponseEntity<ApiError> build(HttpStatusCode status, String message) {
        String error = (status instanceof HttpStatus hs) ? hs.getReasonPhrase() : String.valueOf(status.value());
        return ResponseEntity.status(status)
                .body(new ApiError(status.value(), error, message, Instant.now().toString()));
    }
}
