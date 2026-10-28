package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.controller;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.UserResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service.UsuarioService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Controlador REST para la gestión de usuarios. Todos sus endpoints están reservados
 * a los administradores (rol ADMIN).
 *
 * @author Elías Maciel Villalva
 * @version 2.0
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "Usuarios", description = "Administración de usuarios (solo ADMIN)")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    /** Servicio de consulta de usuarios. */
    private final UsuarioService usuarioService;

    /**
     * Lista todos los usuarios registrados (sin contraseñas).
     *
     * @return 200 con la lista de usuarios; 401 sin token; 403 si el solicitante no es ADMIN.
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Listar usuarios")
    public ResponseEntity<List<UserResponse>> listarUsuarios() {
        return ResponseEntity.ok(usuarioService.listar());
    }
}
