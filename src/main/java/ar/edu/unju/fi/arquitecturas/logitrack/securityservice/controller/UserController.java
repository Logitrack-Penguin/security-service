package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.controller;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.UserResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
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
 * @version 1.0
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    /** Repositorio de acceso a los usuarios persistidos. */
    @Autowired
    private UsuarioRepository usuarioRepository;

    /**
     * Lista todos los usuarios registrados (sin contraseñas).
     *
     * @return Respuesta HTTP 200 con la lista de usuarios; 403 si el solicitante no es ADMIN.
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponse>> listarUsuarios() {
        return ResponseEntity.ok(usuarioRepository.findAll().stream().map(UserResponse::from).toList());
    }
}
