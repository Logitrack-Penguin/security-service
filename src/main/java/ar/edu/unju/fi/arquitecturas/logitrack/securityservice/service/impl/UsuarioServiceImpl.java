package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service.impl;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.UserResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.repository.UsuarioRepository;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service.UsuarioService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

/**
 * Implementación de {@link UsuarioService} para las consultas de usuarios.
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UsuarioServiceImpl implements UsuarioService {

    /** Repositorio de acceso a los usuarios persistidos. */
    private final UsuarioRepository usuarioRepository;

    /**
     * {@inheritDoc}
     */
    @Override
    public UserResponse obtenerPorUsername(String username) {
        return usuarioRepository.findByUsername(username)
                .map(UserResponse::from)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<UserResponse> listar() {
        return usuarioRepository.findAll().stream().map(UserResponse::from).toList();
    }
}
