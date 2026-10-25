package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.repository;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Interfaz de repositorio para la gestión de persistencia de la entidad Usuario.
 * Extiende de JpaRepository utilizando UUID como tipo de dato para la clave primaria.
 *
 * @author Logitrack Penguin.
 * @version 2.0
 */
@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, UUID> {

    /**
     * Busca un usuario dentro del sistema utilizando su nombre de usuario único.
     *
     * @param username Nombre de usuario a buscar.
     * @return Un Optional que contiene al usuario si es encontrado.
     */
    Optional<Usuario> findByUsername(String username);

    /**
     * Verifica la existencia previa de un correo electrónico en la base de datos.
     *
     * @param email Correo electrónico a validar.
     * @return true si el correo ya se encuentra registrado, false en caso contrario.
     */
    boolean existsByEmail(String email);
}