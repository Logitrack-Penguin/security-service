package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service.impl;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Usuario;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Esta clase funciona como un recepcionista o guardia de seguridad del sistema.
 * Su única tarea es recibir los datos de una persona que quiere entrar, buscar su expediente
 * en el archivo central (la base de datos) y verificar qué permisos especiales tiene asignados
 * (por ejemplo, si es un administrador, un cliente o un repartidor).
 *
 * @author Elías Maciel Villalva
 * @version 1.0
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    /**
     * Es la herramienta de acceso directo al fichero o base de datos
     * donde se encuentran guardados todos los usuarios registrados en el sistema.
     */
    @Autowired
    private UsuarioRepository usuarioRepository;

    /**
     * Este proceso se ejecuta automáticamente cada vez que alguien intenta iniciar sesión.
     * Recibe el nombre de usuario que la persona escribió, va al archivo central a buscarlo,
     * comprueba que exista y traduce sus roles a una credencial digital válida que el sistema reconoce.
     *
     * @param username El nombre de la persona que está intentando ingresar al sistema.
     * @return Una credencial digital oficial con los datos y permisos de la persona.
     * @throws UsernameNotFoundException se activa y avisa si el usuario no existe en los registros.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario usuario = usuarioRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con el username: " + username));

        Set<GrantedAuthority> authorities = usuario.getRoles().stream()
                .map(rol -> new SimpleGrantedAuthority("ROLE_" + rol.name()))
                .collect(Collectors.toSet());

        return new User(
                usuario.getUsername(),
                usuario.getPassword(),
                authorities
        );
    }
}