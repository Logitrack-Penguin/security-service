package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.controller;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.JwtResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.LoginRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Controlador REST (componente encargado de exponer endpoints web para recibir peticiones HTTP
 * y retornar respuestas JSON) para la gestión de autenticación y acceso de usuarios.
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Endpoint (punto de entrada HTTP) para autenticar a un usuario en el sistema.
     * Recibe las credenciales (username y password), valida su autenticidad mediante el gestor
     * de autenticación y retorna un token JWT junto con los roles correspondientes.
     *
     * @param loginRequest Objeto DTO que contiene el nombre de usuario y la contraseña.
     * @return Una respuesta HTTP 200 (OK) con el objeto JwtResponse que incluye el token de acceso.
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        // Autenticar las credenciales utilizando el AuthenticationManager de Spring Security.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        // Establecer la autenticación exitosa en el contexto global de seguridad.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Obtener los detalles del usuario autenticado.
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // Generar el token JWT utilizando el componente utilitario JwtUtil.
        String jwt = jwtUtil.generateToken(userDetails);

        // Extraer la lista de roles (authorities) asignados al usuario.
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // Retornar la respuesta estructurada con el token y los datos del usuario.
        return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(), roles));
    }
}