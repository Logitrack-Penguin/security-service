package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.service.impl;

import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.client.ShipmentClienteClient;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.client.ShipmentClienteClient.ClienteShipment;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.client.ShipmentClienteClient.ClienteShipmentRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.RegistroRequest;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.dto.UserResponse;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Rol;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.model.Usuario;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.repository.UsuarioRepository;
import ar.edu.unju.fi.arquitecturas.logitrack.securityservice.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Pruebas unitarias (JUnit 5 + Mockito) de las reglas de registro de {@link AuthServiceImpl}:
 * unicidad de username/email, rol por defecto, roles inválidos y prevención de escalada de privilegios.
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    /** Repositorio simulado. */
    @Mock
    private UsuarioRepository usuarioRepository;

    /** Codificador simulado. */
    @Mock
    private PasswordEncoder encoder;

    /** Administrador de autenticación simulado (no se usa en estas pruebas de registro). */
    @Mock
    private AuthenticationManager authenticationManager;

    /** Utilidad JWT simulada (no se usa en estas pruebas de registro). */
    @Mock
    private JwtUtil jwtUtil;

    /** Cliente simulado de shipment-service. */
    @Mock
    private ShipmentClienteClient shipmentClienteClient;

    /** Servicio bajo prueba, con los mocks inyectados. */
    @InjectMocks
    private AuthServiceImpl authService;

    /**
     * Crea un RegistroRequest de prueba.
     *
     * @param roles Roles solicitados (puede ser nulo).
     * @return La petición de registro.
     */
    private RegistroRequest request(Set<String> roles) {
        return new RegistroRequest("maria", "password123", "maria@mail.com", roles);
    }

    /**
     * Crea un RegistroRequest de una cuenta CLIENTE, con sus datos de cliente.
     *
     * @return La petición de registro.
     */
    private RegistroRequest requestCliente() {
        return new RegistroRequest("maria", "password123", "maria@mail.com", null,
                "30111222", "María", "Gómez", "3881234567");
    }

    /** Simula que el repositorio devuelve el usuario guardado con un id asignado. */
    private void simularGuardado() {
        when(usuarioRepository.save(any(Usuario.class))).thenAnswer(inv -> {
            Usuario u = inv.getArgument(0);
            u.setId(UUID.randomUUID());
            return u;
        });
    }

    /** Sin roles solicitados, el usuario se crea como CLIENTE y con la contraseña cifrada. */
    @Test
    void registrarSinRolesAsignaClienteYCifraPassword() {
        when(encoder.encode("password123")).thenReturn("HASH");
        when(shipmentClienteClient.obtener("30111222")).thenReturn(Optional.empty());
        simularGuardado();

        UserResponse creado = authService.registrar(requestCliente(), false);

        ArgumentCaptor<Usuario> captor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepository).save(captor.capture());
        assertEquals("HASH", captor.getValue().getPassword());
        assertEquals(Set.of("CLIENTE"), creado.getRoles());
    }

    /** Un registro público no puede autoasignarse el rol REPARTIDOR. */
    @Test
    void registroPublicoComoRepartidorDevuelve403() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> authService.registrar(request(Set.of("REPARTIDOR")), false));

        assertEquals(HttpStatus.FORBIDDEN, ex.getStatusCode());
        verify(usuarioRepository, never()).save(any());
    }

    /** Un registro público no puede autoasignarse el rol ADMIN. */
    @Test
    void registroPublicoComoAdminDevuelve403() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> authService.registrar(request(Set.of("admin")), false));

        assertEquals(HttpStatus.FORBIDDEN, ex.getStatusCode());
    }

    /** Un ADMIN sí puede crear un REPARTIDOR. */
    @Test
    void adminPuedeCrearRepartidor() {
        when(encoder.encode(any())).thenReturn("HASH");
        simularGuardado();

        UserResponse creado = authService.registrar(request(Set.of("repartidor")), true);

        assertEquals(Set.of(Rol.REPARTIDOR.name()), creado.getRoles());
    }

    /** Un nombre de rol inexistente devuelve 400. */
    @Test
    void rolInexistenteDevuelve400() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> authService.registrar(request(Set.of("SUPERUSER")), true));

        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatusCode());
    }

    /** Un username ya registrado devuelve 409 y no se guarda nada. */
    @Test
    void usernameDuplicadoDevuelve409() {
        when(usuarioRepository.existsByUsername("maria")).thenReturn(true);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> authService.registrar(request(null), false));

        assertEquals(HttpStatus.CONFLICT, ex.getStatusCode());
        verify(usuarioRepository, never()).save(any());
    }

    /** Un email ya registrado devuelve 409. */
    @Test
    void emailDuplicadoDevuelve409() {
        when(usuarioRepository.existsByEmail("maria@mail.com")).thenReturn(true);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> authService.registrar(request(null), false));

        assertEquals(HttpStatus.CONFLICT, ex.getStatusCode());
    }

    // ---------------- Datos del cliente (cuenta CLIENTE) ----------------

    /** Si el cliente no existe en shipment, se crea con los datos del registro y se guarda el DNI. */
    @Test
    void registroClienteCreaElClienteEnShipmentYGuardaElDni() {
        when(encoder.encode(any())).thenReturn("HASH");
        when(shipmentClienteClient.obtener("30111222")).thenReturn(Optional.empty());
        simularGuardado();

        UserResponse creado = authService.registrar(requestCliente(), false);

        verify(shipmentClienteClient).crear(new ClienteShipmentRequest(
                "30111222", "María", "Gómez", "maria@mail.com", "3881234567"));
        assertEquals("30111222", creado.getDni());
    }

    /** Si el cliente ya existe con el mismo email (sin importar mayúsculas), se vincula sin crearlo. */
    @Test
    void registroClienteExistenteConMismoEmailSoloVincula() {
        when(encoder.encode(any())).thenReturn("HASH");
        when(shipmentClienteClient.obtener("30111222"))
                .thenReturn(Optional.of(new ClienteShipment("30111222", "MARIA@mail.com")));
        simularGuardado();

        UserResponse creado = authService.registrar(requestCliente(), false);

        verify(shipmentClienteClient, never()).crear(any());
        assertEquals("30111222", creado.getDni());
    }

    /** Un DNI de un cliente con otro email devuelve 409 y no se crea la cuenta. */
    @Test
    void registroClienteConDniDeOtraPersonaDevuelve409() {
        when(shipmentClienteClient.obtener("30111222"))
                .thenReturn(Optional.of(new ClienteShipment("30111222", "otra@mail.com")));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> authService.registrar(requestCliente(), false));

        assertEquals(HttpStatus.CONFLICT, ex.getStatusCode());
        verify(usuarioRepository, never()).save(any());
    }

    /** Un DNI que ya tiene cuenta devuelve 409 sin llamar a shipment. */
    @Test
    void registroClienteConDniConCuentaDevuelve409() {
        when(usuarioRepository.existsByDni("30111222")).thenReturn(true);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> authService.registrar(requestCliente(), false));

        assertEquals(HttpStatus.CONFLICT, ex.getStatusCode());
        verifyNoInteractions(shipmentClienteClient);
    }

    /** Si shipment-service no responde, el registro falla con 503 y no se guarda el usuario. */
    @Test
    void registroClienteConShipmentCaidoDevuelve503YNoGuarda() {
        when(shipmentClienteClient.obtener("30111222"))
                .thenThrow(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "No disponible"));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> authService.registrar(requestCliente(), false));

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, ex.getStatusCode());
        verify(usuarioRepository, never()).save(any());
    }

    /** Una cuenta CLIENTE sin sus datos de cliente devuelve 400 con un mensaje por campo. */
    @Test
    void registroClienteSinDatosDeClienteDevuelve400() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> authService.registrar(request(null), false));

        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatusCode());
        assertTrue(ex.getReason().contains("dni:"));
        assertTrue(ex.getReason().contains("telefono:"));
        verifyNoInteractions(shipmentClienteClient);
    }

    /** Un REPARTIDOR creado por un ADMIN no necesita DNI ni toca shipment-service. */
    @Test
    void repartidorNoNecesitaDatosDeCliente() {
        when(encoder.encode(any())).thenReturn("HASH");
        simularGuardado();

        UserResponse creado = authService.registrar(request(Set.of("REPARTIDOR")), true);

        assertNull(creado.getDni());
        verifyNoInteractions(shipmentClienteClient);
    }
}
