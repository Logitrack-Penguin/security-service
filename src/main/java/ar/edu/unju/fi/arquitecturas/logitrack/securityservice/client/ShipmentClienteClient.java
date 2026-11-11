package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Llama a shipment-service para buscar y crear clientes al registrar una cuenta CLIENTE.
 *
 * <p>La llamada es interna (servicio a servicio, por Eureka) y no pasa por el api-gateway: así un
 * usuario CLIENTE sigue sin poder crear clientes por su cuenta, porque el gateway se lo prohíbe.</p>
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@Slf4j
@Component
public class ShipmentClienteClient {

    /** Datos del cliente de shipment que se necesitan para vincularlo (el resto se ignora). */
    public record ClienteShipment(String dni, String email) {
    }

    /** Cuerpo de {@code POST /api/v1/clientes} (ClienteRequestDto de shipment-service). */
    public record ClienteShipmentRequest(String dni, String nombre, String apellido, String email,
                                         String telefono) {
    }

    private static final String RUTA = "/api/v1/clientes";

    /** Elige una instancia de shipment-service registrada en Eureka. */
    private final LoadBalancerClient loadBalancer;

    private final String serviceId;

    private final RestClient restClient = RestClient.create();

    /**
     * No se usa un {@code RestClient.Builder} con {@code @LoadBalanced} como bean: reemplazaría al
     * builder por defecto y el propio cliente de Eureka intentaría resolver "localhost" como servicio.
     *
     * @param loadBalancer Balanceador de Spring Cloud (resuelve el nombre con Eureka).
     * @param serviceId    Nombre de shipment-service en Eureka.
     */
    public ShipmentClienteClient(LoadBalancerClient loadBalancer,
                                 @Value("${logitrack.shipment.service-id:shipment-service}") String serviceId) {
        this.loadBalancer = loadBalancer;
        this.serviceId = serviceId;
    }

    /** URL de clientes en una instancia de shipment-service, o 503 si no hay ninguna registrada. */
    private String urlClientes() {
        ServiceInstance instancia = loadBalancer.choose(serviceId);
        if (instancia == null) {
            log.error("No hay instancias de {} registradas en Eureka", serviceId);
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "No se pudo registrar el cliente; probá más tarde");
        }
        return instancia.getUri() + RUTA;
    }

    /**
     * Busca un cliente por DNI.
     *
     * @param dni DNI del cliente.
     * @return El cliente, o vacío si shipment responde 404.
     * @throws ResponseStatusException 503 si shipment-service no responde.
     */
    public Optional<ClienteShipment> obtener(String dni) {
        try {
            return Optional.ofNullable(restClient.get().uri(urlClientes() + "/{dni}", dni)
                    .retrieve()
                    .body(ClienteShipment.class));
        } catch (HttpClientErrorException.NotFound e) {
            return Optional.empty();
        } catch (RestClientException e) {
            throw noDisponible(e);
        }
    }

    /**
     * Crea un cliente en shipment-service.
     *
     * @param request Datos del cliente.
     * @throws ResponseStatusException con el mismo status y mensaje si shipment lo rechaza
     *                                 (400 datos inválidos, 409 DNI/teléfono/email repetido), o 503
     *                                 si no responde.
     */
    /**
     * Busca el cliente con ese email en shipment-service. Se usa al iniciar sesión para completar el
     * DNI de las cuentas CLIENTE creadas antes de que el DNI viajara en el token (LT4-40).
     * <p>
     * Nunca lanza excepción: si shipment-service no responde, devuelve vacío para no impedir el login.
     * </p>
     *
     * @param email Email del usuario.
     * @return El cliente con ese email, o vacío si no hay ninguno o shipment-service no respondió.
     */
    public Optional<ClienteShipment> buscarPorEmail(String email) {
        try {
            List<ClienteShipment> clientes = restClient.get()
                    .uri(urlClientes() + "?email={email}", email)
                    .retrieve()
                    .body(new ParameterizedTypeReference<List<ClienteShipment>>() {
                    });
            return clientes == null ? Optional.empty() : clientes.stream().findFirst();
        } catch (RestClientException | ResponseStatusException e) {
            log.warn("No se pudo buscar el cliente por email en shipment-service: {}", e.getMessage());
            return Optional.empty();
        }
    }

    public void crear(ClienteShipmentRequest request) {
        try {
            restClient.post()
                    .uri(urlClientes())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .toBodilessEntity();
        } catch (HttpClientErrorException e) {
            throw new ResponseStatusException(e.getStatusCode(), mensajeDe(e));
        } catch (RestClientException e) {
            throw noDisponible(e);
        }
    }

    private ResponseStatusException noDisponible(RestClientException e) {
        log.error("shipment-service no respondió al registrar un cliente: {}", e.getMessage());
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "No se pudo registrar el cliente; probá más tarde");
    }

    /**
     * Arma el mensaje con el cuerpo de error de shipment: {@code { mensaje, detalles: {campo: msg} }}.
     * Los detalles se devuelven como "campo: motivo; …", igual que los errores de validación de
     * este servicio.
     */
    private String mensajeDe(HttpClientErrorException e) {
        Map<String, Object> cuerpo = null;
        try {
            cuerpo = e.getResponseBodyAs(new ParameterizedTypeReference<Map<String, Object>>() {
            });
        } catch (RuntimeException ignorada) {
            // Cuerpo vacío o no JSON: se usa el mensaje genérico.
        }
        if (cuerpo != null && cuerpo.get("detalles") instanceof Map<?, ?> detalles && !detalles.isEmpty()) {
            return detalles.entrySet().stream()
                    .map(d -> d.getKey() + ": " + d.getValue())
                    .sorted()
                    .collect(Collectors.joining("; "));
        }
        if (cuerpo != null && cuerpo.get("mensaje") instanceof String mensaje && !mensaje.isBlank()) {
            return mensaje;
        }
        return "No se pudo registrar el cliente";
    }
}
