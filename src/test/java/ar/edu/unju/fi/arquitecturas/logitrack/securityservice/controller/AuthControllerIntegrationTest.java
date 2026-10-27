package ar.edu.unju.fi.arquitecturas.logitrack.securityservice.controller;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Pruebas de integración de los endpoints de autenticación con el contexto completo de Spring
 * (seguridad, filtro JWT, servicios y H2 en memoria). Verifican el flujo real registro → login → /me
 * y las reglas de autorización por rol.
 * <p>
 * Usa el perfil "test", que además crea el ADMIN inicial "admin" mediante AdminBootstrap.
 * Cada prueba genera usernames únicos para no depender del orden de ejecución.
 * </p>
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerIntegrationTest {

    /** Cliente HTTP simulado para invocar los endpoints sin levantar un servidor real. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Arma el JSON de registro.
     *
     * @param username Nombre de usuario.
     * @param rolesJson Arreglo JSON de roles (por ejemplo {@code ["CLIENTE"]}) o {@code null} para omitirlo.
     * @return Cuerpo JSON de la petición.
     */
    private String registroJson(String username, String rolesJson) {
        String roles = rolesJson == null ? "" : ",\"roles\":" + rolesJson;
        return "{\"username\":\"" + username + "\",\"password\":\"password123\",\"email\":\""
                + username + "@mail.com\"" + roles + "}";
    }

    /**
     * Inicia sesión y devuelve el token JWT obtenido.
     *
     * @param username Nombre de usuario.
     * @param password Contraseña.
     * @return El token JWT.
     * @throws Exception Si falla la petición.
     */
    private String login(String username, String password) throws Exception {
        String body = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.token");
    }

    /**
     * Genera un username único para cada prueba.
     *
     * @return Username aleatorio de 12 caracteres.
     */
    private String usernameUnico() {
        return "u" + UUID.randomUUID().toString().replace("-", "").substring(0, 11);
    }

    /** Registro público, login y consulta de /me con el token emitido. */
    @Test
    void flujoRegistroLoginYMe() throws Exception {
        String username = usernameUnico();
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registroJson(username, null)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.roles[0]").value("CLIENTE"))
                .andExpect(jsonPath("$.password").doesNotExist());

        String token = login(username, "password123");

        mockMvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username));
    }

    /** Registrar dos veces el mismo username devuelve 409. */
    @Test
    void registroDuplicadoDevuelve409() throws Exception {
        String username = usernameUnico();
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registroJson(username, null)))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registroJson(username, null)))
                .andExpect(status().isConflict());
    }

    /** Sin token no se puede crear un REPARTIDOR. */
    @Test
    void registroPublicoComoRepartidorDevuelve403() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registroJson(usernameUnico(), "[\"REPARTIDOR\"]")))
                .andExpect(status().isForbidden());
    }

    /** Con un token de ADMIN sí se puede crear un REPARTIDOR. */
    @Test
    void adminPuedeCrearRepartidor() throws Exception {
        String tokenAdmin = login("admin", "admin-de-prueba-123");

        mockMvc.perform(post("/api/auth/register")
                        .header("Authorization", "Bearer " + tokenAdmin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registroJson(usernameUnico(), "[\"REPARTIDOR\"]")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.roles[0]").value("REPARTIDOR"));
    }

    /** Credenciales incorrectas devuelven 401. */
    @Test
    void loginConPasswordIncorrectaDevuelve401() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"admin\",\"password\":\"incorrecta\"}"))
                .andExpect(status().isUnauthorized());
    }

    /** /me sin token devuelve 401. */
    @Test
    void meSinTokenDevuelve401() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    /** Un CLIENTE no puede listar usuarios (403); un ADMIN sí (200). */
    @Test
    void listarUsuariosSoloParaAdmin() throws Exception {
        String username = usernameUnico();
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registroJson(username, null)))
                .andExpect(status().isCreated());
        String tokenCliente = login(username, "password123");
        String tokenAdmin = login("admin", "admin-de-prueba-123");

        mockMvc.perform(get("/api/users").header("Authorization", "Bearer " + tokenCliente))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/users").header("Authorization", "Bearer " + tokenAdmin))
                .andExpect(status().isOk());
    }
}
