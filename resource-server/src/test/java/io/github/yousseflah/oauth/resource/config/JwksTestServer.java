package io.github.yousseflah.oauth.resource.config;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

final class JwksTestServer implements AutoCloseable {

    private static final String JWKS_PATH = "/oauth2/jwks";

    private final HttpServer server;
    private final ExecutorService executor;
    private final byte[] responseBody;

    private JwksTestServer(HttpServer server, ExecutorService executor, JWK publicJwk) {
        this.server = server;
        this.executor = executor;
        this.responseBody = new JWKSet(publicJwk).toString().getBytes(StandardCharsets.UTF_8);
    }

    static JwksTestServer start(JWK publicJwk) {
        try {
            var server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            var executor = Executors.newVirtualThreadPerTaskExecutor();
            var testServer = new JwksTestServer(server, executor, publicJwk);
            server.createContext(JWKS_PATH, testServer::handleRequest);
            server.setExecutor(executor);
            server.start();
            return testServer;
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to start the JWKS test server", exception);
        }
    }

    URI issuer() {
        return URI.create("http://localhost:" + server.getAddress().getPort());
    }

    URI jwkSetUri() {
        return issuer().resolve(JWKS_PATH);
    }

    private void handleRequest(HttpExchange exchange) throws IOException {
        try (exchange) {
            if (!"GET".equals(exchange.getRequestMethod())
                    || !JWKS_PATH.equals(exchange.getRequestURI().getPath())) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }

            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, responseBody.length);
            exchange.getResponseBody().write(responseBody);
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.close();
    }
}
