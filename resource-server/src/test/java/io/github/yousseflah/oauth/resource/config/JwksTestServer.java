package io.github.yousseflah.oauth.resource.config;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

final class JwksTestServer implements AutoCloseable {

    private static final String JWKS_PATH = "/oauth2/jwks";

    private final HttpServer server;
    private final ExecutorService executor;
    private final AtomicReference<byte[]> responseBody;
    private final AtomicInteger successfulRequestCount = new AtomicInteger();

    private JwksTestServer(HttpServer server, ExecutorService executor, JWK publicJwk) {
        this.server = server;
        this.executor = executor;
        this.responseBody = new AtomicReference<>(serializePublicJwk(publicJwk));
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

    void publish(JWK publicJwk) {
        responseBody.set(serializePublicJwk(publicJwk));
    }

    int successfulRequestCount() {
        return successfulRequestCount.get();
    }

    private void handleRequest(HttpExchange exchange) throws IOException {
        try (exchange) {
            if (!"GET".equals(exchange.getRequestMethod())
                    || !JWKS_PATH.equals(exchange.getRequestURI().getPath())) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }

            var currentResponseBody = responseBody.get();
            exchange.getResponseHeaders().set("Content-Type", JWKSet.MIME_TYPE);
            exchange.sendResponseHeaders(200, currentResponseBody.length);
            exchange.getResponseBody().write(currentResponseBody);
            successfulRequestCount.incrementAndGet();
        }
    }

    private static byte[] serializePublicJwk(JWK publicJwk) {
        if (publicJwk.isPrivate()) {
            throw new IllegalArgumentException("The JWKS test server accepts public keys only");
        }

        return new JWKSet(publicJwk).toString().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void close() {
        server.stop(0);
        executor.close();
    }
}
