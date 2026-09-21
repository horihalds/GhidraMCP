package com.lauriewired.server;

import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Plain-text response writing for the embedded HTTP server.
 */
public final class HttpResponses {

    private HttpResponses() {
    }

    /**
     * Sends {@code response} as a UTF-8 text/plain body with status 200.
     */
    public static void sendText(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
