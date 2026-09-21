package com.lauriewired.util;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Dependency-free parsing of HTTP query strings and form bodies.
 */
public final class QueryParams {

    private QueryParams() {
    }

    /**
     * Parse a raw URL query string, e.g. {@code offset=10&limit=100}.
     */
    public static Map<String, String> parseQuery(String rawQuery) {
        return parse(rawQuery);
    }

    /**
     * Parse a raw form body, e.g. {@code oldName=foo&newName=bar}.
     */
    public static Map<String, String> parseBody(String rawBody) {
        return parse(rawBody);
    }

    /**
     * Splits on '&amp;' and then on '=' with a limit of two, so values that themselves
     * contain an '=' (e.g. {@code filter=a=b}) are preserved instead of being dropped.
     * Pairs without a '=' and malformed percent-escapes are skipped.
     */
    private static Map<String, String> parse(String raw) {
        Map<String, String> result = new HashMap<>();
        if (raw == null || raw.isEmpty()) {
            return result;
        }
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            String[] kv = pair.split("=", 2);
            if (kv.length != 2) {
                continue;
            }
            // URL decode parameter values
            try {
                String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                result.put(key, value);
            } catch (IllegalArgumentException e) {
                // Skip malformed pairs rather than failing the whole request.
            }
        }
        return result;
    }
}
