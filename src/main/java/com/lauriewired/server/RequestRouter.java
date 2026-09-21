package com.lauriewired.server;

import com.lauriewired.util.Paginator;
import com.lauriewired.util.QueryParams;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The single table of HTTP endpoints.
 * <p>
 * Every path this server exposes is declared here once. The strings must not be renamed or
 * re-cased: {@code bridge_mcp_ghidra.py} and third-party MCP clients send them verbatim.
 */
public class RequestRouter {

    // ----------------------------------------------------------------------------------
    // The endpoint table. Keep the historical spelling, including the camelCase ones.
    // ----------------------------------------------------------------------------------
    public static final String METHODS = "/methods";
    public static final String CLASSES = "/classes";
    public static final String DECOMPILE = "/decompile";
    public static final String RENAME_FUNCTION = "/renameFunction";
    public static final String RENAME_DATA = "/renameData";
    public static final String RENAME_VARIABLE = "/renameVariable";
    public static final String SEGMENTS = "/segments";
    public static final String IMPORTS = "/imports";
    public static final String EXPORTS = "/exports";
    public static final String NAMESPACES = "/namespaces";
    public static final String DATA = "/data";
    public static final String SEARCH_FUNCTIONS = "/searchFunctions";
    public static final String GET_FUNCTION_BY_ADDRESS = "/get_function_by_address";
    public static final String GET_CURRENT_ADDRESS = "/get_current_address";
    public static final String GET_CURRENT_FUNCTION = "/get_current_function";
    public static final String LIST_FUNCTIONS = "/list_functions";
    public static final String DECOMPILE_FUNCTION = "/decompile_function";
    public static final String DISASSEMBLE_FUNCTION = "/disassemble_function";
    public static final String SET_DECOMPILER_COMMENT = "/set_decompiler_comment";
    public static final String SET_DISASSEMBLY_COMMENT = "/set_disassembly_comment";
    public static final String RENAME_FUNCTION_BY_ADDRESS = "/rename_function_by_address";
    public static final String SET_FUNCTION_PROTOTYPE = "/set_function_prototype";
    public static final String SET_LOCAL_VARIABLE_TYPE = "/set_local_variable_type";
    public static final String XREFS_TO = "/xrefs_to";
    public static final String XREFS_FROM = "/xrefs_from";
    public static final String FUNCTION_XREFS = "/function_xrefs";
    public static final String STRINGS = "/strings";
    public static final String READ_BYTES = "/read_bytes";
    public static final String READ_DATA = "/read_data";
    public static final String READ_STRING = "/read_string";
    public static final String READ_POINTER = "/read_pointer";

    /** The programs open in the addressed Ghidra tool. */
    public static final String LIST_OPEN_PROGRAMS = "/list_open_programs";

    /** Service fingerprint, version and actually bound port of this Ghidra tool. */
    public static final String SERVER_INFO = "/info";

    /**
     * The same paths in registration order, so the contract can be asserted mechanically. The
     * 31 historical paths stay at the head of the list; new endpoints are appended.
     */
    public static final List<String> PATHS = Collections.unmodifiableList(Arrays.asList(
        METHODS, CLASSES, DECOMPILE, RENAME_FUNCTION, RENAME_DATA, RENAME_VARIABLE, SEGMENTS,
        IMPORTS, EXPORTS, NAMESPACES, DATA, SEARCH_FUNCTIONS, GET_FUNCTION_BY_ADDRESS,
        GET_CURRENT_ADDRESS, GET_CURRENT_FUNCTION, LIST_FUNCTIONS, DECOMPILE_FUNCTION,
        DISASSEMBLE_FUNCTION, SET_DECOMPILER_COMMENT, SET_DISASSEMBLY_COMMENT,
        RENAME_FUNCTION_BY_ADDRESS, SET_FUNCTION_PROTOTYPE, SET_LOCAL_VARIABLE_TYPE, XREFS_TO,
        XREFS_FROM, FUNCTION_XREFS, STRINGS, READ_BYTES, READ_DATA, READ_STRING, READ_POINTER,
        LIST_OPEN_PROGRAMS, SERVER_INFO));

    /** The optional request parameter that selects which open program a request acts on. */
    public static final String PROGRAM_PARAM = "program";

    /**
     * Handles one endpoint and returns the plain-text response body.
     */
    @FunctionalInterface
    public interface Route {
        String handle(Request request) throws IOException;
    }

    /**
     * Read-only view of an incoming request: query parameters, form body and the raw body.
     */
    public static final class Request {

        private final HttpExchange exchange;
        private final Map<String, String> queryParams;
        private String body;

        Request(HttpExchange exchange) {
            this.exchange = exchange;
            this.queryParams = QueryParams.parseQuery(exchange.getRequestURI().getQuery());
        }

        /**
         * @return a query parameter, or null when it was not supplied
         */
        public String query(String name) {
            return queryParams.get(name);
        }

        /**
         * @return a query parameter parsed as an integer, or the default when absent/invalid
         */
        public int intQuery(String name, int defaultValue) {
            return Paginator.parseIntOrDefault(queryParams.get(name), defaultValue);
        }

        /**
         * @return true when a query flag such as {@code ?follow=true} is set
         */
        public boolean boolQuery(String name) {
            return Paginator.parseBooleanFlag(queryParams.get(name));
        }

        /**
         * @return the HTTP method of this request, e.g. {@code GET} or {@code POST}
         */
        public String method() {
            return exchange.getRequestMethod();
        }

        /**
         * @return true when the body is a URL-encoded form, as sent by the mutation endpoints
         */
        public boolean isFormPost() {
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            return contentType != null && contentType.toLowerCase(Locale.ROOT)
                .startsWith("application/x-www-form-urlencoded");
        }

        /**
         * @return a form-body parameter, or null when it was not supplied
         */
        public String form(String name) throws IOException {
            return QueryParams.parseBody(body()).get(name);
        }

        /**
         * @return the request body decoded as UTF-8 (also used as the raw function name by
         *         {@code /decompile})
         */
        public String body() throws IOException {
            if (body == null) {
                body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            }
            return body;
        }
    }

    private final HttpServer server;
    private final Map<String, Route> routes = new LinkedHashMap<>();
    private RequestScope scope;

    public RequestRouter(HttpServer server) {
        this.server = server;
    }

    /**
     * Installs the hook that resolves the request's target program before the route runs.
     *
     * @param scope the resolver, or null to run every route without a scope
     */
    public RequestRouter scope(RequestScope scope) {
        this.scope = scope;
        return this;
    }

    /**
     * Registers one endpoint.
     *
     * @param path one of the path constants of this class
     * @param route the implementation, usually a method reference
     */
    public RequestRouter route(String path, Route route) {
        routes.put(path, route);
        return this;
    }

    /**
     * @return the number of registered endpoints (33 for a fully wired router)
     */
    public int routeCount() {
        return routes.size();
    }

    /**
     * Registers every route with the JDK HTTP server.
     */
    public void install() {
        for (Map.Entry<String, Route> entry : routes.entrySet()) {
            Route route = entry.getValue();
            server.createContext(entry.getKey(), exchange -> HttpResponses.sendText(exchange,
                runRoute(route, new Request(exchange))));
        }
    }

    /**
     * Runs one route with the program selector of this request.
     */
    String runRoute(Route route, Request request) throws IOException {
        return runScoped(route, programSelector(request), request);
    }

    /**
     * Runs one route under the given selector and always releases the scope afterwards, so a
     * pooled worker thread cannot leak a previous request's program into the next one.
     *
     * @param route the endpoint implementation
     * @param selector the requested program, or null for the tool's current program
     * @param request the request handed to the route (null in unit tests)
     * @return the route's response body, or the scope's error message instead
     */
    String runScoped(Route route, String selector, Request request) throws IOException {
        if (scope == null) {
            return route.handle(request);
        }
        String error = scope.begin(selector);
        try {
            return (error != null) ? error : route.handle(request);
        }
        finally {
            scope.end();
        }
    }

    /**
     * Reads the {@code program} selector from the query string, falling back to the form body of
     * a form-based POST. The raw body is never used, so {@code /decompile} keeps sending its
     * function name there.
     */
    private static String programSelector(Request request) throws IOException {
        String selector = request.query(PROGRAM_PARAM);
        if (selector == null && request.isFormPost()) {
            selector = request.form(PROGRAM_PARAM);
        }
        return selector;
    }
}
