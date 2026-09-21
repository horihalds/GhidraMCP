package com.lauriewired.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import org.junit.Test;

/**
 * Pins the HTTP contract: the 31 historical endpoint paths, in order and with their historical
 * spelling, followed by the endpoints added for multi-program support.
 * <p>
 * Third-party MCP clients (including {@code bridge_mcp_ghidra.py}) send these paths verbatim,
 * so any rename, re-casing or removal is a breaking change.
 */
public class RequestRouterTest {

    private static final List<String> HISTORICAL_PATHS = Arrays.asList(
        "/methods",
        "/classes",
        "/decompile",
        "/renameFunction",
        "/renameData",
        "/renameVariable",
        "/segments",
        "/imports",
        "/exports",
        "/namespaces",
        "/data",
        "/searchFunctions",
        "/get_function_by_address",
        "/get_current_address",
        "/get_current_function",
        "/list_functions",
        "/decompile_function",
        "/disassemble_function",
        "/set_decompiler_comment",
        "/set_disassembly_comment",
        "/rename_function_by_address",
        "/set_function_prototype",
        "/set_local_variable_type",
        "/xrefs_to",
        "/xrefs_from",
        "/function_xrefs",
        "/strings",
        "/read_bytes",
        "/read_data",
        "/read_string",
        "/read_pointer");

    @Test
    public void declaresAllThirtyOneHistoricalPathsInOrder() {
        assertEquals(HISTORICAL_PATHS, RequestRouter.PATHS.subList(0, HISTORICAL_PATHS.size()));
    }

    @Test
    public void appendsTheMultiProgramEndpointsAfterTheHistoricalOnes() {
        assertEquals(Arrays.asList("/list_open_programs", "/info"),
            RequestRouter.PATHS.subList(HISTORICAL_PATHS.size(), RequestRouter.PATHS.size()));
    }

    @Test
    public void declaresNoDuplicatePaths() {
        assertEquals(RequestRouter.PATHS.size(),
            new HashSet<>(RequestRouter.PATHS).size());
    }

    @Test
    public void keepsTheCamelCaseEndpointSpellings() {
        assertEquals("/renameFunction", RequestRouter.RENAME_FUNCTION);
        assertEquals("/renameData", RequestRouter.RENAME_DATA);
        assertEquals("/renameVariable", RequestRouter.RENAME_VARIABLE);
        assertEquals("/searchFunctions", RequestRouter.SEARCH_FUNCTIONS);
    }

    @Test
    public void declaresTheNewEndpointsWithLowerCaseSpelling() {
        assertEquals("/list_open_programs", RequestRouter.LIST_OPEN_PROGRAMS);
        assertEquals("/info", RequestRouter.SERVER_INFO);
    }

    @Test
    public void countsRegisteredRoutes() {
        RequestRouter router = new RequestRouter(null);

        RequestRouter returned = router.route(RequestRouter.METHODS, request -> "ok");

        assertEquals(1, router.routeCount());
        assertEquals(router, returned);
    }

    @Test
    public void runsTheRouteWithoutAScopeWhenNoneIsInstalled() throws IOException {
        RequestRouter router = new RequestRouter(null);

        assertEquals("ok", router.runScoped(request -> "ok", "libfoo.so", null));
    }

    @Test
    public void passesTheProgramSelectorToTheScope() throws IOException {
        RecordingScope scope = new RecordingScope();
        RequestRouter router = new RequestRouter(null).scope(scope);

        assertEquals("ok", router.runScoped(request -> "ok", "libfoo.so", null));

        assertEquals(Arrays.asList("libfoo.so"), scope.selectors);
        assertEquals(1, scope.ends);
    }

    @Test
    public void callsTheScopeWithAnAbsentSelector() throws IOException {
        RecordingScope scope = new RecordingScope();
        RequestRouter router = new RequestRouter(null).scope(scope);

        router.runScoped(request -> "ok", null, null);

        assertEquals(Arrays.asList((String) null), scope.selectors);
        assertEquals(1, scope.ends);
    }

    @Test
    public void returnsTheScopeErrorAndSkipsTheRoute() throws IOException {
        RecordingScope scope = new RecordingScope("No program matching 'foo'.");
        RequestRouter router = new RequestRouter(null).scope(scope);
        boolean[] routeRan = {false};

        String body = router.runScoped(request -> {
            routeRan[0] = true;
            return "ok";
        }, "foo", null);

        assertEquals("No program matching 'foo'.", body);
        assertFalse(routeRan[0]);
        assertEquals(1, scope.ends);
    }

    @Test
    public void endsTheScopeWhenTheRouteThrows() {
        RecordingScope scope = new RecordingScope();
        RequestRouter router = new RequestRouter(null).scope(scope);

        try {
            router.runScoped(request -> {
                throw new IOException("boom");
            }, "libfoo.so", null);
            fail("expected the route failure to propagate");
        }
        catch (IOException expected) {
            assertEquals("boom", expected.getMessage());
        }

        assertEquals(1, scope.ends);
    }

    @Test
    public void clearsTheScopeBeforeEachRequest() throws IOException {
        RecordingScope scope = new RecordingScope();
        RequestRouter router = new RequestRouter(null).scope(scope);

        router.runScoped(request -> "first", "libfoo.so", null);
        router.runScoped(request -> "second", null, null);

        assertEquals(Arrays.asList("libfoo.so", null), scope.selectors);
        assertEquals(2, scope.ends);
    }

    /**
     * Minimal {@link RequestScope} that records what the router did with it.
     */
    private static final class RecordingScope implements RequestScope {

        private final List<String> selectors = new ArrayList<>();
        private final String error;
        private int ends;

        RecordingScope() {
            this(null);
        }

        RecordingScope(String error) {
            this.error = error;
        }

        @Override
        public String begin(String programSelector) {
            selectors.add(programSelector);
            return error;
        }

        @Override
        public void end() {
            ends++;
        }
    }
}
