package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.framework.options.Options;

import com.lauriewired.handlers.CallGraphHandlers;
import com.lauriewired.handlers.CommentHandlers;
import com.lauriewired.handlers.DataTypeHandlers;
import com.lauriewired.handlers.DecompilationHandlers;
import com.lauriewired.handlers.FunctionHandlers;
import com.lauriewired.handlers.ListingHandlers;
import com.lauriewired.handlers.MemoryHandlers;
import com.lauriewired.handlers.MutationHandlers;
import com.lauriewired.handlers.ProgramInfoHandlers;
import com.lauriewired.handlers.PrototypeHandlers;
import com.lauriewired.handlers.SearchHandlers;
import com.lauriewired.handlers.ServerHandlers;
import com.lauriewired.handlers.XrefHandlers;
import com.lauriewired.server.HttpServerBootstrap;
import com.lauriewired.server.RequestRouter;
import com.lauriewired.service.DecompilerService;
import com.lauriewired.service.GhidraContext;

import java.io.IOException;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServerBootstrap httpServer;
    private GhidraContext context;
    private DecompilerService decompilerService;
    private ListingHandlers listingHandlers;
    private XrefHandlers xrefHandlers;
    private MemoryHandlers memoryHandlers;
    private DecompilationHandlers decompilationHandlers;
    private MutationHandlers mutationHandlers;
    private PrototypeHandlers prototypeHandlers;
    private ServerHandlers serverHandlers;
    private FunctionHandlers functionHandlers;
    private CommentHandlers commentHandlers;
    private DataTypeHandlers dataTypeHandlers;
    private CallGraphHandlers callGraphHandlers;
    private SearchHandlers searchHandlers;
    private ProgramInfoHandlers programInfoHandlers;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        this.context = new GhidraContext(tool, this);
        this.decompilerService = new DecompilerService(this);
        this.listingHandlers = new ListingHandlers(context);
        this.xrefHandlers = new XrefHandlers(context);
        this.memoryHandlers = new MemoryHandlers(context);
        this.prototypeHandlers = new PrototypeHandlers(context, decompilerService, tool, this);
        this.decompilationHandlers = new DecompilationHandlers(context, decompilerService, tool);
        this.mutationHandlers =
            new MutationHandlers(context, decompilerService, prototypeHandlers, this);
        this.serverHandlers = new ServerHandlers(context);
        this.functionHandlers = new FunctionHandlers(context);
        this.commentHandlers = new CommentHandlers(context);
        this.dataTypeHandlers = new DataTypeHandlers(context);
        this.callGraphHandlers = new CallGraphHandlers(context);
        this.searchHandlers = new SearchHandlers(context);
        this.programInfoHandlers = new ProgramInfoHandlers(context);

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        this.httpServer = new HttpServerBootstrap(tool, this, OPTION_CATEGORY_NAME,
            PORT_OPTION_NAME, DEFAULT_PORT);
        try {
            httpServer.start(this::registerRoutes);
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    /**
     * Binds every endpoint path to the code that implements it.
     */
    private void registerRoutes(RequestRouter router) {
        // Every endpoint acts on the tool's current program unless the request names one of
        // its open programs with the 'program' parameter.
        router.scope(context);

        // Each listing endpoint uses offset & limit from query params:
        router.route(RequestRouter.METHODS, request -> listingHandlers.getAllFunctionNames(
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.CLASSES, request -> listingHandlers.getAllClassNames(
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.DECOMPILE, request ->
            decompilationHandlers.decompileFunctionByName(request.body()));

        router.route(RequestRouter.RENAME_FUNCTION, request ->
            mutationHandlers.renameFunction(request.form("oldName"), request.form("newName"))
                ? "Renamed successfully" : "Rename failed");

        router.route(RequestRouter.RENAME_DATA, request -> {
            mutationHandlers.renameDataAtAddress(request.form("address"), request.form("newName"));
            return "Rename data attempted";
        });

        router.route(RequestRouter.RENAME_VARIABLE, request -> mutationHandlers.renameVariableInFunction(
            request.form("functionName"), request.form("oldName"), request.form("newName")));

        router.route(RequestRouter.SEGMENTS, request -> listingHandlers.listSegments(
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.IMPORTS, request -> listingHandlers.listImports(
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.EXPORTS, request -> listingHandlers.listExports(
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.NAMESPACES, request -> listingHandlers.listNamespaces(
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.DATA, request -> listingHandlers.listDefinedData(
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.SEARCH_FUNCTIONS, request -> listingHandlers.searchFunctionsByName(
            request.query("query"), request.intQuery("offset", 0), request.intQuery("limit", 100)));

        // New API endpoints based on requirements
        router.route(RequestRouter.GET_FUNCTION_BY_ADDRESS, request ->
            decompilationHandlers.getFunctionByAddress(request.query("address")));

        router.route(RequestRouter.GET_CURRENT_ADDRESS, request ->
            decompilationHandlers.getCurrentAddress());

        router.route(RequestRouter.GET_CURRENT_FUNCTION, request ->
            decompilationHandlers.getCurrentFunction());

        router.route(RequestRouter.LIST_FUNCTIONS, request -> listingHandlers.listFunctions());

        router.route(RequestRouter.DECOMPILE_FUNCTION, request ->
            decompilationHandlers.decompileFunctionByAddress(request.query("address")));

        router.route(RequestRouter.DISASSEMBLE_FUNCTION, request ->
            decompilationHandlers.disassembleFunction(request.query("address")));

        router.route(RequestRouter.SET_DECOMPILER_COMMENT, request ->
            decompilationHandlers.setDecompilerComment(
                request.form("address"), request.form("comment"))
                ? "Comment set successfully" : "Failed to set comment");

        router.route(RequestRouter.SET_DISASSEMBLY_COMMENT, request ->
            decompilationHandlers.setDisassemblyComment(
                request.form("address"), request.form("comment"))
                ? "Comment set successfully" : "Failed to set comment");

        router.route(RequestRouter.RENAME_FUNCTION_BY_ADDRESS, request ->
            mutationHandlers.renameFunctionByAddress(
                request.form("function_address"), request.form("new_name"))
                ? "Function renamed successfully" : "Failed to rename function");

        router.route(RequestRouter.SET_FUNCTION_PROTOTYPE, request -> {
            // Call the set prototype function and get detailed result
            PrototypeHandlers.PrototypeResult result = prototypeHandlers.setFunctionPrototype(
                request.form("function_address"), request.form("prototype"));

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                return successMsg;
            }
            // Return the detailed error message to the client
            return "Failed to set function prototype: " + result.getErrorMessage();
        });

        router.route(RequestRouter.SET_LOCAL_VARIABLE_TYPE, request ->
            mutationHandlers.setLocalVariableTypeResponse(
                request.form("function_address"), request.form("variable_name"),
                request.form("new_type")));

        router.route(RequestRouter.XREFS_TO, request -> xrefHandlers.getXrefsTo(
            request.query("address"), request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.XREFS_FROM, request -> xrefHandlers.getXrefsFrom(
            request.query("address"), request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.FUNCTION_XREFS, request -> xrefHandlers.getFunctionXrefs(
            request.query("name"), request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.STRINGS, request -> listingHandlers.listDefinedStrings(
            request.intQuery("offset", 0), request.intQuery("limit", 100), request.query("filter")));

        // ----------------------------------------------------------------------------------
        // Read-only memory access endpoints
        // ----------------------------------------------------------------------------------
        router.route(RequestRouter.READ_BYTES, request -> memoryHandlers.readBytes(
            request.query("address"),
            request.query("offset"),
            request.query("block"),
            request.intQuery("length", MemoryHandlers.DEFAULT_READ_LENGTH),
            request.query("format")));

        router.route(RequestRouter.READ_DATA, request -> memoryHandlers.readData(
            request.query("address"),
            request.query("offset"),
            request.query("block"),
            request.intQuery("count", 1)));

        router.route(RequestRouter.READ_STRING, request -> memoryHandlers.readString(
            request.query("address"),
            request.query("offset"),
            request.query("block"),
            request.intQuery("max_length", MemoryHandlers.DEFAULT_STRING_MAX_LENGTH),
            request.query("encoding")));

        router.route(RequestRouter.READ_POINTER, request -> memoryHandlers.readPointer(
            request.query("address"),
            request.query("offset"),
            request.query("block"),
            request.query("size") != null ? request.intQuery("size", 0) : null,
            request.boolQuery("follow")));

        // ----------------------------------------------------------------------------------
        // Endpoints describing the tool itself
        // ----------------------------------------------------------------------------------
        router.route(RequestRouter.LIST_OPEN_PROGRAMS, request -> serverHandlers.listOpenPrograms(
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.SERVER_INFO, request ->
            serverHandlers.info(httpServer.getBoundPort()));

        // ----------------------------------------------------------------------------------
        // Read-only function introspection and comment endpoints
        // ----------------------------------------------------------------------------------
        router.route(RequestRouter.GET_FUNCTION_DETAILS, request -> functionHandlers.getFunctionDetails(
            request.query("address"), request.query("name")));

        router.route(RequestRouter.LIST_FUNCTION_VARIABLES, request ->
            functionHandlers.listFunctionVariables(request.query("address"), request.query("name"),
                request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.GET_COMMENTS, request -> commentHandlers.getComments(
            request.query("address"), request.query("name"), request.query("scope"),
            request.intQuery("offset", 0), request.intQuery("limit", 200)));

        // ----------------------------------------------------------------------------------
        // Read-only data type endpoints
        // ----------------------------------------------------------------------------------
        router.route(RequestRouter.LIST_DATA_TYPES, request -> dataTypeHandlers.listDataTypes(
            request.query("filter"), request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.GET_DATA_TYPE, request ->
            dataTypeHandlers.getDataType(request.query("name")));

        // ----------------------------------------------------------------------------------
        // Read-only call-graph traversal endpoints
        // ----------------------------------------------------------------------------------
        router.route(RequestRouter.GET_CALLERS, request -> callGraphHandlers.getCallers(
            request.query("address"), request.query("name"), request.intQuery("depth", 1),
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.GET_CALLEES, request -> callGraphHandlers.getCallees(
            request.query("address"), request.query("name"), request.intQuery("depth", 1),
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        // ----------------------------------------------------------------------------------
        // Read-only search endpoints
        // ----------------------------------------------------------------------------------
        router.route(RequestRouter.SEARCH_BYTES, request -> searchHandlers.searchBytes(
            request.query("pattern"), request.query("block"),
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        router.route(RequestRouter.SEARCH_SYMBOLS, request -> searchHandlers.searchSymbols(
            request.query("query"), request.query("kind"), request.boolQuery("case_sensitive"),
            request.intQuery("offset", 0), request.intQuery("limit", 100)));

        // ----------------------------------------------------------------------------------
        // Read-only program metadata endpoint
        // ----------------------------------------------------------------------------------
        router.route(RequestRouter.GET_PROGRAM_INFO, request -> programInfoHandlers.getProgramInfo(
            request.intQuery("offset", 0), request.intQuery("limit", 100)));
    }

    @Override
    public void dispose() {
        if (httpServer != null) {
            httpServer.dispose();
            httpServer = null;
        }
        if (decompilerService != null) {
            decompilerService.dispose();
            decompilerService = null;
        }
        super.dispose();
    }
}
