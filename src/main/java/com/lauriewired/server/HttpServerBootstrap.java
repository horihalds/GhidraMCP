package com.lauriewired.server;

import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.options.Options;
import ghidra.util.Msg;

import com.lauriewired.util.PortPicker;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * Owns the lifecycle of the embedded HTTP server: reads the configured port, creates the
 * server, installs the routes and stops the server again on shutdown.
 * <p>
 * When the configured port is taken (typically because another Ghidra window already runs the
 * plugin) the next free port is used instead, so several windows can coexist without editing
 * Tool Options. The configured value is never rewritten; {@link #getBoundPort()} reports the
 * port the server is actually listening on.
 */
public class HttpServerBootstrap {

    /**
     * Supplies the endpoint bindings; the wiring itself stays outside this class.
     */
    @FunctionalInterface
    public interface RouteRegistrar {
        void register(RequestRouter router);
    }

    private final PluginTool tool;
    private final Object logSource;
    private final String optionCategory;
    private final String portOptionName;
    private final int defaultPort;

    private HttpServer server;
    private volatile int boundPort;

    public HttpServerBootstrap(PluginTool tool, Object logSource, String optionCategory,
                               String portOptionName, int defaultPort) {
        this.tool = tool;
        this.logSource = logSource;
        this.optionCategory = optionCategory;
        this.portOptionName = portOptionName;
        this.defaultPort = defaultPort;
    }

    /**
     * Starts the HTTP server on the configured port, replacing any instance that is still
     * running (e.g. when the plugin is reloaded). If the configured port is already bound, the
     * first free port of the following {@link PortPicker#MAX_ATTEMPTS} ports is used instead;
     * the tool option keeps the configured value.
     */
    public void start(RouteRegistrar registrar) throws IOException {
        int configuredPort = readPort();

        stopRunningServer("Stopping existing HTTP server before starting new one.", 0);

        int port = PortPicker.firstFree(configuredPort, PortPicker.MAX_ATTEMPTS);
        if (port < 0) {
            Msg.error(logSource, "No free port in " + configuredPort + "-"
                + (configuredPort + PortPicker.MAX_ATTEMPTS - 1) + ": the GhidraMCP HTTP server "
                + "was not started. Free a port or change '" + portOptionName
                + "' in Tool Options.");
            return;
        }
        if (port != configuredPort) {
            Msg.warn(logSource, "Port " + configuredPort + " is already in use, so the GhidraMCP "
                + "HTTP server listens on port " + port + " instead. The '" + portOptionName
                + "' option keeps its configured value; use /info to see the actual port.");
        }

        HttpServer httpServer = HttpServer.create(new InetSocketAddress(port), 0);
        RequestRouter router = new RequestRouter(httpServer);
        registrar.register(router);
        router.install();

        httpServer.setExecutor(null);
        this.server = httpServer;
        this.boundPort = port;
        new Thread(() -> {
            try {
                httpServer.start();
                Msg.info(logSource, "GhidraMCP HTTP server started on port " + port);
            }
            catch (Exception e) {
                Msg.error(logSource,
                    "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                this.server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    /**
     * @return the port the embedded server is listening on, or 0 when it is not running
     */
    public int getBoundPort() {
        return boundPort;
    }

    /**
     * Stops the server, letting in-flight connections finish.
     */
    public void dispose() {
        stopRunningServer("Stopping GhidraMCP HTTP server...", 1);
    }

    private int readPort() {
        Options options = tool.getOptions(optionCategory);
        return options.getInt(portOptionName, defaultPort);
    }

    private void stopRunningServer(String message, int delaySeconds) {
        if (server == null) {
            return;
        }
        Msg.info(logSource, message);
        server.stop(delaySeconds); // Stop with a small delay for connections to finish
        server = null; // Nullify the reference
        boundPort = 0;
        Msg.info(logSource, "GhidraMCP HTTP server stopped.");
    }
}
