package com.lauriewired.handlers;

import com.lauriewired.service.GhidraContext;
import com.lauriewired.util.Paginator;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Endpoints that describe the tool's open programs rather than the contents of one of them.
 */
public class ServerHandlers {

    /** Resource holding the extension's own metadata, including its version. */
    private static final String VERSION_RESOURCE = "extension.properties";

    private final GhidraContext context;

    public ServerHandlers(GhidraContext context) {
        this.context = context;
    }

    /**
     * Lists the programs open in this Ghidra tool, one line per program:
     * {@code <name> | <path> | <language id> | <current|open>}.
     */
    public String listOpenPrograms(int offset, int limit) {
        Program current = context.getToolProgram();

        List<String> lines = new ArrayList<>();
        for (Program program : context.getOpenPrograms()) {
            lines.add(String.format("%s | %s | %s | %s",
                program.getName(),
                domainPath(program),
                languageId(program),
                program.equals(current) ? "current" : "open"));
        }
        return Paginator.paginate(lines, offset, limit);
    }

    /**
     * Describes this server as {@code key=value} lines. The {@code service} line is the
     * fingerprint the MCP bridge looks for when it probes a port, and {@code port} is the port
     * the server is really bound to, which may differ from the configured one when several
     * Ghidra windows are running.
     *
     * @param port the port the embedded HTTP server is listening on
     */
    public String info(int port) {
        Program current = context.getToolProgram();
        return "service=ghidra-mcp\n"
            + "version=" + extensionVersion() + "\n"
            + "port=" + port + "\n"
            + "programs=" + context.getOpenPrograms().length + "\n"
            + "current=" + (current != null ? current.getName() : "(none)");
    }

    private static String extensionVersion() {
        Properties properties = new Properties();
        try (InputStream stream = ServerHandlers.class.getClassLoader()
            .getResourceAsStream(VERSION_RESOURCE)) {
            if (stream == null) {
                return "unknown";
            }
            properties.load(stream);
        }
        catch (IOException e) {
            return "unknown";
        }
        String version = properties.getProperty("version");
        return (version == null || version.isEmpty()) ? "unknown" : version;
    }

    private static String domainPath(Program program) {
        DomainFile file = program.getDomainFile();
        return file != null ? file.getPathname() : "";
    }

    private static String languageId(Program program) {
        Language language = program.getLanguage();
        return language != null ? language.getLanguageID().getIdAsString() : "unknown";
    }
}
