package com.lauriewired.handlers;

import com.lauriewired.service.AddressResolver;
import com.lauriewired.service.FunctionLookup;
import com.lauriewired.service.GhidraContext;
import com.lauriewired.util.Paginator;
import com.lauriewired.util.TextUtils;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

import java.util.ArrayList;
import java.util.List;

/**
 * Read-only program metadata endpoint: everything a client needs to orient itself in a newly
 * loaded binary from a single call.
 */
public class ProgramInfoHandlers {

    /** Upper bound for one page of entry points. */
    public static final int MAX_PAGE = 1000;

    private final GhidraContext context;

    public ProgramInfoHandlers(GhidraContext context) {
        this.context = context;
    }

    /**
     * GET /get_program_info implementation: language, compiler, memory layout and counts,
     * followed by the paginated external entry points.
     */
    public String getProgramInfo(int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return FunctionLookup.NO_PROGRAM;

        StringBuilder result = new StringBuilder();
        result.append("Program: ").append(TextUtils.escapeNonAscii(program.getName())).append('\n');
        result.append("File: ").append(TextUtils.escapeNonAscii(domainPath(program))).append('\n');
        result.append("Language: ").append(languageId(program)).append('\n');
        result.append("Compiler: ").append(compilerSpec(program)).append('\n');
        result.append("Endianness: ").append(isBigEndian(program) ? "big" : "little").append('\n');
        result.append("Address size: ").append(program.getDefaultPointerSize()).append('\n');
        result.append("Image base: ").append(address(program.getImageBase())).append('\n');
        result.append("Address range: ").append(address(program.getMinAddress()))
            .append(" - ").append(address(program.getMaxAddress())).append('\n');
        result.append("Memory blocks: ").append(program.getMemory().getBlocks().length).append('\n');
        result.append("Functions: ").append(program.getFunctionManager().getFunctionCount())
            .append('\n');
        result.append("Symbols: ").append(program.getSymbolTable().getNumSymbols()).append('\n');
        result.append("Defined data: ").append(program.getListing().getNumDefinedData()).append('\n');
        result.append("Executable format: ").append(orUnknown(program.getExecutableFormat()))
            .append('\n');
        result.append("Executable MD5: ").append(orUnknown(program.getExecutableMD5()));

        List<String> entries = entryPoints(program);
        result.append("\nEntry points:\n")
            .append(Paginator.paginateWithTotal(entries, offset, Math.min(limit, MAX_PAGE)));
        return result.toString();
    }

    /**
     * External entry points as "0x&lt;address&gt; &lt;label&gt;" lines.
     */
    private static List<String> entryPoints(Program program) {
        List<String> entries = new ArrayList<>();
        AddressIterator addresses = program.getSymbolTable().getExternalEntryPointIterator();
        while (addresses.hasNext()) {
            Address address = addresses.next();
            Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
            entries.add(String.format("  %s %s",
                AddressResolver.formatAddress(address),
                symbol == null ? "(no label)" : TextUtils.escapeNonAscii(symbol.getName())));
        }
        return entries;
    }

    private static String domainPath(Program program) {
        DomainFile file = program.getDomainFile();
        return file != null ? file.getPathname() : "";
    }

    private static String languageId(Program program) {
        Language language = program.getLanguage();
        return language != null ? language.getLanguageID().getIdAsString() : "unknown";
    }

    private static String compilerSpec(Program program) {
        CompilerSpec compilerSpec = program.getCompilerSpec();
        if (compilerSpec == null) {
            return "unknown";
        }
        String name = compilerSpec.getCompilerSpecDescription() == null ? "unknown"
            : compilerSpec.getCompilerSpecDescription().getCompilerSpecName();
        return TextUtils.escapeNonAscii(compilerSpec.getCompilerSpecID().getIdAsString())
            + " (" + TextUtils.escapeNonAscii(name) + ")";
    }

    private static boolean isBigEndian(Program program) {
        Language language = program.getLanguage();
        return language != null && language.isBigEndian();
    }

    private static String address(Address address) {
        return address == null ? "(none)" : AddressResolver.formatAddress(address);
    }

    private static String orUnknown(String value) {
        return (value == null || value.isEmpty()) ? "unknown" : TextUtils.escapeNonAscii(value);
    }
}
