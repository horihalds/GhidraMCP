package com.lauriewired.handlers;

import com.lauriewired.service.AddressResolver;
import com.lauriewired.service.FunctionLookup;
import com.lauriewired.service.GhidraContext;
import com.lauriewired.util.BytePattern;
import com.lauriewired.util.Paginator;
import com.lauriewired.util.TextUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Read-only search endpoints: a hex signature with wildcards in memory, and a regular
 * expression over function/label/data names.
 */
public class SearchHandlers {

    /** Upper bound for one page of matches. */
    public static final int MAX_PAGE = 1000;

    /** Upper bound for one page of byte matches; the scan stops as soon as it is filled. */
    public static final int MAX_MATCHES = 5000;

    /** Memory is read in chunks of this size, with an overlap of one pattern minus one byte. */
    private static final int CHUNK_SIZE = 64 * 1024;

    private final GhidraContext context;

    public SearchHandlers(GhidraContext context) {
        this.context = context;
    }

    /**
     * GET /search_bytes implementation: find a hex pattern in initialized memory. The scan
     * stops once the requested page is full, so an early page never walks the whole image.
     */
    public String searchBytes(String patternParam, String blockParam, int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return FunctionLookup.NO_PROGRAM;
        if (patternParam == null || patternParam.trim().isEmpty()) return "Pattern is required";

        BytePattern pattern;
        try {
            pattern = BytePattern.parse(patternParam);
        }
        catch (IllegalArgumentException e) {
            return e.getMessage();
        }

        Memory memory = program.getMemory();
        if (blockParam != null && !blockParam.isEmpty() && memory.getBlock(blockParam) == null) {
            return "Unknown memory block: " + blockParam;
        }

        int pageLimit = Math.min(limit, MAX_MATCHES);
        long wanted = (long) Math.max(0, offset) + Math.max(0, pageLimit);
        List<String> matches = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || matches.size() >= wanted) {
                continue;
            }
            if (blockParam != null && !blockParam.isEmpty() && !blockParam.equals(block.getName())) {
                continue;
            }
            scanBlock(program, block, pattern, matches, wanted);
        }

        return Paginator.paginateWithTotal(matches, offset, pageLimit);
    }

    /**
     * GET /search_symbols implementation: a regular expression over function, label and data
     * names, case-insensitive unless {@code case_sensitive=true}.
     */
    public String searchSymbols(String query, String kindParam, boolean caseSensitive,
                                int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return FunctionLookup.NO_PROGRAM;
        if (query == null || query.isEmpty()) return "Query is required";

        String kind = (kindParam == null || kindParam.isEmpty()) ? "any" : kindParam.toLowerCase();
        if (!"any".equals(kind) && !"function".equals(kind) && !"label".equals(kind)
                && !"data".equals(kind)) {
            return "Invalid kind: " + kindParam + " (expected any, function, label or data)";
        }

        Pattern regex;
        try {
            regex = Pattern.compile(query, caseSensitive ? 0 : Pattern.CASE_INSENSITIVE);
        }
        catch (PatternSyntaxException e) {
            return "Invalid regular expression: " + e.getMessage();
        }

        List<String> lines = new ArrayList<>();
        if ("any".equals(kind) || "function".equals(kind)) {
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function function = functions.next();
                if (regex.matcher(function.getName()).find()) {
                    lines.add(String.format("%s function @ %s",
                        TextUtils.escapeNonAscii(function.getName(true)),
                        AddressResolver.formatAddress(function.getEntryPoint())));
                }
            }
        }

        if (!"function".equals(kind)) {
            for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
                if (symbol.getSymbolType() != SymbolType.LABEL) {
                    continue;
                }
                boolean isData =
                    program.getListing().getDefinedDataAt(symbol.getAddress()) != null;
                if ("data".equals(kind) && !isData) {
                    continue;
                }
                if ("label".equals(kind) && isData) {
                    continue;
                }
                if (!regex.matcher(symbol.getName()).find()) {
                    continue;
                }
                lines.add(String.format("%s %s @ %s",
                    TextUtils.escapeNonAscii(symbol.getName(true)),
                    isData ? "data" : "label",
                    AddressResolver.formatAddress(symbol.getAddress())));
            }
        }

        return Paginator.paginateWithTotal(lines, offset, Math.min(limit, MAX_PAGE));
    }

    /**
     * Scans one block in 64 KiB windows, re-reading the pattern-minus-one tail of each window so
     * a match spanning a window boundary is still found exactly once.
     */
    private static void scanBlock(Program program, MemoryBlock block, BytePattern pattern,
                                  List<String> matches, long wanted) {
        Address start = block.getStart();
        long blockSize = block.getSize();
        int overlap = pattern.length() - 1;

        for (long position = 0; position < blockSize && matches.size() < wanted;
                position += CHUNK_SIZE) {
            int length = (int) Math.min((long) CHUNK_SIZE + overlap, blockSize - position);
            byte[] data = new byte[length];
            try {
                block.getBytes(start.add(position), data);
            }
            catch (MemoryAccessException e) {
                continue;
            }

            int fresh = (int) Math.min(CHUNK_SIZE, blockSize - position);
            for (int i = 0; i < fresh && matches.size() < wanted; i++) {
                if (pattern.matchesAt(data, i)) {
                    matches.add(describeMatch(program, block, start.add(position + i), data, i,
                        pattern));
                }
            }
        }
    }

    /**
     * "0x<address> in <block> (<containing function>): <actual bytes>".
     */
    private static String describeMatch(Program program, MemoryBlock block, Address address,
                                        byte[] data, int offset, BytePattern pattern) {
        Function function = program.getFunctionManager().getFunctionContaining(address);
        String location = function == null
            ? block.getName()
            : block.getName() + " (" + TextUtils.escapeNonAscii(function.getName()) + ")";
        return String.format("%s in %s: %s",
            AddressResolver.formatAddress(address), location, pattern.renderAt(data, offset));
    }
}
