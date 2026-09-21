package com.lauriewired.handlers;

import com.lauriewired.service.GhidraContext;
import com.lauriewired.util.Paginator;
import com.lauriewired.util.TextUtils;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.util.*;

/**
 * Read-only listing endpoints: functions, classes, segments, imports, exports, namespaces,
 * defined data and strings. Every response body is byte-identical to the pre-refactor one.
 */
public class ListingHandlers {

    private final GhidraContext context;

    public ListingHandlers(GhidraContext context) {
        this.context = context;
    }

    public String getAllFunctionNames(int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return Paginator.paginateWithTotal(names, offset, limit);
    }

    public String getAllClassNames(int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return Paginator.paginateWithTotal(sorted, offset, limit);
    }

    public String listSegments(int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return Paginator.paginateWithTotal(lines, offset, limit);
    }

    public String listImports(int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return Paginator.paginateWithTotal(lines, offset, limit);
    }

    public String listExports(int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return Paginator.paginateWithTotal(lines, offset, limit);
    }

    public String listNamespaces(int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return Paginator.paginateWithTotal(sorted, offset, limit);
    }

    public String listDefinedData(int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        TextUtils.escapeNonAscii(label),
                        TextUtils.escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return Paginator.paginateWithTotal(lines, offset, limit);
    }

    public String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'\n"
                + Paginator.paginateWithTotal(matches, offset, limit);
        }
        return Paginator.paginateWithTotal(matches, offset, limit);
    }

    /**
     * List all functions in the database
     */
    public String listFunctions() {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            lines.add(String.format("%s at %s",
                func.getName(),
                func.getEntryPoint()));
        }

        return Paginator.paginateWithTotal(lines, 0, lines.size());
    }

/**
 * List all defined strings in the program with their addresses
 */
    public String listDefinedStrings(int offset, int limit, String filter) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = TextUtils.escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return Paginator.paginateWithTotal(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    public boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }
}

