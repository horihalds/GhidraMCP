package com.lauriewired.handlers;

import com.lauriewired.service.FunctionLookup;
import com.lauriewired.service.GhidraContext;
import com.lauriewired.util.Paginator;
import com.lauriewired.util.TextUtils;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;

/**
 * Read-only data type endpoints: enumerate the types a program knows and inspect a struct,
 * union, enum or typedef in full.
 */
public class DataTypeHandlers {

    /** Upper bound for one page of data types. */
    public static final int MAX_PAGE = 1000;

    private final GhidraContext context;

    public DataTypeHandlers(GhidraContext context) {
        this.context = context;
    }

    /**
     * GET /list_data_types implementation: one line per type as
     * {@code <path> (<kind>, <n> bytes)}, optionally filtered by a case-insensitive substring
     * of the name or full path.
     */
    public String listDataTypes(String filter, int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return FunctionLookup.NO_PROGRAM;

        String needle = (filter == null || filter.isEmpty()) ? null : filter.toLowerCase();
        List<String> lines = new ArrayList<>();
        for (DataType type : allTypes(program)) {
            if (needle != null && !matches(type, needle)) {
                continue;
            }
            lines.add(String.format("%s (%s, %d bytes)",
                TextUtils.escapeNonAscii(type.getPathName()), kindOf(type), type.getLength()));
        }

        return Paginator.paginateWithTotal(lines, offset, Math.min(limit, MAX_PAGE));
    }

    /**
     * GET /get_data_type implementation: fields of a structure/union, members of an enum, the
     * aliased type of a typedef, or the size of a simple type. A name that matches several types
     * is reported as ambiguous instead of picking one arbitrarily.
     */
    public String getDataType(String name) {
        Program program = context.getCurrentProgram();
        if (program == null) return FunctionLookup.NO_PROGRAM;
        if (name == null || name.isEmpty()) return "Type name is required";

        DataTypeManager manager = program.getDataTypeManager();
        DataType type = manager.getDataType(name);
        if (type == null) {
            List<DataType> candidates = new ArrayList<>();
            for (DataType candidate : allTypes(program)) {
                if (name.equals(candidate.getName()) || name.equals(candidate.getPathName())) {
                    candidates.add(candidate);
                }
            }
            if (candidates.isEmpty()) {
                return "Data type not found: '" + name + "'";
            }
            if (candidates.size() > 1) {
                return ambiguous(name, candidates);
            }
            type = candidates.get(0);
        }

        StringBuilder result = new StringBuilder();
        result.append("Name: ").append(TextUtils.escapeNonAscii(type.getName())).append('\n');
        result.append("Kind: ").append(kindOf(type)).append('\n');
        result.append("Size: ").append(type.getLength()).append('\n');
        result.append("Path: ").append(TextUtils.escapeNonAscii(type.getPathName()));

        if (type instanceof Composite) {
            appendComponents(result, (Composite) type);
        }
        else if (type instanceof Enum) {
            appendEnum(result, (Enum) type);
        }
        else if (type instanceof TypeDef) {
            result.append("\nAliased type: ")
                .append(TextUtils.escapeNonAscii(((TypeDef) type).getDataType().getPathName()));
        }
        else {
            String description = type.getDescription();
            if (description != null && !description.isEmpty()) {
                result.append("\nDescription: ").append(TextUtils.escapeString(description));
            }
        }
        return result.toString();
    }

    /**
     * Structures and unions: one line per defined field, with offset, type, size and any field
     * comment.
     */
    private static void appendComponents(StringBuilder result, Composite composite) {
        result.append("\nFields: ").append(composite.getNumDefinedComponents());
        for (DataTypeComponent field : composite.getDefinedComponents()) {
            DataType fieldType = field.getDataType();
            String fieldName = field.getFieldName();
            String comment = field.getComment();
            result.append(String.format("%n+0x%-4x %s : %s (%d)%s",
                field.getOffset(),
                TextUtils.escapeNonAscii(fieldName == null ? "(unnamed)" : fieldName),
                TextUtils.escapeNonAscii(fieldType == null ? "undefined" : fieldType.getName()),
                field.getLength(),
                (comment == null || comment.isEmpty())
                    ? "" : "   // " + TextUtils.escapeString(comment)));
        }
    }

    /**
     * Enums: member/value pairs, in declaration order, with the member comment when there is one.
     */
    private static void appendEnum(StringBuilder result, Enum enumType) {
        String[] names = enumType.getNames();
        long[] values = enumType.getValues();
        result.append("\nMembers: ").append(names.length);
        for (int i = 0; i < names.length; i++) {
            long value = i < values.length ? values[i] : 0;
            String comment = enumType.getComment(names[i]);
            result.append(String.format("%n%s = %d%s",
                TextUtils.escapeNonAscii(names[i]), value,
                (comment == null || comment.isEmpty())
                    ? "" : "   // " + TextUtils.escapeString(comment)));
        }
    }

    /**
     * "Data type 'x' is ambiguous" followed by the matching candidates.
     */
    private static String ambiguous(String name, List<DataType> candidates) {
        StringBuilder result = new StringBuilder("Data type '")
            .append(TextUtils.escapeNonAscii(name))
            .append("' is ambiguous; candidates:");
        for (DataType candidate : candidates) {
            result.append(String.format("%n  %s (%s, %d bytes)",
                TextUtils.escapeNonAscii(candidate.getPathName()), kindOf(candidate),
                candidate.getLength()));
        }
        return result.toString();
    }

    private static boolean matches(DataType type, String needle) {
        String name = type.getName();
        String path = type.getPathName();
        return (name != null && name.toLowerCase().contains(needle))
            || (path != null && path.toLowerCase().contains(needle));
    }

    /**
     * All types of the program's own data type manager.
     */
    private static List<DataType> allTypes(Program program) {
        ProgramBasedDataTypeManager manager = program.getDataTypeManager();
        List<DataType> types = new ArrayList<>();
        manager.getAllDataTypes(types);
        return types;
    }

    /**
     * The same vocabulary the endpoint documents: struct, union, enum, typedef, pointer, array,
     * function or builtin.
     */
    private static String kindOf(DataType type) {
        if (type instanceof Union) {
            return "union";
        }
        if (type instanceof Structure) {
            return "struct";
        }
        if (type instanceof Enum) {
            return "enum";
        }
        if (type instanceof TypeDef) {
            return "typedef";
        }
        if (type instanceof Pointer) {
            return "pointer";
        }
        if (type instanceof Array) {
            return "array";
        }
        if (type instanceof FunctionDefinition) {
            return "function";
        }
        return "builtin";
    }
}
