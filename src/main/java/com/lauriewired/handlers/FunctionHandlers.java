package com.lauriewired.handlers;

import com.lauriewired.service.AddressResolver;
import com.lauriewired.service.FunctionLookup;
import com.lauriewired.service.GhidraContext;
import com.lauriewired.util.Paginator;
import com.lauriewired.util.TextUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

/**
 * Read-only function introspection endpoints: the real declaration of a function and the
 * parameters/locals it uses.
 */
public class FunctionHandlers {

    /** Upper bound for one page of variables, so a single request cannot return everything. */
    public static final int MAX_PAGE = 1000;

    private final GhidraContext context;

    public FunctionHandlers(GhidraContext context) {
        this.context = context;
    }

    /**
     * GET /get_function_details implementation: signature, calling convention, storage and
     * flags of one function, plus its immediate caller/callee counts.
     */
    public String getFunctionDetails(String addressParam, String nameParam) {
        Program program = context.getCurrentProgram();
        if (program == null) return FunctionLookup.NO_PROGRAM;

        Function function = FunctionLookup.resolve(program, addressParam, nameParam);
        if (function == null) return FunctionLookup.describeMiss(addressParam, nameParam);

        DataType returnType = function.getReturnType();
        StringBuilder result = new StringBuilder();
        result.append("Function: ").append(TextUtils.escapeNonAscii(function.getName())).append('\n');
        result.append("Entry: ").append(AddressResolver.formatAddress(function.getEntryPoint())).append('\n');
        result.append("Signature: ").append(TextUtils.escapeNonAscii(prototype(function))).append('\n');
        result.append("Calling convention: ")
            .append(TextUtils.escapeNonAscii(function.getCallingConventionName())).append('\n');
        result.append("Return type: ").append(typeName(returnType))
            .append(" (").append(sizeOf(returnType)).append(")").append('\n');
        result.append("Parameters: ").append(function.getParameterCount()).append('\n');
        result.append("Stack frame: ").append(function.getStackFrame().getFrameSize()).append('\n');
        result.append("Body: ").append(describeBody(function.getBody())).append('\n');
        result.append(String.format("Flags: thunk=%s noReturn=%s varArgs=%s external=%s inline=%s",
            function.isThunk(), function.hasNoReturn(), function.hasVarArgs(),
            function.isExternal(), function.isInline())).append('\n');
        result.append("Callers: ")
            .append(immediateCallers(function)).append('\n');
        result.append("Callees: ").append(immediateCallees(function));
        return result.toString();
    }

    /**
     * GET /list_function_variables implementation: one line per parameter and local variable.
     */
    public String listFunctionVariables(String addressParam, String nameParam, int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return FunctionLookup.NO_PROGRAM;

        Function function = FunctionLookup.resolve(program, addressParam, nameParam);
        if (function == null) return FunctionLookup.describeMiss(addressParam, nameParam);

        List<String> lines = new ArrayList<>();
        for (Parameter parameter : function.getParameters()) {
            lines.add(formatVariable("param", parameter, parameter.isAutoParameter(), function));
        }
        for (Variable local : function.getLocalVariables()) {
            lines.add(formatVariable("local", local, false, function));
        }

        return Paginator.paginateWithTotal(lines, offset, Math.min(limit, MAX_PAGE));
    }

    /**
     * Prototype string including the calling convention; auto-parameters are skipped so the
     * client sees the declaration it can actually reproduce.
     */
    private static String prototype(Function function) {
        try {
            return function.getPrototypeString(true, true);
        }
        catch (RuntimeException e) {
            return function.getName();
        }
    }

    /**
     * "<min> - <max> (<n> bytes)" for the function body, or "(none)" for an external/thunk
     * function that has no instructions.
     */
    private static String describeBody(AddressSetView body) {
        if (body == null || body.isEmpty()) {
            return "(none)";
        }
        return String.format("%s - %s (%d bytes)",
            AddressResolver.formatAddress(body.getMinAddress()),
            AddressResolver.formatAddress(body.getMaxAddress()),
            body.getNumAddresses());
    }

    /**
     * One variable line: kind, name (marked when auto-generated), type, size, storage and the
     * address of its first use.
     */
    private static String formatVariable(String kind, Variable variable, boolean auto,
                                         Function function) {
        DataType type = variable.getDataType();
        VariableStorage storage = variable.getVariableStorage();
        return String.format("%s %s%s : %s (%s) [%s] @ %s",
            kind,
            TextUtils.escapeNonAscii(variable.getName()),
            auto ? " (auto)" : "",
            typeName(type),
            sizeOf(type),
            storage == null ? "unassigned" : TextUtils.escapeNonAscii(storage.toString()),
            firstUseAddress(function, variable));
    }

    /**
     * Address of the variable's first use, i.e. the function entry plus its first-use offset.
     */
    private static String firstUseAddress(Function function, Variable variable) {
        Address entry = function.getEntryPoint();
        if (entry != null) {
            int firstUseOffset = variable.getFirstUseOffset();
            if (firstUseOffset > 0) {
                try {
                    return AddressResolver.formatAddress(entry.add(firstUseOffset));
                }
                catch (RuntimeException e) {
                    // fall back to the entry point
                }
            }
            return AddressResolver.formatAddress(entry);
        }
        return "(unknown)";
    }

    private static String typeName(DataType type) {
        return type == null ? "unknown" : TextUtils.escapeNonAscii(type.getName());
    }

    private static String sizeOf(DataType type) {
        if (type == null || type.getLength() < 0) {
            return "unknown size";
        }
        return type.getLength() + " bytes";
    }

    /**
     * Number of distinct functions that call this one right away.
     */
    private static int immediateCallers(Function function) {
        try {
            return function.getCallingFunctions(TaskMonitor.DUMMY).size();
        }
        catch (RuntimeException e) {
            return 0;
        }
    }

    /**
     * Number of distinct functions this one calls right away.
     */
    private static int immediateCallees(Function function) {
        try {
            return function.getCalledFunctions(TaskMonitor.DUMMY).size();
        }
        catch (RuntimeException e) {
            return 0;
        }
    }
}
