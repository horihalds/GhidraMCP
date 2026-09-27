package com.lauriewired.handlers;

import com.lauriewired.service.AddressResolver;
import com.lauriewired.service.FunctionLookup;
import com.lauriewired.service.GhidraContext;
import com.lauriewired.util.Paginator;
import com.lauriewired.util.TextUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;

/**
 * Read-only comment endpoints: the comments an earlier analysis stored at one address or
 * anywhere inside a function.
 */
public class CommentHandlers {

    /** Upper bound for one page of commented code units. */
    public static final int MAX_PAGE = 1000;

    private final GhidraContext context;

    public CommentHandlers(GhidraContext context) {
        this.context = context;
    }

    /**
     * GET /get_comments implementation.
     * <p>
     * {@code scope=address} reports the comments at the resolved address; {@code scope=function}
     * walks the function body. When no scope is given, a {@code name} means function scope and an
     * {@code address} means address scope.
     */
    public String getComments(String addressParam, String nameParam, String scopeParam,
                              int offset, int limit) {
        Program program = context.getCurrentProgram();
        if (program == null) return FunctionLookup.NO_PROGRAM;

        String scope = scopeParam;
        if (scope == null || scope.isEmpty()) {
            scope = (nameParam != null && !nameParam.isEmpty()) ? "function" : "address";
        }

        if ("function".equalsIgnoreCase(scope)) {
            return functionComments(program, addressParam, nameParam, offset, limit);
        }
        if ("address".equalsIgnoreCase(scope)) {
            return addressComments(program, addressParam, nameParam);
        }
        return "Invalid scope: " + scopeParam + " (expected address or function)";
    }

    /**
     * Comments attached to one address, one line per comment type that is present.
     */
    private String addressComments(Program program, String addressParam, String nameParam) {
        Address address;
        if (addressParam != null && !addressParam.isEmpty()) {
            address = FunctionLookup.parseAddress(program, addressParam);
            if (address == null) {
                return "Invalid address: " + addressParam;
            }
        }
        else if (nameParam != null && !nameParam.isEmpty()) {
            Function function = FunctionLookup.resolve(program, null, nameParam);
            if (function == null) {
                return "Function not found: " + nameParam;
            }
            address = function.getEntryPoint();
        }
        else {
            return "Address is required";
        }

        List<String> lines = commentLines(program, address);
        String header = AddressResolver.formatAddress(address) + ":";
        return lines.isEmpty() ? "No comments at " + header : header + "\n" + String.join("\n", lines);
    }

    /**
     * Every code unit in the function body that carries at least one comment, paginated per
     * code unit so a comment never gets separated from its address.
     */
    private String functionComments(Program program, String addressParam, String nameParam,
                                    int offset, int limit) {
        Function function = FunctionLookup.resolve(program, addressParam, nameParam);
        if (function == null) return FunctionLookup.describeMiss(addressParam, nameParam);

        List<String> entries = new ArrayList<>();
        InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            List<String> lines = commentLines(program, instruction.getAddress());
            if (!lines.isEmpty()) {
                entries.add(AddressResolver.formatAddress(instruction.getAddress()) + ":\n"
                    + String.join("\n", lines));
            }
        }

        String summary = Paginator.paginateWithTotal(entries, offset, Math.min(limit, MAX_PAGE));
        if (entries.isEmpty()) {
            return "No comments in function " + TextUtils.escapeNonAscii(function.getName())
                + "\n" + summary;
        }
        return summary;
    }

    /**
     * The PRE/EOL/PLATE/POST comments stored at one address, in that order.
     */
    private static List<String> commentLines(Program program, Address address) {
        Listing listing = program.getListing();
        List<String> lines = new ArrayList<>();
        addComment(lines, "PRE", listing.getComment(CommentType.PRE, address));
        addComment(lines, "EOL", listing.getComment(CommentType.EOL, address));
        addComment(lines, "PLATE", listing.getComment(CommentType.PLATE, address));
        addComment(lines, "POST", listing.getComment(CommentType.POST, address));
        return lines;
    }

    private static void addComment(List<String> lines, String label, String text) {
        if (text != null && !text.isEmpty()) {
            lines.add("  " + label + ": " + TextUtils.escapeString(text));
        }
    }
}
