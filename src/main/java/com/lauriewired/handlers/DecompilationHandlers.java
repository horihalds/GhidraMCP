package com.lauriewired.handlers;

import com.lauriewired.service.AddressResolver;
import com.lauriewired.service.DecompilerService;
import com.lauriewired.service.GhidraContext;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;

/**
 * Decompilation, disassembly and comment endpoints.
 */
public class DecompilationHandlers {

    private final GhidraContext context;
    private final DecompilerService decompilerService;
    private final PluginTool tool;

    public DecompilationHandlers(GhidraContext context, DecompilerService decompilerService,
                                 PluginTool tool) {
        this.context = context;
        this.decompilerService = decompilerService;
        this.tool = tool;
    }

    public String decompileFunctionByName(String name) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result = decompilerService.decompile(func);
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    /**
     * Get function by address
     */
    public String getFunctionByAddress(String addressStr) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    public String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    public String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        // The location belongs to the program the user is looking at, so a request-scoped
        // program must not be consulted here.
        Program program = context.getToolProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * Decompile a function at the given address
     */
    public String decompileFunctionByAddress(String addressStr) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = AddressResolver.findFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompileResults result = decompilerService.decompile(func);

            return (result != null && result.decompileCompleted())
                ? result.getDecompiledFunction().getC()
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    public String disassembleFunction(String addressStr) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = AddressResolver.findFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    public boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = context.getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        Boolean applied = context.runInTransaction(transactionName, program, () -> {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            program.getListing().setComment(addr, commentType, comment);
            return true;
        }, committed -> committed);
        return Boolean.TRUE.equals(applied);
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    public boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    public boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }
}

