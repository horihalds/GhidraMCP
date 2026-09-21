package com.lauriewired.handlers;

import com.lauriewired.service.AddressResolver;
import com.lauriewired.service.DecompilerService;
import com.lauriewired.service.GhidraContext;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.util.Iterator;

/**
 * Mutating endpoints: renames and local variable type changes. Every mutation runs through
 * {@link GhidraContext#runInTransaction}.
 */
public class MutationHandlers {

    private final GhidraContext context;
    private final DecompilerService decompilerService;
    private final PrototypeHandlers prototypes;
    private final Object logSource;

    public MutationHandlers(GhidraContext context, DecompilerService decompilerService,
                            PrototypeHandlers prototypes, Object logSource) {
        this.context = context;
        this.decompilerService = decompilerService;
        this.prototypes = prototypes;
        this.logSource = logSource;
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
     * Compare the given HighFunction's idea of the prototype with the Function's idea.
     * Return true if there is a difference. If a specific symbol is being changed,
     * it can be passed in to check whether or not the prototype is being affected.
     * @param highSymbol (if not null) is the symbol being modified
     * @param hfunction is the given HighFunction
     * @return true if there is a difference (and a full commit is required)
     */
    protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }

        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            VariableStorage storage = param.getStorage();
            // Don't compare using the equals method so that DynamicVariableStorage can match
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }

        return false;
    }

    public boolean renameFunction(String oldName, String newName) {
        Program program = context.getCurrentProgram();
        if (program == null) return false;

        Boolean renamed = context.runInTransaction("Rename function via HTTP", program, () -> {
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (func.getName().equals(oldName)) {
                    func.setName(newName, SourceType.USER_DEFINED);
                    return true;
                }
            }
            return false;
        }, committed -> committed);
        return Boolean.TRUE.equals(renamed);
    }

    public void renameDataAtAddress(String addressStr, String newName) {
        Program program = context.getCurrentProgram();
        if (program == null) return;

        context.runInTransaction("Rename data", program, () -> {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Listing listing = program.getListing();
            Data data = listing.getDefinedDataAt(addr);
            if (data != null) {
                SymbolTable symTable = program.getSymbolTable();
                Symbol symbol = symTable.getPrimarySymbol(addr);
                if (symbol != null) {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                } else {
                    symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                }
            }
            return Boolean.TRUE;
        });
    }

    public String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decompilerService.decompile(func);
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();

            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        Boolean renamed = context.runInTransaction("Rename variable", program, () -> {
            try {
                if (commitRequired) {
                    HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                        ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                }
                HighFunctionDBUtil.updateDBVariable(
                    finalHighSymbol,
                    newVarName,
                    null,
                    SourceType.USER_DEFINED
                );
                return true;
            }
            catch (Exception e) {
                Msg.error(logSource, "Failed to rename variable", e);
                return false;
            }
        }, committed -> committed);

        if (renamed == null) {
            return "Failed to execute rename on Swing thread";
        }
        return renamed ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Rename a function by its address
     */
    public boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = context.getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
            newName == null || newName.isEmpty()) {
            return false;
        }

        Boolean renamed = context.runInTransaction("Rename function by address", program,
            () -> performFunctionRename(program, functionAddrStr, newName), committed -> committed);
        return Boolean.TRUE.equals(renamed);
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    public boolean performFunctionRename(Program program, String functionAddrStr, String newName)
            throws DuplicateNameException, InvalidInputException {
        Address addr = program.getAddressFactory().getAddress(functionAddrStr);
        Function func = AddressResolver.findFunctionForAddress(program, addr);

        if (func == null) {
            Msg.error(logSource, "Could not find function at address: " + functionAddrStr);
            return false;
        }

        func.setName(newName, SourceType.USER_DEFINED);
        return true;
    }

    public boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = context.getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        Boolean applied = context.runInTransaction("Set variable type", program,
            () -> prototypes.applyVariableType(program, functionAddrStr, variableName, newType),
            committed -> committed);
        return Boolean.TRUE.equals(applied);
    }

    /**
     * Builds the detailed response of the /set_local_variable_type endpoint.
     */
    public String setLocalVariableTypeResponse(String functionAddress, String variableName,
                                                String newType) {
        // Capture detailed information about setting the type
        StringBuilder responseMsg = new StringBuilder();
        responseMsg.append("Setting variable type: ").append(variableName)
                  .append(" to ").append(newType)
                  .append(" in function at ").append(functionAddress).append("\n\n");

        // Attempt to find the data type in various categories
        Program program = context.getCurrentProgram();
        if (program != null) {
            DataTypeManager dtm = program.getDataTypeManager();
            DataType directType = prototypes.findDataTypeByNameInAllCategories(dtm, newType);
            if (directType != null) {
                responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
            } else if (newType.startsWith("P") && newType.length() > 1) {
                String baseTypeName = newType.substring(1);
                DataType baseType = prototypes.findDataTypeByNameInAllCategories(dtm, baseTypeName);
                if (baseType != null) {
                    responseMsg.append("Found base type for pointer: ")
                               .append(baseType.getPathName()).append("\n");
                } else {
                    responseMsg.append("Base type not found for pointer: ")
                               .append(baseTypeName).append("\n");
                }
            } else {
                responseMsg.append("Type not found directly: ").append(newType).append("\n");
            }
        }

        // Try to set the type
        boolean success = setLocalVariableType(functionAddress, variableName, newType);

        String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
        responseMsg.append("\nResult: ").append(successMsg);

        return responseMsg.toString();
    }
}

