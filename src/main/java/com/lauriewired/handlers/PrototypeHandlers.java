package com.lauriewired.handlers;

import com.lauriewired.service.AddressResolver;
import com.lauriewired.service.DecompilerService;
import com.lauriewired.service.GhidraContext;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.Iterator;

/**
 * Prototype and data type endpoints: function signatures and variable types.
 */
public class PrototypeHandlers {

    private final GhidraContext context;
    private final DecompilerService decompilerService;
    private final PluginTool tool;
    private final Object logSource;

    public PrototypeHandlers(GhidraContext context, DecompilerService decompilerService,
                             PluginTool tool, Object logSource) {
        this.context = context;
        this.decompilerService = decompilerService;
        this.tool = tool;
        this.logSource = logSource;
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    public static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    public PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = context.getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        PrototypeResult result = context.runInTransaction("Set function prototype", program,
            () -> applyFunctionPrototype(program, functionAddrStr, prototype), applied -> applied.isSuccess());

        if (result == null) {
            return new PrototypeResult(false, "Failed to set function prototype on Swing thread");
        }
        return result;
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    public PrototypeResult applyFunctionPrototype(Program program, String functionAddrStr, String prototype) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = AddressResolver.findFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                Msg.error(logSource, msg);
                return new PrototypeResult(false, msg);
            }

            Msg.info(logSource, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            return parseFunctionSignatureAndApply(program, addr, prototype);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            Msg.error(logSource, msg, e);
            return new PrototypeResult(false, msg);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    public void addPrototypeComment(Program program, Function func, String prototype)
            throws ContextChangeException {
        program.getListing().setComment(
            func.getEntryPoint(),
            CodeUnit.PLATE_COMMENT,
            "Setting prototype: " + prototype
        );
    }

    /**
     * Parse and apply the function signature with error handling
     */
    public PrototypeResult parseFunctionSignatureAndApply(Program program, Address addr, String prototype) {
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms =
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                Msg.error(logSource, msg);
                return new PrototypeResult(false, msg);
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                Msg.info(logSource, "Successfully applied function signature");
                return new PrototypeResult(true, "");
            }

            String msg = "Command failed: " + cmd.getStatusMsg();
            Msg.error(logSource, msg);
            return new PrototypeResult(false, msg);
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            Msg.error(logSource, msg, e);
            return new PrototypeResult(false, msg);
        }
    }

    /**
     * Helper method that performs the actual variable type change
     */
    public boolean applyVariableType(Program program, String functionAddrStr,
                                     String variableName, String newType) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = AddressResolver.findFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(logSource, "Could not find function at address: " + functionAddrStr);
                return false;
            }

            DecompileResults results = decompileFunction(func);
            if (results == null || !results.decompileCompleted()) {
                return false;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(logSource, "No high function available");
                return false;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(logSource, "Could not find variable '" + variableName + "' in decompiled function");
                return false;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(logSource, "No HighVariable found for symbol: " + variableName);
                return false;
            }

            Msg.info(logSource, "Found high variable for: " + variableName +
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(logSource, "Could not resolve data type: " + newType);
                return false;
            }

            Msg.info(logSource, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            return updateVariableType(symbol, dataType);

        } catch (Exception e) {
            Msg.error(logSource, "Error setting variable type: " + e.getMessage());
            return false;
        }
    }

    /**
     * Apply the type update in a transaction
     */
    public boolean updateVariableType(HighSymbol symbol, DataType dataType)
            throws DuplicateNameException, InvalidInputException {
        // Use HighFunctionDBUtil to update the variable with the new type
        HighFunctionDBUtil.updateDBVariable(
            symbol,                // The high symbol to modify
            symbol.getName(),      // Keep original name
            dataType,              // The new data type
            SourceType.USER_DEFINED // Mark as user-defined
        );

        Msg.info(logSource, "Successfully set variable type using HighFunctionDBUtil");
        return true;
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    public DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(logSource, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(logSource, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(logSource, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }

    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    public DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    public DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    /**
     * Find a high symbol by name in the given high function
     */
    public HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    public DecompileResults decompileFunction(Function func) {
        // Decompile the function
        DecompileResults results =
            decompilerService.decompile(func, DecompilerService.FULL_DECOMPILE_TIMEOUT_SECONDS);

        if (results == null || !results.decompileCompleted()) {
            Msg.error(logSource, "Could not decompile function: "
                + (results != null ? results.getErrorMessage() : "decompiler unavailable"));
            return null;
        }

        return results;
    }
}

