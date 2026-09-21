package com.lauriewired.service;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

/**
 * Resolves the {@code address} / {@code name} pair the function-oriented endpoints accept.
 * <p>
 * The {@code address} parameter takes precedence and, like
 * {@link AddressResolver#findFunctionForAddress}, also matches the function that <em>contains</em>
 * the address. A {@code name} is matched exactly against the program's functions.
 */
public final class FunctionLookup {

    /** Response when no program is loaded at all. */
    public static final String NO_PROGRAM = "No program loaded";

    private FunctionLookup() {
    }

    /**
     * @return the requested function, or null when no parameter was given or nothing matched
     */
    public static Function resolve(Program program, String addressParam, String nameParam) {
        if (addressParam != null && !addressParam.isEmpty()) {
            Address address = parseAddress(program, addressParam);
            return address == null ? null : AddressResolver.findFunctionForAddress(program, address);
        }
        if (nameParam != null && !nameParam.isEmpty()) {
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function function = functions.next();
                if (nameParam.equals(function.getName())) {
                    return function;
                }
            }
        }
        return null;
    }

    /**
     * Parses an address the way {@link AddressResolver#resolveFromParams} does: as a Ghidra
     * address first, then as a decimal or "0x"-prefixed number.
     *
     * @return the address, or null when the value is unparsable
     */
    public static Address parseAddress(Program program, String addressParam) {
        try {
            Address address = program.getAddressFactory().getAddress(addressParam);
            if (address != null) {
                return address;
            }
        }
        catch (RuntimeException e) {
            // fall through to the numeric form
        }
        Long numeric = AddressResolver.parseLongOrNull(addressParam);
        return numeric == null ? null
            : program.getAddressFactory().getDefaultAddressSpace().getAddress(numeric);
    }

    /**
     * Explains why {@link #resolve} returned nothing, so every endpoint reports the same text.
     */
    public static String describeMiss(String addressParam, String nameParam) {
        boolean hasAddress = addressParam != null && !addressParam.isEmpty();
        boolean hasName = nameParam != null && !nameParam.isEmpty();
        if (!hasAddress && !hasName) {
            return "Address or name is required";
        }
        if (hasAddress) {
            return "No function at or containing " + addressParam;
        }
        return "Function not found: " + nameParam;
    }
}
