package com.lauriewired.service;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;

/**
 * Resolves the address an endpoint was asked about and formats addresses for responses.
 * <p>
 * The addressing precedence of the HTTP API is preserved: {@code address} &gt;
 * {@code block} + {@code offset} &gt; {@code offset} (interpreted as a file offset).
 * It also maps a resolved address to the function that contains it.
 */
public final class AddressResolver {

    private AddressResolver() {
    }

    /**
     * Parses a decimal or "0x"-prefixed hexadecimal number; returns null when unparsable.
     */
    public static Long parseLongOrNull(String value) {
        if (value == null || value.isEmpty()) return null;
        String trimmed = value.trim();
        try {
            if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
                return Long.parseUnsignedLong(trimmed.substring(2), 16);
            }
            return Long.parseLong(trimmed);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Formats an address with a "0x" prefix, e.g. "0x140001000".
     */
    public static String formatAddress(Address address) {
        return "0x" + address.toString(false);
    }

    /**
     * Resolves an address from the request parameters, applying the precedence
     * address &gt; block+offset &gt; file offset. Throws IllegalArgumentException with a
     * user-facing message when no valid addressing mode was supplied.
     */
    public static Address resolveFromParams(Program program, String addressParam,
                                            String offsetParam, String blockParam) {
        if (addressParam != null && !addressParam.isEmpty()) {
            Address addr = null;
            try {
                addr = program.getAddressFactory().getAddress(addressParam);
            } catch (Exception e) {
                addr = null;
            }
            if (addr == null) {
                Long numeric = parseLongOrNull(addressParam);
                if (numeric == null) {
                    throw new IllegalArgumentException("Invalid address: " + addressParam);
                }
                addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(numeric);
            }
            return addr;
        }

        if (blockParam != null && !blockParam.isEmpty()) {
            MemoryBlock block = program.getMemory().getBlock(blockParam);
            if (block == null) {
                throw new IllegalArgumentException("Unknown memory block: " + blockParam);
            }
            long blockOffset = 0;
            if (offsetParam != null && !offsetParam.isEmpty()) {
                Long numeric = parseLongOrNull(offsetParam);
                if (numeric == null) {
                    throw new IllegalArgumentException("Invalid offset: " + offsetParam);
                }
                blockOffset = numeric;
            }
            try {
                return block.getStart().add(blockOffset);
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("Invalid offset: " + offsetParam);
            }
        }

        if (offsetParam != null && !offsetParam.isEmpty()) {
            Long numeric = parseLongOrNull(offsetParam);
            if (numeric == null) {
                throw new IllegalArgumentException("Invalid offset: " + offsetParam);
            }
            Address addr = addressForFileOffset(program, numeric);
            if (addr == null) {
                throw new IllegalArgumentException(String.format("No memory block covers file offset 0x%x", numeric));
            }
            return addr;
        }

        throw new IllegalArgumentException("Address, offset or block+offset is required");
    }

    /**
     * Maps a raw file offset to the address that maps it, or null when no block covers it.
     */
    public static Address addressForFileOffset(Program program, long fileOffset) {
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
                Address addr = info.locateAddressForFileOffset(fileOffset);
                if (addr != null) {
                    return addr;
                }
            }
        }
        return null;
    }

    /**
     * Human-readable description of the resolved address: the containing memory block name.
     */
    public static String describeAddress(Program program, Address address) {
        MemoryBlock block = program.getMemory().getBlock(address);
        return block != null ? block.getName() : "(unmapped)";
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    public static Function findFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }
}
