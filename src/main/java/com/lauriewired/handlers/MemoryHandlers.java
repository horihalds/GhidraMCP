package com.lauriewired.handlers;

import com.lauriewired.service.AddressResolver;
import com.lauriewired.service.GhidraContext;
import com.lauriewired.util.TextUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.Symbol;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Read-only memory access endpoints: raw bytes, defined data items, strings and pointers.
 */
public class MemoryHandlers {

    public static final int DEFAULT_READ_LENGTH = 64;
    public static final int MAX_READ_LENGTH = 8192;
    public static final int MAX_DATA_ITEMS = 64;
    public static final int DEFAULT_STRING_MAX_LENGTH = 256;
    public static final int MAX_STRING_LENGTH = 4096;

    private final GhidraContext context;

    public MemoryHandlers(GhidraContext context) {
        this.context = context;
    }

    /**
     * GET /read_bytes implementation: raw bytes at an address/offset in hex or base64.
     */
    public String readBytes(String addressParam, String offsetParam, String blockParam,
                            int requestedLength, String format) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        int length = Math.max(1, Math.min(MAX_READ_LENGTH, requestedLength));

        Address start;
        try {
            start = AddressResolver.resolveFromParams(program, addressParam, offsetParam, blockParam);
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        }

        MemoryBlock block = program.getMemory().getBlock(start);
        if (block == null || !block.isInitialized()) {
            return String.format("Address %s is not in an initialized memory block", AddressResolver.formatAddress(start));
        }

        byte[] bytes = readBytesAt(program, start, length);

        boolean fileOffsetMode = (addressParam == null || addressParam.isEmpty())
                && (blockParam == null || blockParam.isEmpty())
                && offsetParam != null && !offsetParam.isEmpty();

        String header;
        if (fileOffsetMode) {
            Long fileOffset = AddressResolver.parseLongOrNull(offsetParam);
            header = String.format("# fileOffset=0x%x -> address=%s block=%s read=%d requested=%d",
                fileOffset, AddressResolver.formatAddress(start), TextUtils.escapeNonAscii(block.getName()), bytes.length, length);
        } else {
            header = String.format("# address=%s block=%s read=%d requested=%d",
                AddressResolver.formatAddress(start), TextUtils.escapeNonAscii(block.getName()), bytes.length, length);
        }

        String body = "base64".equalsIgnoreCase(format)
            ? TextUtils.encodeBase64(bytes)
            : TextUtils.formatHexDump(start.getOffset(), bytes);

        return body.isEmpty() ? header : header + "\n" + body;
    }

    /**
     * GET /read_data implementation: defined, typed data items at an address.
     */
    public String readData(String addressParam, String offsetParam, String blockParam, int requestedCount) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        int count = Math.max(1, Math.min(MAX_DATA_ITEMS, requestedCount));

        Address start;
        try {
            start = AddressResolver.resolveFromParams(program, addressParam, offsetParam, blockParam);
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        }

        List<String> lines = new ArrayList<>();
        if (program.getListing().getDefinedDataAt(start) != null) {
            DataIterator it = program.getListing().getDefinedData(start, true);
            while (it.hasNext() && lines.size() < count) {
                lines.add(formatDataItem(it.next()));
            }
        } else {
            Data containing = program.getListing().getDataContaining(start);
            if (containing != null) {
                lines.add(formatDataItem(containing));
            } else {
                return String.format("No defined data at %s; use read_bytes for raw bytes", AddressResolver.formatAddress(start));
            }
        }

        return String.join("\n", lines);
    }

    /**
     * GET /read_string implementation: decodes a C string at an address.
     */
    public String readString(String addressParam, String offsetParam, String blockParam,
                             int requestedMaxLength, String encoding) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        int maxLength = Math.max(1, Math.min(MAX_STRING_LENGTH, requestedMaxLength));

        Address start;
        try {
            start = AddressResolver.resolveFromParams(program, addressParam, offsetParam, blockParam);
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        }

        MemoryBlock block = program.getMemory().getBlock(start);
        if (block == null || !block.isInitialized()) {
            return String.format("Address %s is not in an initialized memory block", AddressResolver.formatAddress(start));
        }

        byte[] raw = readBytesAt(program, start, maxLength);

        String requested = (encoding == null || encoding.isEmpty()) ? "auto" : encoding.toLowerCase();
        String usedEncoding;
        switch (requested) {
            case "ascii": usedEncoding = "ASCII"; break;
            case "utf8": usedEncoding = "UTF-8"; break;
            case "utf16le": usedEncoding = "UTF-16LE"; break;
            case "utf16be": usedEncoding = "UTF-16BE"; break;
            default: usedEncoding = detectStringEncoding(program, start, raw); break;
        }

        int byteLength = TextUtils.stringByteLength(raw, usedEncoding);
        String decoded = new String(raw, 0, byteLength, charsetFor(usedEncoding));
        return String.format("%s: \"%s\" (%d bytes, %s)",
            AddressResolver.formatAddress(start), TextUtils.escapeString(decoded), byteLength, usedEncoding);
    }

    /**
     * GET /read_pointer implementation: reads a pointer value and optionally follows it.
     */
    public String readPointer(String addressParam, String offsetParam, String blockParam,
                              Integer requestedSize, boolean follow) {
        Program program = context.getCurrentProgram();
        if (program == null) return "No program loaded";

        int size = requestedSize != null ? requestedSize : program.getDefaultPointerSize();
        if (size != 4 && size != 8) {
            return "Invalid size: " + size + " (expected 4 or 8)";
        }

        Address start;
        try {
            start = AddressResolver.resolveFromParams(program, addressParam, offsetParam, blockParam);
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        }

        MemoryBlock block = program.getMemory().getBlock(start);
        if (block == null || !block.isInitialized()) {
            return String.format("Address %s is not in an initialized memory block", AddressResolver.formatAddress(start));
        }

        byte[] raw = readBytesAt(program, start, size);
        if (raw.length < size) {
            return String.format("Could not read %d bytes at %s (read %d)",
                size, AddressResolver.formatAddress(start), raw.length);
        }

        boolean bigEndian = program.getMemory().isBigEndian();
        long value = 0;
        for (int i = 0; i < size; i++) {
            int b = raw[i] & 0xFF;
            if (bigEndian) {
                value = (value << 8) | b;
            } else {
                value |= ((long) b) << (8 * i);
            }
        }

        Address target = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
        MemoryBlock targetBlock = program.getMemory().getBlock(target);
        String targetBlockName = targetBlock != null ? TextUtils.escapeNonAscii(targetBlock.getName()) : "unmapped";

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%s: %s -> %s (%s, block %s)",
            AddressResolver.formatAddress(start), TextUtils.hexBytes(raw), AddressResolver.formatAddress(target),
            symbolAt(program, target), targetBlockName));

        if (follow && targetBlock != null && targetBlock.isInitialized()) {
            Data data = program.getListing().getDefinedDataAt(target);
            if (data == null) {
                data = program.getListing().getDataContaining(target);
            }
            if (data != null) {
                sb.append('\n').append("target ").append(formatDataItem(data));
            } else {
                byte[] targetBytes = readBytesAt(program, target, 16);
                if (targetBytes.length > 0) {
                    sb.append('\n').append("target ").append(AddressResolver.formatAddress(target)).append(":\n");
                    sb.append(TextUtils.formatHexDump(target.getOffset(), targetBytes));
                }
            }
        }

        return sb.toString();
    }

    /**
     * Gap-tolerant chunked read: reads up to length bytes, stopping at the first unmapped
     * or uninitialized block. Returns only the bytes that were actually read.
     */
    private byte[] readBytesAt(Program program, Address start, int length) {
        Memory memory = program.getMemory();
        byte[] buffer = new byte[length];
        int totalRead = 0;
        Address current = start;
        while (totalRead < length) {
            MemoryBlock block = memory.getBlock(current);
            if (block == null || !block.isInitialized()) {
                break;
            }
            long remaining = block.getEnd().subtract(current) + 1;
            int chunk = (int) Math.min((long) (length - totalRead), remaining);
            if (chunk <= 0) {
                break;
            }
            try {
                int read = memory.getBytes(current, buffer, totalRead, chunk);
                if (read <= 0) {
                    break;
                }
                totalRead += read;
                current = current.add(read);
            } catch (MemoryAccessException e) {
                break;
            } catch (RuntimeException e) {
                break;
            }
        }
        return Arrays.copyOf(buffer, totalRead);
    }

    /**
     * Formats a defined data item as "<addr>: <label> = <value> [<type>, <n> bytes]".
     */
    private String formatDataItem(Data data) {
        String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
        String valRepr = data.getDefaultValueRepresentation();
        String typeName = data.getDataType() != null ? data.getDataType().getName() : "unknown";
        return String.format("%s: %s = %s [%s, %d bytes]",
            AddressResolver.formatAddress(data.getAddress()),
            TextUtils.escapeNonAscii(label),
            TextUtils.escapeNonAscii(valRepr != null ? valRepr : ""),
            TextUtils.escapeNonAscii(typeName),
            data.getLength());
    }

    /**
     * Charset for one of the supported string encoding names.
     */
    private Charset charsetFor(String encoding) {
        switch (encoding) {
            case "UTF-8": return StandardCharsets.UTF_8;
            case "UTF-16LE": return StandardCharsets.UTF_16LE;
            case "UTF-16BE": return StandardCharsets.UTF_16BE;
            default: return StandardCharsets.US_ASCII;
        }
    }

    /**
     * Detects the encoding of the C string at an address, defaulting to ASCII/UTF-8.
     */
    private String detectStringEncoding(Program program, Address start, byte[] bytes) {
        Data data = program.getListing().getDefinedDataAt(start);
        if (data != null && data.getDataType() != null) {
            String typeName = data.getDataType().getName().toLowerCase();
            if (typeName.contains("utf16") || typeName.contains("utf-16")
                    || typeName.contains("unicode")) {
                return program.getMemory().isBigEndian() ? "UTF-16BE" : "UTF-16LE";
            }
        }
        // Interleaved zero bytes indicate UTF-16; the zero position selects the endianness.
        boolean zeroAtOdd = false;
        boolean zeroAtEven = false;
        for (int i = 0; i + 1 < bytes.length && i < 32; i += 2) {
            if (bytes[i] != 0 && bytes[i + 1] == 0) zeroAtOdd = true;
            if (bytes[i] == 0 && bytes[i + 1] != 0) zeroAtEven = true;
        }
        if (zeroAtOdd && !zeroAtEven) return "UTF-16LE";
        if (zeroAtEven && !zeroAtOdd) return "UTF-16BE";
        return "ASCII";
    }

    /**
     * Symbol/label at an address, or "(unnamed)" when none is present.
     */
    private String symbolAt(Program program, Address address) {
        Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
        if (symbol != null && symbol.getName() != null && !symbol.getName().isEmpty()) {
            return TextUtils.escapeNonAscii(symbol.getName());
        }
        return "(unnamed)";
    }
}

