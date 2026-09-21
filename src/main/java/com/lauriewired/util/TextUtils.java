package com.lauriewired.util;

import java.util.Base64;

/**
 * Dependency-free text and byte formatting helpers shared by the HTTP handlers.
 * <p>
 * Nothing in here touches Ghidra types, so the behaviour is unit-testable without
 * launching the tool.
 */
public final class TextUtils {

    private TextUtils() {
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     * <p>
     * Non-ASCII characters are emitted as full UTF-16 code units ({@code \x<hex>}); the
     * previous implementation masked every character with {@code 0xFF}, which truncated
     * anything above U+00FF to a single bogus byte.
     */
    public static String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c));
            }
        }
        return sb.toString();
    }

    /**
     * Escape special characters in a string for display
     */
    public static String escapeString(String input) {
        if (input == null) return "";

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Space-separated hex representation of bytes, e.g. "00 20 40 00".
     */
    public static String hexBytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02x", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Encodes bytes as a single base64 line.
     */
    public static String encodeBase64(byte[] bytes) {
        return "base64:" + Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Length in bytes of a C string, stopping at the first terminator;<br>
     * the terminator is two bytes wide for UTF-16 encodings.
     */
    public static int stringByteLength(byte[] bytes, String encoding) {
        if (encoding.startsWith("UTF-16")) {
            for (int i = 0; i + 1 < bytes.length; i += 2) {
                if (bytes[i] == 0 && bytes[i + 1] == 0) return i;
            }
            return bytes.length % 2 == 0 ? bytes.length : bytes.length - 1;
        }
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == 0) return i;
        }
        return bytes.length;
    }

    /**
     * Formats bytes as 16-bytes-per-line hex with an ASCII gutter, the line prefix
     * being the address of the first byte of the line.
     */
    public static String formatHexDump(long baseAddress, byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i += 16) {
            int end = Math.min(i + 16, bytes.length);
            StringBuilder hex = new StringBuilder();
            StringBuilder ascii = new StringBuilder();
            for (int j = i; j < end; j++) {
                int b = bytes[j] & 0xFF;
                hex.append(String.format("%02x", b));
                if (j < end - 1) {
                    hex.append(' ');
                }
                ascii.append((b >= 32 && b < 127) ? (char) b : '.');
            }
            for (int k = 0; k < 16 - (end - i); k++) {
                hex.append("   ");
            }
            sb.append(String.format("0x%x: %s |%s|", baseAddress + i, hex, ascii));
            if (end < bytes.length) {
                sb.append('\n');
            }
        }
        return sb.toString();
    }
}
