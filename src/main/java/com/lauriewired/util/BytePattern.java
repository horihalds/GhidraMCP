package com.lauriewired.util;

/**
 * A byte signature with optional wildcards, parsed from a {@code "48 8b ?? 40"} style string.
 * <p>
 * Deliberately free of Ghidra types so parsing and matching can be unit-tested without a
 * program database; the search endpoint only walks memory and calls {@link #matchesAt}.
 */
public final class BytePattern {

    /** Upper bound for a pattern, so a search cannot be asked to scan for something enormous. */
    public static final int MAX_PATTERN_BYTES = 256;

    private static final String WILDCARD_TOKEN = "??";

    private final byte[] bytes;
    private final boolean[] wildcards;
    private final String text;

    private BytePattern(byte[] bytes, boolean[] wildcards) {
        this.bytes = bytes;
        this.wildcards = wildcards;
        this.text = format(bytes, wildcards);
    }

    /**
     * Parses whitespace-separated tokens, each either two hex digits or {@code ??}.
     *
     * @throws IllegalArgumentException when the pattern is empty, too long or has a bad token;
     *     the message names the offending token
     */
    public static BytePattern parse(String pattern) {
        if (pattern == null || pattern.trim().isEmpty()) {
            throw new IllegalArgumentException("Empty byte pattern");
        }
        String[] tokens = pattern.trim().split("\\s+");
        if (tokens.length > MAX_PATTERN_BYTES) {
            throw new IllegalArgumentException(
                "Byte pattern is longer than " + MAX_PATTERN_BYTES + " bytes");
        }

        byte[] bytes = new byte[tokens.length];
        boolean[] wildcards = new boolean[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i];
            if (WILDCARD_TOKEN.equals(token)) {
                wildcards[i] = true;
                continue;
            }
            if (token.length() != 2) {
                throw new IllegalArgumentException(invalidToken(token));
            }
            int high = Character.digit(token.charAt(0), 16);
            int low = Character.digit(token.charAt(1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException(invalidToken(token));
            }
            bytes[i] = (byte) ((high << 4) | low);
        }
        return new BytePattern(bytes, wildcards);
    }

    /**
     * @return the number of bytes the pattern spans
     */
    public int length() {
        return bytes.length;
    }

    /**
     * @return the canonical form of the pattern: lower-case hex with {@code ??} placeholders
     */
    public String text() {
        return text;
    }

    /**
     * @return true when {@code data} has this pattern at {@code offset}; a wildcard byte always
     *     matches and a buffer that is too short never does
     */
    public boolean matchesAt(byte[] data, int offset) {
        if (data == null || offset < 0 || (long) offset + bytes.length > data.length) {
            return false;
        }
        for (int i = 0; i < bytes.length; i++) {
            if (!wildcards[i] && data[offset + i] != bytes[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Renders the actual bytes at a match, in the same lower-case hex style as the rest of the
     * bridge, so a caller can see what the wildcard positions matched.
     */
    public String renderAt(byte[] data, int offset) {
        if (data == null || offset < 0 || (long) offset + bytes.length > data.length) {
            return text;
        }
        StringBuilder rendered = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                rendered.append(' ');
            }
            rendered.append(String.format("%02x", data[offset + i] & 0xff));
        }
        return rendered.toString();
    }

    private static String invalidToken(String token) {
        return "Invalid byte pattern token '" + token + "' (expected two hex digits or ??)";
    }

    private static String format(byte[] bytes, boolean[] wildcards) {
        StringBuilder text = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                text.append(' ');
            }
            text.append(wildcards[i] ? WILDCARD_TOKEN : String.format("%02x", bytes[i] & 0xff));
        }
        return text.toString();
    }
}
