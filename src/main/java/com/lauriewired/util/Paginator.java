package com.lauriewired.util;

import java.util.List;

/**
 * Pagination helpers shared by the listing endpoints.
 * <p>
 * This class is deliberately dependency-free so it can be exercised from a plain
 * unit test without a Ghidra runtime.
 */
public final class Paginator {

    private Paginator() {
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset &amp; limit.
     * Negative offsets are clamped to zero and the range end is computed without the
     * {@code offset + limit} integer overflow of the original implementation.
     */
    public static String paginate(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);

        if (start >= items.size() || limit <= 0) {
            return ""; // no items in range
        }

        long requestedEnd = (long) start + limit;
        int end = (int) Math.min((long) items.size(), requestedEnd);
        if (end <= start) {
            return "";
        }
        return String.join("\n", items.subList(start, end));
    }

    /**
     * Like {@link #paginate(List, int, int)} but appends a trailing summary line so a client
     * can tell whether it needs to request another page: {@code # showing <first>-<last> of
     * <total>}. An empty listing reports {@code # showing 0 of 0}; an offset past the end (or a
     * non-positive limit) reports {@code # showing 0 of <total> (offset <start>)}.
     */
    public static String paginateWithTotal(List<String> items, int offset, int limit) {
        int total = items.size();
        int start = Math.max(0, offset);

        boolean inRange = limit > 0 && start < total;
        int end = inRange ? (int) Math.min((long) total, (long) start + limit) : start;
        String body = inRange ? String.join("\n", items.subList(start, end)) : "";

        String summary;
        if (total == 0) {
            summary = "# showing 0 of 0";
        }
        else if (!inRange) {
            summary = String.format("# showing 0 of %d (offset %d)", total, start);
        }
        else {
            summary = String.format("# showing %d-%d of %d", start + 1, end, total);
        }
        return body.isEmpty() ? summary : body + "\n" + summary;
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    public static int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Parses a query flag such as ?follow=true; absent values are false.
     */
    public static boolean parseBooleanFlag(String value) {
        return value != null && (value.equalsIgnoreCase("true")
            || value.equals("1") || value.equalsIgnoreCase("yes"));
    }
}
