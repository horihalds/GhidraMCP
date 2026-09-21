package com.lauriewired.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

/**
 * Unit tests for {@link Paginator}. These run without a Ghidra runtime.
 */
public class PaginatorTest {

    private static List<String> items(int count) {
        List<String> items = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            items.add("item" + i);
        }
        return items;
    }

    @Test
    public void paginateReturnsRequestedWindow() {
        List<String> items = items(250);

        String page = Paginator.paginate(items, 0, 100);

        String[] lines = page.split("\n");
        assertEquals(100, lines.length);
        assertEquals("item0", lines[0]);
        assertEquals("item99", lines[99]);
    }

    @Test
    public void paginateReturnsRemainingItemsWhenLimitExceedsList() {
        assertEquals(10, Paginator.paginate(items(10), 0, 1000).split("\n").length);
    }

    @Test
    public void paginateHandlesMaxValueLimitWithoutOverflow() {
        List<String> items = items(250);

        String page = Paginator.paginate(items, 0, Integer.MAX_VALUE);

        assertEquals(250, page.split("\n").length);
    }

    @Test
    public void paginateHandlesHugeOffsetWithoutOverflow() {
        assertEquals("", Paginator.paginate(items(250), Integer.MAX_VALUE - 1, Integer.MAX_VALUE));
    }

    @Test
    public void paginateReturnsEmptyStringWhenOffsetIsPastTheEnd() {
        assertEquals("", Paginator.paginate(items(5), 5, 10));
        assertEquals("", Paginator.paginate(items(5), 500, 10));
    }

    @Test
    public void paginateClampsNegativeOffset() {
        assertEquals("item0\nitem1", Paginator.paginate(items(5), -100, 2));
    }

    @Test
    public void paginateReturnsEmptyStringForNonPositiveLimit() {
        assertEquals("", Paginator.paginate(items(5), 0, 0));
        assertEquals("", Paginator.paginate(items(5), 0, -1));
    }

    @Test
    public void paginateHandlesEmptyList() {
        assertEquals("", Paginator.paginate(new ArrayList<String>(), 0, 10));
    }

    @Test
    public void parseIntOrDefaultFallsBackForMissingOrInvalidValues() {
        assertEquals(100, Paginator.parseIntOrDefault("abc", 100));
        assertEquals(100, Paginator.parseIntOrDefault(null, 100));
        assertEquals(100, Paginator.parseIntOrDefault("", 100));
        assertEquals(-5, Paginator.parseIntOrDefault("-5", 100));
        assertEquals(42, Paginator.parseIntOrDefault("42", 100));
        assertEquals(2147483647, Paginator.parseIntOrDefault("2147483648", 2147483647));
    }

    @Test
    public void parseBooleanFlagAcceptsCommonTruthySpellings() {
        assertTrue(Paginator.parseBooleanFlag("true"));
        assertTrue(Paginator.parseBooleanFlag("TRUE"));
        assertTrue(Paginator.parseBooleanFlag("1"));
        assertTrue(Paginator.parseBooleanFlag("yes"));
        assertFalse(Paginator.parseBooleanFlag("false"));
        assertFalse(Paginator.parseBooleanFlag("0"));
        assertFalse(Paginator.parseBooleanFlag(""));
        assertFalse(Paginator.parseBooleanFlag(null));
    }
}
