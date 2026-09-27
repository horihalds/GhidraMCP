package com.lauriewired.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Pins the parsing and matching of hex byte patterns with {@code ??} wildcards.
 */
public class BytePatternTest {

    @Test
    public void parsesAndCanonicalisesHexTokens() {
        BytePattern pattern = BytePattern.parse("48 8B ?? 40");

        assertEquals(4, pattern.length());
        assertEquals("48 8b ?? 40", pattern.text());
    }

    @Test
    public void acceptsExtraWhitespaceBetweenTokens() {
        assertEquals("48 8b ?? 40", BytePattern.parse("  48   8b\t??\n40 ").text());
    }

    @Test
    public void matchesAWildcardInTheMiddle() {
        BytePattern pattern = BytePattern.parse("48 8b ?? 40");

        assertTrue(pattern.matchesAt(data(0x48, 0x8b, 0x05, 0x40), 0));
        // the wildcard matches whichever byte happens to be there...
        assertTrue(pattern.matchesAt(data(0x48, 0x8b, 0xff, 0x40), 0));
        // ...while the fixed positions have to be exact
        assertFalse(pattern.matchesAt(data(0x48, 0x8b, 0x05, 0x41), 0));
        assertFalse(pattern.matchesAt(data(0x49, 0x8b, 0x05, 0x40), 0));
    }

    @Test
    public void matchesWildcardsAtTheStartAndEnd() {
        assertTrue(BytePattern.parse("?? 8b 05").matchesAt(data(0x00, 0x8b, 0x05), 0));
        assertTrue(BytePattern.parse("8b 05 ??").matchesAt(data(0x8b, 0x05, 0xff), 0));
        assertFalse(BytePattern.parse("8b 05 ??").matchesAt(data(0x8b, 0x06, 0xff), 0));
    }

    @Test
    public void wildcardOnlyPatternMatchesAnythingOfItsLength() {
        BytePattern pattern = BytePattern.parse("?? ??");

        assertTrue(pattern.matchesAt(data(0x00, 0x00), 0));
        assertTrue(pattern.matchesAt(data(0xff, 0x7f), 0));
        assertFalse(pattern.matchesAt(data(0x00, 0x00, 0x00), 2));
    }

    @Test
    public void matchesAtAnOffsetInsideTheBuffer() {
        BytePattern pattern = BytePattern.parse("8b 05");

        assertTrue(pattern.matchesAt(data(0x48, 0x48, 0x8b, 0x05), 2));
        assertFalse(pattern.matchesAt(data(0x48, 0x8b, 0x48, 0x48), 0));
    }

    @Test
    public void doesNotMatchABufferShorterThanThePattern() {
        BytePattern pattern = BytePattern.parse("48 8b 05 40");

        assertFalse(pattern.matchesAt(data(0x48, 0x8b), 0));
        assertFalse(pattern.matchesAt(new byte[0], 0));
    }

    @Test
    public void doesNotMatchAnOffsetOutsideTheBuffer() {
        BytePattern pattern = BytePattern.parse("48 8b");

        assertFalse(pattern.matchesAt(data(0x48, 0x8b), -1));
        assertFalse(pattern.matchesAt(data(0x48, 0x8b), 1));
        assertFalse(pattern.matchesAt(null, 0));
    }

    @Test
    public void renderAtRendersTheActualBytes() {
        BytePattern pattern = BytePattern.parse("48 8b ?? 40");

        assertEquals("48 8b 05 40", pattern.renderAt(data(0x48, 0x8b, 0x05, 0x40), 0));
    }

    @Test
    public void rejectsANonHexTokenNamingIt() {
        IllegalArgumentException e =
            assertThrows(IllegalArgumentException.class, () -> BytePattern.parse("48 xZ"));

        assertTrue(e.getMessage(), e.getMessage().contains("'xZ'"));
    }

    @Test
    public void rejectsAnOddLengthTokenNamingIt() {
        IllegalArgumentException e =
            assertThrows(IllegalArgumentException.class, () -> BytePattern.parse("48 4 05"));

        assertTrue(e.getMessage(), e.getMessage().contains("'4'"));
    }

    @Test
    public void rejectsAnEmptyPattern() {
        assertThrows(IllegalArgumentException.class, () -> BytePattern.parse(""));
        assertThrows(IllegalArgumentException.class, () -> BytePattern.parse("   "));
        assertThrows(IllegalArgumentException.class, () -> BytePattern.parse(null));
    }

    @Test
    public void rejectsAPatternLongerThanTheCap() {
        StringBuilder tooLong = new StringBuilder();
        for (int i = 0; i < BytePattern.MAX_PATTERN_BYTES + 1; i++) {
            tooLong.append("90 ");
        }

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> BytePattern.parse(tooLong.toString()));

        assertTrue(e.getMessage(), e.getMessage().contains(String.valueOf(BytePattern.MAX_PATTERN_BYTES)));
    }

    @Test
    public void acceptsAPatternAtTheCap() {
        StringBuilder atCap = new StringBuilder();
        for (int i = 0; i < BytePattern.MAX_PATTERN_BYTES; i++) {
            atCap.append("90 ");
        }

        assertEquals(BytePattern.MAX_PATTERN_BYTES, BytePattern.parse(atCap.toString()).length());
    }

    private static byte[] data(int... values) {
        byte[] bytes = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            bytes[i] = (byte) values[i];
        }
        return bytes;
    }
}
