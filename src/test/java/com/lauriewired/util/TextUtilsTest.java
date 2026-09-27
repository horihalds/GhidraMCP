package com.lauriewired.util;

import static org.junit.Assert.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.Test;

/**
 * Unit tests for {@link TextUtils}. These run without a Ghidra runtime.
 */
public class TextUtilsTest {

    private static String repeat(String value, int times) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < times; i++) {
            sb.append(value);
        }
        return sb.toString();
    }

    @Test
    public void escapeNonAsciiLeavesPureAsciiUntouched() {
        assertEquals("main", TextUtils.escapeNonAscii("main"));
        assertEquals("main_01", TextUtils.escapeNonAscii("main_01"));
    }

    @Test
    public void escapeNonAsciiEscapesAccentedCharacterAsFullCodeUnit() {
        assertEquals("caf\\xe9", TextUtils.escapeNonAscii("caf\u00e9"));
    }

    @Test
    public void escapeNonAsciiDoesNotMaskCodePointsAbove0xff() {
        assertEquals("\\x2192", TextUtils.escapeNonAscii("\u2192"));
        assertEquals("\\x4e2d", TextUtils.escapeNonAscii("\u4e2d"));
    }

    @Test
    public void escapeNonAsciiEscapesControlCharacters() {
        assertEquals("a\\xd\\xa", TextUtils.escapeNonAscii("a\r\n"));
        assertEquals("", TextUtils.escapeNonAscii(null));
    }

    @Test
    public void escapeStringMapsWhitespaceEscapes() {
        assertEquals("a\\nb\\rc\\td", TextUtils.escapeString("a\nb\rc\td"));
    }

    @Test
    public void escapeStringEmitsHexEscapesForOtherBytes() {
        assertEquals("\\x00", TextUtils.escapeString("\u0000"));
        assertEquals("\\xe9", TextUtils.escapeString("\u00e9"));
        assertEquals("", TextUtils.escapeString(null));
    }

    @Test
    public void hexBytesIsSpaceSeparated() {
        assertEquals("00 20 40 00", TextUtils.hexBytes(new byte[] { 0x00, 0x20, 0x40, 0x00 }));
        assertEquals("ff", TextUtils.hexBytes(new byte[] { (byte) 0xFF }));
        assertEquals("", TextUtils.hexBytes(new byte[0]));
    }

    @Test
    public void encodeBase64PrefixesThePayload() {
        assertEquals("base64:QUJD", TextUtils.encodeBase64("ABC".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void stringByteLengthStopsAtSingleByteTerminator() {
        byte[] data = new byte[] { 'h', 'i', 0, 'x' };

        assertEquals(2, TextUtils.stringByteLength(data, "UTF-8"));
        assertEquals(3, TextUtils.stringByteLength(new byte[] { 'a', 'b', 'c' }, "UTF-8"));
    }

    @Test
    public void stringByteLengthStopsAtWideTerminatorForUtf16() {
        byte[] utf16 = new byte[] { 'h', 0, 'i', 0, 0, 0, 'x', 0 };

        assertEquals(4, TextUtils.stringByteLength(utf16, "UTF-16LE"));
        assertEquals(4, TextUtils.stringByteLength(new byte[] { 0x00, 'h', 0x00, 'i', 0, 0 }, "UTF-16BE"));
    }

    @Test
    public void stringByteLengthIgnoresTrailingOddByteForUtf16() {
        assertEquals(2, TextUtils.stringByteLength(new byte[] { 'h', 0, 'i' }, "UTF-16LE"));
    }

    @Test
    public void formatHexDumpFormatsSixteenBytesPerLine() {
        byte[] bytes = new byte[16];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) i;
        }

        assertEquals("0x140001000: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f |................|",
            TextUtils.formatHexDump(0x140001000L, bytes));
    }

    @Test
    public void formatHexDumpPadsShortLinesAndRendersAsciiGutter() {
        byte[] bytes = new byte[] { 'A', 0x00, 'B' };
        String expected = "0x1000: 41 00 42" + repeat("   ", 13) + " |A.B|";

        assertEquals(expected, TextUtils.formatHexDump(0x1000L, bytes));
    }

    @Test
    public void formatHexDumpUsesOneLinePerSixteenBytes() {
        byte[] bytes = new byte[17];
        bytes[16] = 0x41;

        String[] lines = TextUtils.formatHexDump(0x400000L, bytes).split("\n");

        assertEquals(2, lines.length);
        assertEquals("0x400010: 41" + repeat("   ", 15) + " |A|", lines[1]);
    }

    @Test
    public void formatHexDumpHandlesEmptyInput() {
        assertEquals("", TextUtils.formatHexDump(0x1000L, new byte[0]));
    }
}
