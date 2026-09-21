package com.lauriewired.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * Unit tests for {@link ProgramSelector}. These run without a Ghidra runtime.
 */
public class ProgramSelectorTest {

    private static ProgramSelector.Candidate candidate(String name, String fileName,
                                                       String path) {
        return new ProgramSelector.Candidate(name, fileName, path);
    }

    private static List<ProgramSelector.Candidate> twoPrograms() {
        return new ArrayList<>(Arrays.asList(
            candidate("libfoo.so", "libfoo.so", "/proj/libfoo.so"),
            candidate("bar.exe", "bar.exe", "/proj/bar.exe")));
    }

    @Test
    public void absentOrEmptySelectorMeansTheCurrentProgram() {
        assertTrue(ProgramSelector.match(null, twoPrograms()).isCurrent());
        assertTrue(ProgramSelector.match("", twoPrograms()).isCurrent());
        assertTrue(ProgramSelector.match("   ", twoPrograms()).isCurrent());
    }

    @Test
    public void currentLiteralMeansTheCurrentProgram() {
        assertTrue(ProgramSelector.match("current", twoPrograms()).isCurrent());
        assertTrue(ProgramSelector.match("CURRENT", twoPrograms()).isCurrent());
    }

    @Test
    public void matchesExactProgramName() {
        ProgramSelector.MatchResult result = ProgramSelector.match("libfoo.so", twoPrograms());

        assertTrue(result.isMatch());
        assertEquals("libfoo.so", result.getMatch().getFileName());
        assertFalse(result.isError());
    }

    @Test
    public void matchesProgramNameCaseInsensitively() {
        ProgramSelector.MatchResult result = ProgramSelector.match("LIBFOO.SO", twoPrograms());

        assertTrue(result.isMatch());
        assertEquals("libfoo.so", result.getMatch().getName());
    }

    @Test
    public void matchesDomainFileNameWhenTheProgramNameDiffers() {
        List<ProgramSelector.Candidate> candidates = Arrays.asList(
            candidate("libfoo", "", "libfoo.so"));

        ProgramSelector.MatchResult result = ProgramSelector.match("libfoo.so", candidates);

        assertTrue(result.isMatch());
        assertEquals("libfoo", result.getMatch().getName());
    }

    @Test
    public void matchesTrimmedSelector() {
        assertTrue(ProgramSelector.match("  bar.exe  ", twoPrograms()).isMatch());
    }

    @Test
    public void matchesPathSuffixOnlyOnASegmentBoundary() {
        List<ProgramSelector.Candidate> candidates = Arrays.asList(
            candidate("plain", "plain", "/proj/foobar"),
            candidate("nested", "nested", "/proj/sub/bar"));

        // 'foobar' ends with 'bar' but not on a path-segment boundary, so only the nested file
        // may match.
        ProgramSelector.MatchResult result = ProgramSelector.match("bar", candidates);

        assertTrue(result.isMatch());
        assertEquals("nested", result.getMatch().getName());
    }

    @Test
    public void matchesAFullPathSuffix() {
        List<ProgramSelector.Candidate> candidates = Arrays.asList(
            candidate("first", "bar", "/proj/a/bar"),
            candidate("second", "bar", "/proj/b/bar"));

        ProgramSelector.MatchResult result = ProgramSelector.match("/proj/b/bar", candidates);

        assertTrue(result.isMatch());
        assertEquals("second", result.getMatch().getName());
    }

    @Test
    public void reportsAmbiguityInsteadOfGuessing() {
        List<ProgramSelector.Candidate> candidates = Arrays.asList(
            candidate("first", "libfoo.so", "/proj/a/libfoo.so"),
            candidate("second", "libfoo.so", "/proj/b/libfoo.so"));

        ProgramSelector.MatchResult result = ProgramSelector.match("libfoo.so", candidates);

        assertTrue(result.isError());
        assertNull(result.getMatch());
        assertEquals("Ambiguous program 'libfoo.so': /proj/a/libfoo.so, /proj/b/libfoo.so",
            result.getError());
    }

    @Test
    public void reportsNoMatchWithTheAvailableProgramNames() {
        ProgramSelector.MatchResult result = ProgramSelector.match("missing", twoPrograms());

        assertTrue(result.isError());
        assertEquals("No program matching 'missing'. Open programs: libfoo.so, bar.exe",
            result.getError());
    }

    @Test
    public void reportsNoMatchWhenNothingIsOpen() {
        ProgramSelector.MatchResult result =
            ProgramSelector.match("missing", new ArrayList<ProgramSelector.Candidate>());

        assertTrue(result.isError());
        assertEquals("No program matching 'missing'. Open programs: (none)", result.getError());
    }

    @Test
    public void prefersTheExactNameOverACaseInsensitiveDuplicate() {
        List<ProgramSelector.Candidate> candidates = Arrays.asList(
            candidate("libfoo.so", "libfoo.so", "/proj/libfoo.so"),
            candidate("LIBFOO.SO", "LIBFOO.SO", "/proj/LIBFOO.SO"));

        ProgramSelector.MatchResult result = ProgramSelector.match("libfoo.so", candidates);

        assertTrue(result.isMatch());
        assertEquals("/proj/libfoo.so", result.getMatch().getPath());
    }
}
