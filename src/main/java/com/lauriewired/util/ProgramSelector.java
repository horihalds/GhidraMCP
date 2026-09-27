package com.lauriewired.util;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * Resolves the optional {@code program} request parameter against the programs that are open in
 * one Ghidra tool.
 * <p>
 * Everything here works on plain strings, so the matching rules can be exercised from a unit
 * test without a Ghidra runtime; {@code GhidraContext} only has to map a {@code Program} onto a
 * {@link Candidate}.
 */
public final class ProgramSelector {

    /** The literal selector that means "whatever program the tool shows". */
    public static final String CURRENT = "current";

    private ProgramSelector() {
    }

    /**
     * One open program, flattened to the strings a selector can match against.
     */
    public static final class Candidate {

        private final String name;
        private final String fileName;
        private final String path;

        public Candidate(String name, String fileName, String path) {
            this.name = name != null ? name : "";
            this.fileName = fileName != null ? fileName : "";
            this.path = path != null ? path : "";
        }

        /** @return the program name, i.e. the name of the domain object */
        public String getName() {
            return name;
        }

        /** @return the name of the domain file the program lives in */
        public String getFileName() {
            return fileName;
        }

        /** @return the full path of the domain file */
        public String getPath() {
            return path;
        }
    }

    /**
     * Outcome of {@link #match(String, List)}: exactly one of "resolved program", "the tool's
     * current program" and "error" applies.
     */
    public static final class MatchResult {

        private final Candidate match;
        private final boolean current;
        private final String error;

        private MatchResult(Candidate match, boolean current, String error) {
            this.match = match;
            this.current = current;
            this.error = error;
        }

        static MatchResult of(Candidate candidate) {
            return new MatchResult(candidate, false, null);
        }

        static MatchResult currentProgram() {
            return new MatchResult(null, true, null);
        }

        static MatchResult error(String message) {
            return new MatchResult(null, false, message);
        }

        /** @return true when the selector resolved to exactly one open program */
        public boolean isMatch() {
            return match != null;
        }

        /** @return true when the selector asked for the tool's current program */
        public boolean isCurrent() {
            return current;
        }

        /** @return true when the selector matched nothing, or more than one program */
        public boolean isError() {
            return error != null;
        }

        /** @return the resolved program, or null when there is none */
        public Candidate getMatch() {
            return match;
        }

        /** @return the message to show the client, or null when there is no error */
        public String getError() {
            return error;
        }
    }

    /**
     * Resolves {@code selector} with the precedence exact program name, case-insensitive program
     * name, domain-file name, then path suffix.
     *
     * @param selector the raw selector: an absent, blank or {@code current} value means "the
     *        program the tool currently shows"
     * @param candidates the programs open in the tool, in a stable order
     * @return the resolved program, the current-program marker, or an error naming the
     *         candidates when the selector is ambiguous or matches nothing
     */
    public static MatchResult match(String selector, List<Candidate> candidates) {
        if (selector == null || selector.trim().isEmpty()
            || selector.trim().equalsIgnoreCase(CURRENT)) {
            return MatchResult.currentProgram();
        }
        String wanted = selector.trim();

        MatchResult result = unique(candidates, c -> c.getName().equals(wanted), wanted);
        if (result != null) {
            return result;
        }
        result = unique(candidates, c -> c.getName().equalsIgnoreCase(wanted), wanted);
        if (result != null) {
            return result;
        }
        result = unique(candidates, c -> c.getFileName().equalsIgnoreCase(wanted), wanted);
        if (result != null) {
            return result;
        }
        result = unique(candidates, c -> isPathSuffix(c.getPath(), wanted), wanted);
        if (result != null) {
            return result;
        }
        return MatchResult.error(noMatch(wanted, candidates));
    }

    /**
     * @return the single matching candidate wrapped as a result, null when nothing matched, or an
     *         ambiguity error when several did
     */
    private static MatchResult unique(List<Candidate> candidates, Predicate<Candidate> predicate,
                                      String selector) {
        List<Candidate> matches = new ArrayList<>();
        for (Candidate candidate : candidates) {
            if (predicate.test(candidate)) {
                matches.add(candidate);
            }
        }
        if (matches.isEmpty()) {
            return null;
        }
        if (matches.size() > 1) {
            List<String> locations = new ArrayList<>();
            for (Candidate candidate : matches) {
                locations.add(candidate.getPath().isEmpty() ? candidate.getName()
                    : candidate.getPath());
            }
            return MatchResult.error("Ambiguous program '" + selector + "': "
                + String.join(", ", locations));
        }
        return MatchResult.of(matches.get(0));
    }

    /**
     * Matches a trailing path segment boundary-aware, so the selector {@code bar} matches
     * {@code /proj/a/bar} but not {@code /proj/foobar}.
     */
    private static boolean isPathSuffix(String path, String selector) {
        if (path.isEmpty() || !path.endsWith(selector)) {
            return false;
        }
        if (path.length() == selector.length()) {
            return true;
        }
        return path.charAt(path.length() - selector.length() - 1) == '/';
    }

    private static String noMatch(String selector, List<Candidate> candidates) {
        List<String> names = new ArrayList<>();
        for (Candidate candidate : candidates) {
            names.add(candidate.getName());
        }
        return "No program matching '" + selector + "'. Open programs: "
            + (names.isEmpty() ? "(none)" : String.join(", ", names));
    }
}
