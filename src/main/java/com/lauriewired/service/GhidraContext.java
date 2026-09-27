package com.lauriewired.service;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import com.lauriewired.server.RequestScope;
import com.lauriewired.util.ProgramSelector;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

/**
 * Single access point for the current program and for mutating work that has to happen on
 * the Swing thread inside a program transaction.
 * <p>
 * The access point also implements the router's {@link RequestScope}: a request may name one of
 * the open programs through the {@code program} parameter, and the resolution is kept per thread
 * only for the duration of that request.
 */
public class GhidraContext implements RequestScope {

    private final PluginTool tool;
    private final Object logSource;
    private final ThreadLocal<Program> scopedProgram = new ThreadLocal<>();

    public GhidraContext(PluginTool tool, Object logSource) {
        this.tool = tool;
        this.logSource = logSource;
    }

    /**
     * @return the program this request targets: the one resolved from the {@code program}
     *         parameter, or the program the tool currently shows when none was requested
     */
    public Program getCurrentProgram() {
        Program scoped = scopedProgram.get();
        return scoped != null ? scoped : getToolProgram();
    }

    /**
     * @return the program currently open in the tool, or null if none is loaded
     */
    public Program getToolProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    /**
     * @return every program open in the tool, never null and in the tool's own order
     */
    public Program[] getOpenPrograms() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return new Program[0];
        }
        Program[] open = pm.getAllOpenPrograms();
        return open != null ? open : new Program[0];
    }

    /**
     * Resolves a {@code program} selector without scoping anything.
     *
     * @return the single matching open program, or null when the selector means the tool's
     *         current program, matches nothing or is ambiguous
     */
    public Program resolveProgram(String selector) {
        return matchOpenPrograms(selector).program;
    }

    @Override
    public String begin(String programSelector) {
        end();
        ScopedMatch match = matchOpenPrograms(programSelector);
        if (match.program != null) {
            scopedProgram.set(match.program);
        }
        return match.error;
    }

    @Override
    public void end() {
        scopedProgram.remove();
    }

    /**
     * Matches a selector against the programs open in the tool. At most one of the two fields is
     * set: an error message, or the program to act on (null for "the tool's current program").
     */
    private ScopedMatch matchOpenPrograms(String selector) {
        Program[] open = getOpenPrograms();
        List<ProgramSelector.Candidate> candidates = new ArrayList<>();
        for (Program program : open) {
            candidates.add(toCandidate(program));
        }

        ProgramSelector.MatchResult result = ProgramSelector.match(selector, candidates);
        if (result.isError()) {
            return new ScopedMatch(null, result.getError());
        }
        if (result.isMatch()) {
            for (int i = 0; i < candidates.size(); i++) {
                if (candidates.get(i) == result.getMatch()) {
                    return new ScopedMatch(open[i], null);
                }
            }
        }
        return new ScopedMatch(null, null);
    }

    private static ProgramSelector.Candidate toCandidate(Program program) {
        String fileName = "";
        String path = "";
        DomainFile file = program.getDomainFile();
        if (file != null) {
            fileName = file.getName();
            path = file.getPathname();
        }
        return new ProgramSelector.Candidate(program.getName(), fileName, path);
    }

    /**
     * Runs the given body on the Swing thread inside a transaction named after the operation
     * and commits it as soon as the body produced a non-null result.
     *
     * @return the body's result, or null if it failed
     */
    public <T> T runInTransaction(String name, Program program, TransactionBody<T> body) {
        return runInTransaction(name, program, body, result -> result != null);
    }

    /**
     * Runs the given body on the Swing thread inside a transaction named after the operation.
     * The transaction is committed only when the body completed and {@code commit} accepts the
     * result, so callers keep full control over what counts as success.
     *
     * @return the body's result, or null if it threw or the Swing thread could not run it
     */
    public <T> T runInTransaction(String name, Program program, TransactionBody<T> body,
                                  Predicate<T> commit) {
        AtomicReference<T> result = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(name);
                boolean commitFlag = false;
                try {
                    T value = body.run();
                    result.set(value);
                    commitFlag = value != null && commit.test(value);
                }
                catch (Exception e) {
                    Msg.error(logSource, "Error during transaction '" + name + "'", e);
                }
                finally {
                    program.endTransaction(tx, commitFlag);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(logSource, "Failed to run '" + name + "' on the Swing thread", e);
        }
        return result.get();
    }

    /**
     * Resolution outcome of one selector: the program to act on, or the reason it could not be
     * resolved.
     */
    private static final class ScopedMatch {

        private final Program program;
        private final String error;

        ScopedMatch(Program program, String error) {
            this.program = program;
            this.error = error;
        }
    }
}
