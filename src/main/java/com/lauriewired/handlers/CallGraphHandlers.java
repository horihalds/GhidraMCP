package com.lauriewired.handlers;

import com.lauriewired.service.AddressResolver;
import com.lauriewired.service.FunctionLookup;
import com.lauriewired.service.GhidraContext;
import com.lauriewired.util.Paginator;
import com.lauriewired.util.TextUtils;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Read-only call-graph endpoints: walk callers or callees breadth-first up to a bounded depth.
 */
public class CallGraphHandlers {

    /** Upper bound for one page of call-graph nodes. */
    public static final int MAX_PAGE = 1000;

    /** Upper bound for the traversal depth, so a request can never walk a whole call graph. */
    public static final int MAX_DEPTH = 4;

    private final GhidraContext context;

    public CallGraphHandlers(GhidraContext context) {
        this.context = context;
    }

    /**
     * GET /get_callers implementation: the functions that reach this one, level by level.
     */
    public String getCallers(String addressParam, String nameParam, int depth, int offset, int limit) {
        return walk(addressParam, nameParam, depth, offset, limit, true);
    }

    /**
     * GET /get_callees implementation: the functions this one reaches, level by level.
     */
    public String getCallees(String addressParam, String nameParam, int depth, int offset, int limit) {
        return walk(addressParam, nameParam, depth, offset, limit, false);
    }

    /**
     * Breadth-first traversal shared by both endpoints. A function is reported once, at the
     * shallowest depth it is reachable at, which also keeps mutual recursion from looping.
     */
    private String walk(String addressParam, String nameParam, int depth, int offset, int limit,
                        boolean callers) {
        Program program = context.getCurrentProgram();
        if (program == null) return FunctionLookup.NO_PROGRAM;

        Function start = FunctionLookup.resolve(program, addressParam, nameParam);
        if (start == null) return FunctionLookup.describeMiss(addressParam, nameParam);

        int maxDepth = Math.max(1, Math.min(depth, MAX_DEPTH));
        List<String> lines = new ArrayList<>();
        Set<Long> visited = new HashSet<>();
        visited.add(start.getEntryPoint().getOffset());

        Deque<Level> queue = new ArrayDeque<>();
        queue.add(new Level(start, 0));
        while (!queue.isEmpty()) {
            Level current = queue.poll();
            if (current.depth >= maxDepth) {
                continue;
            }
            int nextDepth = current.depth + 1;
            for (Function next : callers ? callersOf(program, current.function)
                    : calleesOf(current.function)) {
                if (!visited.add(next.getEntryPoint().getOffset())) {
                    continue;
                }
                lines.add(String.format("d%d %s %s (%s of %s)",
                    nextDepth,
                    AddressResolver.formatAddress(next.getEntryPoint()),
                    TextUtils.escapeNonAscii(next.getName()),
                    callers ? "caller" : "callee",
                    TextUtils.escapeNonAscii(current.function.getName())));
                queue.add(new Level(next, nextDepth));
            }
        }

        return Paginator.paginateWithTotal(lines, offset, Math.min(limit, MAX_PAGE));
    }

    /**
     * Functions that reference the entry point of the given function, in reference order.
     */
    private static List<Function> callersOf(Program program, Function function) {
        Set<Function> callers = new LinkedHashSet<>();
        ReferenceIterator references =
            program.getReferenceManager().getReferencesTo(function.getEntryPoint());
        while (references.hasNext()) {
            Reference reference = references.next();
            Function caller =
                program.getFunctionManager().getFunctionContaining(reference.getFromAddress());
            if (caller != null) {
                callers.add(caller);
            }
        }
        return new ArrayList<>(callers);
    }

    /**
     * Functions the given function calls directly.
     */
    private static List<Function> calleesOf(Function function) {
        return new ArrayList<>(function.getCalledFunctions(TaskMonitor.DUMMY));
    }

    /**
     * A function together with the depth it was reached at.
     */
    private static final class Level {

        private final Function function;
        private final int depth;

        Level(Function function, int depth) {
            this.function = function;
            this.depth = depth;
        }
    }
}
