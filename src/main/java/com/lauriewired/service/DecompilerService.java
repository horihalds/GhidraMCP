package com.lauriewired.service;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.List;

/**
 * Owns the {@link DecompInterface} instances used by the HTTP handlers.
 * <p>
 * Creating a decompiler is expensive, so one instance is cached per thread and re-opened when
 * the current program changes. Every instance created here is disposed when the plugin shuts
 * down, which replaces the previous per-request {@code new DecompInterface()} leak.
 */
public class DecompilerService {

    /** Timeout for decompilations that are only inspected for symbols or types. */
    public static final int TIMEOUT_SECONDS = 30;

    /** Timeout for decompilations whose C code is part of the response. */
    public static final int FULL_DECOMPILE_TIMEOUT_SECONDS = 60;

    private final ThreadLocal<DecompilerHolder> decompilers = new ThreadLocal<>();
    private final List<DecompilerHolder> created = new ArrayList<>();
    private final Object logSource;

    public DecompilerService(Object logSource) {
        this.logSource = logSource;
    }

    /**
     * Decompiles a function with the default timeout.
     *
     * @return the results, or null if there was nothing to decompile
     */
    public DecompileResults decompile(Function function) {
        return decompile(function, TIMEOUT_SECONDS);
    }

    /**
     * Decompiles a function with an explicit timeout.
     *
     * @return the results, or null if there was nothing to decompile
     */
    public DecompileResults decompile(Function function, int timeoutSeconds) {
        if (function == null) {
            return null;
        }
        DecompInterface decompiler = decompilerFor(function.getProgram());
        if (decompiler == null) {
            return null;
        }
        return decompiler.decompileFunction(function, timeoutSeconds, new ConsoleTaskMonitor());
    }

    /**
     * Decompiles the function with the given name.
     *
     * @return the results, or null if no such function exists
     */
    public DecompileResults decompileByName(Program program, String name) {
        return decompile(findFunctionByName(program, name));
    }

    /**
     * Decompiles the function at (or containing) the given address.
     *
     * @return the results, or null if no such function exists
     */
    public DecompileResults decompileByAddress(Program program, String addressStr) {
        return decompile(findFunctionByAddress(program, addressStr));
    }

    /**
     * Disposes every decompiler created by this service.
     */
    public void dispose() {
        synchronized (created) {
            for (DecompilerHolder holder : created) {
                holder.dispose();
            }
            created.clear();
        }
        decompilers.remove();
    }

    private DecompInterface decompilerFor(Program program) {
        if (program == null) {
            return null;
        }

        DecompilerHolder holder = decompilers.get();
        if (holder == null) {
            holder = new DecompilerHolder();
            decompilers.set(holder);
            synchronized (created) {
                created.add(holder);
            }
        }

        if (holder.isOpenFor(program)) {
            return holder.decompiler;
        }

        // Re-open (and dispose the previous instance) when the tool switched programs.
        holder.dispose();
        DecompInterface decompiler = new DecompInterface();
        decompiler.setSimplificationStyle("decompile"); // Full decompilation
        decompiler.openProgram(program);
        holder.decompiler = decompiler;
        holder.program = program;
        return decompiler;
    }

    private Function findFunctionByName(Program program, String name) {
        if (program == null || name == null) {
            return null;
        }
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (name.equals(func.getName())) {
                return func;
            }
        }
        return null;
    }

    private Function findFunctionByAddress(Program program, String addressStr) {
        if (program == null || addressStr == null || addressStr.isEmpty()) {
            return null;
        }
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                func = program.getFunctionManager().getFunctionContaining(addr);
            }
            return func;
        }
        catch (Exception e) {
            Msg.error(logSource, "Invalid function address: " + addressStr, e);
            return null;
        }
    }

    /**
     * Per-thread decompiler plus the program it was opened for.
     */
    private static final class DecompilerHolder {

        private DecompInterface decompiler;
        private Program program;

        boolean isOpenFor(Program candidate) {
            return decompiler != null && program == candidate;
        }

        void dispose() {
            if (decompiler != null) {
                decompiler.dispose();
                decompiler = null;
            }
            program = null;
        }
    }
}
