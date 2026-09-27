package com.lauriewired.util;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;

/**
 * Finds a free TCP port, so several Ghidra windows can each run the plugin while all of them are
 * configured with the same default port.
 * <p>
 * Only the JDK socket API is used, which keeps the helper unit-testable without a Ghidra runtime.
 */
public final class PortPicker {

    /** How many consecutive ports are tried after the configured one. */
    public static final int MAX_ATTEMPTS = 10;

    private PortPicker() {
    }

    /**
     * @return true when a server can bind the port, i.e. when nothing else on this machine holds
     *         it on any interface
     */
    public static boolean isFree(int port) {
        if (port < 1 || port > 65535) {
            return false;
        }
        // Bind the same wildcard address the HTTP server uses, so the probe reports exactly the
        // conflicts that would make the server fail to start.
        try (ServerSocket socket = new ServerSocket()) {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(port), 1);
            return true;
        }
        catch (IOException | IllegalArgumentException | SecurityException e) {
            return false;
        }
    }

    /**
     * Scans {@code [preferred, preferred + attempts)} for the first free port.
     *
     * @param preferred the port the user configured
     * @param attempts how many consecutive ports to probe, at least 1
     * @return the first free port, {@code preferred} itself when it is free, or -1 when the whole
     *         window is occupied
     */
    public static int firstFree(int preferred, int attempts) {
        int probes = Math.max(1, attempts);
        for (int port = preferred; port < preferred + probes; port++) {
            if (port > 65535) {
                break;
            }
            if (isFree(port)) {
                return port;
            }
        }
        return -1;
    }
}
