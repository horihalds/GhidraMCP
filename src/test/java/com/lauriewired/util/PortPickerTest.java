package com.lauriewired.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Test;

/**
 * Unit tests for {@link PortPicker}. These bind loopback sockets only, so they need no Ghidra
 * runtime. Every case starts from a run of ports that was free when the test began.
 */
public class PortPickerTest {

    private final List<ServerSocket> openSockets = new ArrayList<>();

    @After
    public void closeSockets() {
        for (ServerSocket socket : openSockets) {
            try {
                socket.close();
            }
            catch (IOException ignored) {
                // Nothing useful to do while tearing a test down.
            }
        }
        openSockets.clear();
    }

    @Test
    public void freePortReturnsItself() {
        int port = freeRun(1);

        assertTrue(PortPicker.isFree(port));
        assertEquals(port, PortPicker.firstFree(port, PortPicker.MAX_ATTEMPTS));
    }

    @Test
    public void occupiedPortFallsThroughToTheNextFreeOne() {
        int port = freeRun(2);
        occupy(port);

        assertFalse(PortPicker.isFree(port));
        assertEquals(port + 1, PortPicker.firstFree(port, PortPicker.MAX_ATTEMPTS));
    }

    @Test
    public void skipsSeveralOccupiedPorts() {
        int port = freeRun(4);
        occupy(port);
        occupy(port + 1);
        occupy(port + 2);

        assertEquals(port + 3, PortPicker.firstFree(port, PortPicker.MAX_ATTEMPTS));
    }

    @Test
    public void returnsMinusOneWhenTheWholeWindowIsOccupied() {
        int port = freeRun(3);
        occupy(port);
        occupy(port + 1);
        occupy(port + 2);

        assertEquals(-1, PortPicker.firstFree(port, 3));
    }

    @Test
    public void probesAtLeastOnePortEvenForANonPositiveAttemptCount() {
        int port = freeRun(1);

        assertEquals(port, PortPicker.firstFree(port, 0));
    }

    @Test
    public void rejectsOutOfRangePorts() {
        assertFalse(PortPicker.isFree(0));
        assertFalse(PortPicker.isFree(-1));
        assertFalse(PortPicker.isFree(65536));
    }

    /**
     * @return the first port of a run of {@code count} consecutive ports that are all free
     */
    private static int freeRun(int count) {
        int start = freePort();
        int found = 0;
        for (int candidate = start; candidate < start + 200; candidate++) {
            if (PortPicker.isFree(candidate)) {
                if (++found == count) {
                    return candidate - count + 1;
                }
            }
            else {
                found = 0;
            }
        }
        throw new IllegalStateException("no run of " + count + " free ports above " + start);
    }

    /**
     * @return a port the operating system just handed out and that is free again
     */
    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
        catch (IOException e) {
            throw new IllegalStateException("could not reserve a port for the test", e);
        }
    }

    private void occupy(int port) {
        try {
            ServerSocket socket = new ServerSocket();
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 1);
            openSockets.add(socket);
        }
        catch (IOException e) {
            throw new IllegalStateException("could not occupy port " + port, e);
        }
    }
}
