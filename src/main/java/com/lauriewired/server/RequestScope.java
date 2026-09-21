package com.lauriewired.server;

/**
 * Hook the {@link RequestRouter} calls around every route so that a request can be resolved to
 * the program it targets before its handler runs.
 * <p>
 * Implementations are free to keep the resolved target in a thread-local: the router always
 * pairs {@link #begin(String)} with {@link #end()} for the request that runs on this thread.
 */
public interface RequestScope {

    /**
     * Resolves the target of the request that is about to run.
     *
     * @param programSelector the optional {@code program} request parameter, or null when the
     *        request did not ask for a specific program
     * @return an error message to send to the client instead of running the route, or null to
     *         let the route run
     */
    String begin(String programSelector);

    /**
     * Releases whatever {@link #begin(String)} allocated. Always called, including when the
     * route threw, because the JDK HTTP server pools its worker threads between requests.
     */
    void end();
}
