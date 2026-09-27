package com.lauriewired.service;

/**
 * Work that must run on the Swing thread inside a program transaction.
 * <p>
 * Implementations may throw checked exceptions; the surrounding transaction helper treats
 * any exception as a failure and does not commit the transaction.
 *
 * @param <T> type of the value produced by the body
 */
public interface TransactionBody<T> {

    T run() throws Exception;
}
