package eu.interopehrate.md2dsm.api;

/**
 * A checked exception to notify that a key is missing.
 */

public class NoSuchKeyException extends Throwable {

    /**
     * Creates a new {@link NoSuchKeyException} object.
     *
     * @param msg the exception message.
     */
    public NoSuchKeyException(String msg) {
        super(msg);
    }
}
