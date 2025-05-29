package com.ggar.cirrus.caf.common;

/**
 * Base runtime exception for all exceptions originating from the
 * Cryptographic Access Framework (FAC).
 * <p>
 * Using a custom base exception allows consuming applications to catch
 * all FAC-specific issues with a single catch block if desired.
 * </p>
 */
public class FacException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public FacException(String message) {
        super(message);
    }

    public FacException(String message, Throwable cause) {
        super(message, cause);
    }
}
