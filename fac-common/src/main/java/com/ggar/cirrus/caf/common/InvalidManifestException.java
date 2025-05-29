package com.ggar.cirrus.caf.common;

/**
 * Exception thrown when an {@code AccessManifest} is found to be invalid,
 * malformed, or contains inconsistent data that prevents its processing.
 * <p>
 * This could be due to missing required fields, invalid cryptographic parameters
 * within its pipeline, or other structural issues.
 * </p>
 */
public class InvalidManifestException extends ManifestProcessingException {

    private static final long serialVersionUID = 1L;

    public InvalidManifestException(String message, String manifestId, String resourceId) {
        super(message, manifestId, resourceId);
    }

    public InvalidManifestException(String message, String manifestId, String resourceId, Throwable cause) {
        super(message, manifestId, resourceId, cause);
    }
}
