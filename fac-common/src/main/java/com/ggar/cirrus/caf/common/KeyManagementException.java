package com.ggar.cirrus.caf.common;

import lombok.Getter;

/**
 * Exception related to key management operations, such as issues with
 * generating, storing, retrieving, or protecting cryptographic keys (IKPs, REKs).
 */
@Getter
public class KeyManagementException extends FacException {

    private static final long serialVersionUID = 1L;
    private final String keyIdentifier; // Could be a key alias, fingerprint, or part of the key data

    public KeyManagementException(String message, String keyIdentifier) {
        super(message);
        this.keyIdentifier = keyIdentifier;
    }

    public KeyManagementException(String message, String keyIdentifier, Throwable cause) {
        super(message, cause);
        this.keyIdentifier = keyIdentifier;
    }
}