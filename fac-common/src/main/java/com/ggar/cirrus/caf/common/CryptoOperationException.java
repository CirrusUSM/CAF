package com.ggar.cirrus.caf.common;

import lombok.Getter;

/**
 * Exception thrown when a cryptographic operation (e.g., encryption, decryption,
 * key generation, signature verification) fails.
 * <p>
 * This typically wraps lower-level exceptions from the underlying cryptographic
 * provider (like Bouncy Castle or JCE) to provide a FAC-specific error.
 * </p>
 */
@Getter
public class CryptoOperationException extends FacException {

    private static final long serialVersionUID = 1L;
    private final String algorithm; // Algorithm that failed, if known.

    public CryptoOperationException(String message, String algorithm, Throwable cause) {
        super(message, cause);
        this.algorithm = algorithm;
    }

    public CryptoOperationException(String message, Throwable cause) {
        this(message, null, cause);
    }
}
