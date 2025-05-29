package com.ggar.cirrus.fac.crypto.api.dto;

import java.io.Serializable;

/**
 * Marker interface for representing cryptographic key material.
 * Concrete classes will provide specific key types (symmetric, asymmetric public/private).
 * Implementations should be immutable.
 */
public interface KeyMaterial extends Serializable {
    /**
     * Gets the algorithm for which this key is intended (e.g., "AES", "RSA", "EC").
     *
     * @return The algorithm name.
     */
    String getAlgorithm();

    /**
     * Gets the raw byte representation of the key material.
     * Callers should be careful when handling this directly.
     *
     * @return The key material as a byte array.
     */
    byte[] getEncoded();
}