package com.ggar.cirrus.fac.crypto.api.dto;

import lombok.Value;

/**
 * Represents an immutable public key component of an asymmetric key pair.
 */
@Value
public class PublicKeyMaterial implements KeyMaterial {
    private static final long serialVersionUID = 1L;

    /**
     * The raw byte representation of the public key (e.g., X.509 format).
     */
    byte[] encoded;

    /**
     * The algorithm for which this key is intended (e.g., "RSA", "EC").
     */
    String algorithm;
}