package com.ggar.cirrus.fac.crypto.api.dto;

import lombok.Value;

/**
 * Represents an immutable private key component of an asymmetric key pair.
 * Note: This DTO holds the plaintext private key material. It is the responsibility
 * of higher-level services (like UserKeyManagementService in a client application or ZKM flow)
 * to ensure this material is only held in memory when decrypted and is otherwise protected.
 */
@Value
public class PrivateKeyMaterial implements KeyMaterial {
    private static final long serialVersionUID = 1L;

    /**
     * The raw byte representation of the private key (e.g., PKCS#8 format).
     */
    byte[] encoded;

    /**
     * The algorithm for which this key is intended (e.g., "RSA", "EC").
     */
    String algorithm;
}