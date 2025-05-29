package com.ggar.cirrus.fac.crypto.api.dto;

//import com.framework.access.common.CryptoParameters; // Assuming this might be needed for parameters
import lombok.Value;

/**
 * Represents an immutable symmetric cryptographic key.
 * This can be used as a Resource Encryption Key (REK) or a Key Encryption Key (KEK).
 */
@Value
public class SymmetricKey implements KeyMaterial {
    private static final long serialVersionUID = 1L;

    /**
     * The raw byte representation of the symmetric key.
     */
    byte[] encoded;

    /**
     * The algorithm for which this key is intended (e.g., "AES").
     */
    String algorithm;

//    TODO
    // Optionally, key length could also be a field if not derivable from encoded.length
    // or algorithm specifics (e.g. AES-128, AES-256 needs this context).
    // CryptoParameters could carry this.
}