package com.ggar.cirrus.fac.crypto.api.dto;

import com.ggar.cirrus.caf.common.CryptoParameters; // For IV etc.
import lombok.Value;
import java.io.Serializable;

/**
 * Represents the output of an encryption operation.
 * Typically contains the ciphertext and any necessary parameters for decryption,
 * like an Initialization Vector (IV) or an AEAD authentication tag.
 * These parameters are often bundled in CryptoParameters.
 */
@Value
public class EncryptionOutput implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The resulting ciphertext.
     */
    byte[] ciphertext;

    /**
     * Cryptographic parameters used during encryption that might be needed for decryption,
     * e.g., IV, salt, AEAD tag. This should include any generated IV/nonce.
     */
    CryptoParameters parameters;
}