package com.ggar.cirrus.fac.crypto.api.dto;

import lombok.Value;
import java.io.Serializable;

/**
 * Represents the output of a decryption operation.
 * Typically contains the plaintext data.
 */
@Value
public class DecryptionOutput implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The resulting plaintext.
     */
    byte[] plaintext;
}