package com.ggar.cirrus.fac.crypto.api.dto;

import lombok.Value;
import java.io.Serializable;

/**
 * Represents a digital signature.
 */
@Value
public class Signature implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The raw byte value of the signature.
     */
    byte[] signatureBytes;

    /**
     * The algorithm used to generate the signature (e.g., "SHA256withRSA", "SHA512withECDSA").
     */
    String algorithm;
}