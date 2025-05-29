package com.ggar.cirrus.fac.crypto.api;

import com.ggar.cirrus.caf.common.CryptoOperationException;
import com.ggar.cirrus.caf.common.CryptoParameters;

/**
 * Service interface for cryptographic hashing operations.
 */
public interface HashingService {

    /**
     * Computes the hash of the given data.
     *
     * @param data The data to hash.
     * @param cryptoParameters Parameters specifying the hash algorithm (e.g., "SHA-256", "SHA-512").
     * Must contain {@link CryptoParameters#ALGORITHM_NAME}.
     * @return The computed hash as a byte array.
     * @throws CryptoOperationException if hashing fails.
     */
    byte[] hash(byte[] data, CryptoParameters cryptoParameters) throws CryptoOperationException;
}