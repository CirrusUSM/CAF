package com.ggar.cirrus.fac.crypto.api;

import com.ggar.cirrus.caf.common.CryptoOperationException;
import com.ggar.cirrus.caf.common.CryptoParameters;
import com.ggar.cirrus.fac.crypto.api.dto.SymmetricKey; // Or a more generic DerivedKey DTO if needed

/**
 * Service interface for deriving cryptographic keys from passwords or other secrets
 * using strong Key Derivation Functions (KDFs).
 */
public interface PasswordBasedKeyDerivationService {

    /**
     * Derives a symmetric key from a password and other parameters (like salt and iterations).
     *
     * @param password The password or secret input. This should be a char[] to allow for zeroization.
     * @param cryptoParameters Parameters specifying the KDF (e.g., "Argon2id", "PBKDF2WithHmacSHA256"),
     * salt (via {@link CryptoParameters#SALT}),
     * iteration count (via {@link CryptoParameters#KDF_ITERATIONS}),
     * desired key length (via {@link CryptoParameters#KEY_LENGTH_BITS}),
     * and any other KDF-specific parameters.
     * @return The derived {@link SymmetricKey}. The key's algorithm might be "RAW" or specific to its intended use.
     * @throws CryptoOperationException if key derivation fails.
     */
    SymmetricKey deriveKeyFromPassword(char[] password, CryptoParameters cryptoParameters) throws CryptoOperationException;
}