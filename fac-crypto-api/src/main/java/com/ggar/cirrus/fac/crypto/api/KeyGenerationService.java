package com.ggar.cirrus.fac.crypto.api;

import com.ggar.cirrus.caf.common.CryptoOperationException;
import com.ggar.cirrus.caf.common.CryptoParameters;
import com.ggar.cirrus.fac.crypto.api.dto.IdentityKeyPair;
import com.ggar.cirrus.fac.crypto.api.dto.SymmetricKey;

/**
 * Service interface for generating cryptographic keys.
 * Implementations will be responsible for using secure random sources
 * and adhering to specified cryptographic parameters.
 */
public interface KeyGenerationService {

    /**
     * Generates a new symmetric key (e.g., for use as a Resource Encryption Key - REK).
     *
     * @param cryptoParameters Parameters specifying the algorithm (e.g., "AES"), key length (e.g., 256 bits), etc.
     * Must contain at least {@link CryptoParameters#ALGORITHM_NAME} and {@link CryptoParameters#KEY_LENGTH_BITS}.
     * @return The generated {@link SymmetricKey}.
     * @throws CryptoOperationException if key generation fails.
     */
    SymmetricKey generateSymmetricKey(CryptoParameters cryptoParameters) throws CryptoOperationException;

    /**
     * Generates a new asymmetric key pair (e.g., for use as an Identity Key Pair - IKP).
     *
     * @param cryptoParameters Parameters specifying the algorithm (e.g., "RSA", "EC"), key size (e.g., 2048 for RSA, 256 for EC),
     * and any curve parameters if applicable. Must contain at least {@link CryptoParameters#ALGORITHM_NAME}
     * and relevant size/curve parameters.
     * @return The generated {@link IdentityKeyPair}.
     * @throws CryptoOperationException if key pair generation fails.
     */
    IdentityKeyPair generateIdentityKeyPair(CryptoParameters cryptoParameters) throws CryptoOperationException;
}