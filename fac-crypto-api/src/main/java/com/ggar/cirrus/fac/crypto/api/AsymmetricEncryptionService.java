package com.ggar.cirrus.fac.crypto.api;

import com.ggar.cirrus.caf.common.CryptoOperationException;
import com.ggar.cirrus.caf.common.CryptoParameters;
import com.ggar.cirrus.fac.crypto.api.dto.DecryptionOutput;
import com.ggar.cirrus.fac.crypto.api.dto.EncryptionOutput;
import com.ggar.cirrus.fac.crypto.api.dto.PrivateKeyMaterial;
import com.ggar.cirrus.fac.crypto.api.dto.PublicKeyMaterial;

/**
 * Service interface for asymmetric encryption and decryption operations.
 * Typically used for encrypting/decrypting small amounts of data, such as symmetric keys (key wrapping/unwrapping).
 */
public interface AsymmetricEncryptionService {

    /**
     * Encrypts plaintext data using a recipient's public key.
     *
     * @param plaintext The data to encrypt (should be small, e.g., a symmetric key).
     * @param publicKey The recipient's {@link PublicKeyMaterial}.
     * @param cryptoParameters Parameters for the encryption operation (e.g., "RSA/ECB/OAEPWithSHA-256AndMGF1Padding").
     * This should specify the exact asymmetric scheme.
     * @return An {@link EncryptionOutput} containing the ciphertext.
     * @throws CryptoOperationException if encryption fails.
     */
    EncryptionOutput encrypt(byte[] plaintext, PublicKeyMaterial publicKey, CryptoParameters cryptoParameters) throws CryptoOperationException;

    /**
     * Decrypts ciphertext data using the recipient's private key.
     *
     * @param ciphertext The data to decrypt.
     * @param privateKey The recipient's {@link PrivateKeyMaterial}.
     * @param cryptoParameters Parameters used during encryption, essential for decryption (e.g., "RSA/ECB/OAEPWithSHA-256AndMGF1Padding").
     * @return A {@link DecryptionOutput} containing the plaintext.
     * @throws CryptoOperationException if decryption fails (e.g., bad key, corrupted ciphertext).
     */
    DecryptionOutput decrypt(byte[] ciphertext, PrivateKeyMaterial privateKey, CryptoParameters cryptoParameters) throws CryptoOperationException;
}