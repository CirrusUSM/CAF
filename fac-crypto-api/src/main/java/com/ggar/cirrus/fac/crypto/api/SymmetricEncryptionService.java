package com.ggar.cirrus.fac.crypto.api;

import com.ggar.cirrus.caf.common.CryptoOperationException;
import com.ggar.cirrus.caf.common.CryptoParameters;
import com.ggar.cirrus.fac.crypto.api.dto.DecryptionOutput;
import com.ggar.cirrus.fac.crypto.api.dto.EncryptionOutput;
import com.ggar.cirrus.fac.crypto.api.dto.SymmetricKey;

/**
 * Service interface for symmetric encryption and decryption operations.
 */
public interface SymmetricEncryptionService {

    /**
     * Encrypts plaintext data using a symmetric key.
     *
     * @param plaintext The data to encrypt.
     * @param key The {@link SymmetricKey} to use for encryption.
     * @param cryptoParameters Parameters for the encryption operation, such as the specific algorithm
     * (e.g., "AES/GCM/NoPadding"), mode, padding, and potentially a
     * pre-defined IV or instructions to generate one. If an IV is generated,
     * it must be included in the returned {@link EncryptionOutput#getParameters()}.
     * @return An {@link EncryptionOutput} containing the ciphertext and any parameters needed for decryption (like IV).
     * @throws CryptoOperationException if encryption fails.
     */
    EncryptionOutput encrypt(byte[] plaintext, SymmetricKey key, CryptoParameters cryptoParameters) throws CryptoOperationException;

    /**
     * Decrypts ciphertext data using a symmetric key.
     *
     * @param ciphertext The data to decrypt.
     * @param key The {@link SymmetricKey} to use for decryption.
     * @param cryptoParameters Parameters used during encryption, essential for decryption
     * (e.g., algorithm, IV, AEAD tag length, associated data).
     * Must include any IV or nonce via {@link CryptoParameters#IV}.
     * @return A {@link DecryptionOutput} containing the plaintext.
     * @throws CryptoOperationException if decryption fails (e.g., bad key, incorrect IV, tampered ciphertext for AEAD).
     */
    DecryptionOutput decrypt(byte[] ciphertext, SymmetricKey key, CryptoParameters cryptoParameters) throws CryptoOperationException;
}