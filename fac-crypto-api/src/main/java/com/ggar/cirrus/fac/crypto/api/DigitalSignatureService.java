package com.ggar.cirrus.fac.crypto.api;

import com.ggar.cirrus.caf.common.CryptoOperationException;
import com.ggar.cirrus.caf.common.CryptoParameters;
import com.ggar.cirrus.fac.crypto.api.dto.PrivateKeyMaterial;
import com.ggar.cirrus.fac.crypto.api.dto.PublicKeyMaterial;
import com.ggar.cirrus.fac.crypto.api.dto.Signature;

/**
 * Service interface for creating and verifying digital signatures.
 */
public interface DigitalSignatureService {

    /**
     * Signs the given data using a private key.
     *
     * @param data The data to sign.
     * @param privateKey The {@link PrivateKeyMaterial} to use for signing.
     * @param cryptoParameters Parameters specifying the signature algorithm (e.g., "SHA256withRSA", "SHA512withECDSA").
     * Must contain {@link CryptoParameters#ALGORITHM_NAME}.
     * @return A {@link Signature} object containing the signature bytes and algorithm.
     * @throws CryptoOperationException if signing fails.
     */
    Signature sign(byte[] data, PrivateKeyMaterial privateKey, CryptoParameters cryptoParameters) throws CryptoOperationException;

    /**
     * Verifies a digital signature against the given data and a public key.
     *
     * @param data The original data that was signed.
     * @param signature The {@link Signature} object to verify.
     * @param publicKey The {@link PublicKeyMaterial} to use for verification.
     * @param cryptoParameters Parameters specifying the signature algorithm. Should match the one in the Signature object
     * and be used by the verification implementation.
     * @return {@code true} if the signature is valid, {@code false} otherwise.
     * @throws CryptoOperationException if the verification process itself encounters an error (not for an invalid signature).
     */
    boolean verify(byte[] data, Signature signature, PublicKeyMaterial publicKey, CryptoParameters cryptoParameters) throws CryptoOperationException;
}