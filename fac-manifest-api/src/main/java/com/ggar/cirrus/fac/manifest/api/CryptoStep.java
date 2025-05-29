package com.ggar.cirrus.fac.manifest.api;

import com.ggar.cirrus.caf.common.CryptoParameters;
import lombok.Builder;
import lombok.Value;

import java.io.Serializable;

/**
 * Represents a single, defined cryptographic operation within an {@link AccessManifest}'s pipeline.
 * This class is immutable.
 */
@Value
@Builder
public class CryptoStep implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * A unique identifier for this step within its pipeline, used for referencing its output.
     */
    String stepId;

    /**
     * The name of the cryptographic operation to perform (e.g., "ASYMMETRIC_DECRYPT", "SYMMETRIC_DECRYPT",
     * "KEY_DERIVATION_FROM_PASSWORD"). Consuming applications or crypto providers will map this
     * to specific functions.
     */
    String operationName;

    /**
     * The specific algorithm to be used for this operation (e.g., "RSA-OAEP-SHA256", "AES-256-GCM").
     * This, along with parameters in {@code cryptoParameters}, guides the {@code CryptoAPI}.
     */
    String algorithmName;

    /**
     * Describes where to get the primary input data for this cryptographic operation.
     */
    InputSourceInfo inputSource;

    /**
     * Describes where to get the key material for this cryptographic operation.
     */
    KeySourceInfo keySource;

    /**
     * Additional parameters required by the specified algorithm for this operation
     * (e.g., IV, salt, KDF iterations, AEAD tag).
     * This is an instance of {@link com.ggar.cirrus.caf.common.CryptoParameters}.
     */
    CryptoParameters cryptoParameters;

    /**
     * An optional name given to the output of this step. If provided, subsequent steps
     * in the pipeline can reference this output as an input or key source using this name.
     * The output of the final step in a successful pipeline is considered the derived REK.
     */
    String outputName;
}