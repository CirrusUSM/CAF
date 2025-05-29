package com.ggar.cirrus.fac.manifest.api;

import com.ggar.cirrus.caf.common.CryptoParameters;
import lombok.Builder;
import lombok.Value;

import java.io.Serializable;

/**
 * Describes the source of input data for a {@link CryptoStep}.
 * This class is immutable.
 */
@Value
@Builder
public class InputSourceInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The type of input source.
     */
    CryptoStepInputSourceType type;

    /**
     * Optional key to identify a specific part within the {@link AccessManifest#getEncryptedPayload()} map.
     * Used when {@code type} is {@link CryptoStepInputSourceType#MANIFEST_PAYLOAD}.
     */
    String payloadKey;

    /**
     * Optional reference to the {@link CryptoStep#getOutputName()} of a previous step in the pipeline.
     * Used when {@code type} is {@link CryptoStepInputSourceType#PREVIOUS_STEP_OUTPUT}.
     */
    String stepRef;

    /**
     * Optional constant data to be used as input.
     * Used when {@code type} is {@link CryptoStepInputSourceType#CONSTANT_DATA}.
     * Note: Storing large constants here might be inefficient; consider manifest payload for larger data.
     */
    byte[] constantData;
}