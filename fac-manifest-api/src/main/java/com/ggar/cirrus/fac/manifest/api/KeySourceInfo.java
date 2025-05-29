package com.ggar.cirrus.fac.manifest.api;

import lombok.Builder;
import lombok.Value;

import java.io.Serializable;

/**
 * Describes the source of key material for a {@link CryptoStep}.
 * This class is immutable.
 */
@Value
@Builder
public class KeySourceInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The type of key source.
     */
    CryptoStepKeySourceType type;

    /**
     * Optional identifier used by certain key source types.
     * For {@link CryptoStepKeySourceType#IDENTITY_IKP_PRIVATE_KEY}, it might be a key alias.
     * For {@link CryptoStepKeySourceType#APPLICATION_RESOLVED_KEY}, it's an application-specific identifier.
     * For {@link CryptoStepKeySourceType#GROUP_SYMMETRIC_KEY}, it's the group identifier.
     */
    String identifier;

    /**
     * Optional reference to the {@link CryptoStep#getOutputName()} of a previous step in the pipeline.
     * Used when {@code type} is {@link CryptoStepKeySourceType#PREVIOUS_STEP_OUTPUT_AS_KEY}.
     */
    String stepRef;

    /**
     * Optional hint for the UI when prompting for a secret.
     * Used when {@code type} is {@link CryptoStepKeySourceType#INPUT_PROVIDER_SECRET}.
     */
    String promptHint;
}