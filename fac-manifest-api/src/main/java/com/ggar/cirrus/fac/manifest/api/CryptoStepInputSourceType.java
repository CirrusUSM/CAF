package com.ggar.cirrus.fac.manifest.api;

import java.io.Serializable;

/**
 * Enumerates the possible types for the source of input data for a {@link CryptoStep}.
 */
public enum CryptoStepInputSourceType implements Serializable {
    /**
     * The input data is sourced directly from a named part of the {@link AccessManifest}'s encrypted payload.
     * Requires {@link InputSourceInfo#getPayloadKey()} to be set.
     */
    MANIFEST_PAYLOAD,

    /**
     * The input data is the output of a previous {@link CryptoStep} in the same pipeline.
     * Requires {@link InputSourceInfo#getStepRef()} to be set, referencing the {@link CryptoStep#getOutputName()}
     * of a preceding step.
     */
    PREVIOUS_STEP_OUTPUT,

    /**
     * The input data is a constant value provided directly within the {@link InputSourceInfo}.
     * Requires {@link InputSourceInfo#getConstantData()} to be set.
     */
    CONSTANT_DATA
}