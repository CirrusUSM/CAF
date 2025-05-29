package com.ggar.cirrus.fac.manifest.api;

import java.io.Serializable;

//TODO: cambiar a modelo de interfaces
/**
 * Enumerates the possible types for the source of key material for a {@link CryptoStep}.
 */
public enum CryptoStepKeySourceType implements Serializable {
    /**
     * The key material is the primary private key of the current Identity's Key Pair (IKP).
     * The consuming application (via {@code InputProvider}) is responsible for unlocking and providing this key.
     * {@link KeySourceInfo#getIdentifier()} might hold an alias or hint for which IKP if an identity has multiple.
     */
    IDENTITY_IKP_PRIVATE_KEY,

    /**
     * The key material is a secret (e.g., password, recovery code) to be obtained from the user
     * via the {@code InputProvider}.
     * {@link KeySourceInfo#getPromptHint()} can guide the UI.
     * This secret is typically then used in a key derivation step.
     */
    INPUT_PROVIDER_SECRET,

    /**
     * The key material is the output of a previous {@link CryptoStep} in the same pipeline.
     * Requires {@link KeySourceInfo#getStepRef()} to be set, referencing the {@link CryptoStep#getOutputName()}
     * of a preceding step that produced key material.
     */
    PREVIOUS_STEP_OUTPUT_AS_KEY,

    /**
     * The key material is to be resolved by the consuming application via the {@code KeySourceResolver} interface.
     * {@link KeySourceInfo#getIdentifier()} provides a context-specific identifier for the application to resolve.
     * This allows for integration with external Key Management Systems (KMS) or custom key stores.
     */
    APPLICATION_RESOLVED_KEY,

    /**
     * The key material is a symmetric group key.
     * The consuming application (via {@code InputProvider}) is responsible for providing this key
     * based on the current identity's group memberships.
     * {@link KeySourceInfo#getIdentifier()} would typically hold the group ID.
     */
    GROUP_SYMMETRIC_KEY
}