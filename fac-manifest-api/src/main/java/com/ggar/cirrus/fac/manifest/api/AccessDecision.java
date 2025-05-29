package com.ggar.cirrus.fac.manifest.api;

import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.caf.common.Permission;

//TODO: check if a SymmetricKey
import com.ggar.cirrus.fac.crypto.api.dto.SymmetricKey; // Assuming REK is a SymmetricKey
import lombok.Builder;
import lombok.Value;

import java.io.Serializable;
import java.util.Set;

/**
 * Represents the outcome of an access decision made by the {@code AccessDecisionEngine}.
 * This class is immutable.
 */
@Value
@Builder
public class AccessDecision implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * Enumerates the possible outcomes of an access decision.
     */
    public enum Outcome {
        /** Access is granted, and the REK has been successfully derived. */
        GRANTED,
        /** Access is explicitly denied based on manifest evaluation. */
        DENIED,
        /**
         * The cryptographic pipeline requires dynamic input from the user (e.g., password, recovery code)
         * and is currently paused. The consuming application should use the {@code InputProvider}
         * to obtain the required secret and re-attempt evaluation with the new context.
         */
        REQUIRES_USER_INPUT,
        /** A step in the cryptographic pipeline failed (e.g., decryption error, invalid key). */
        PIPELINE_STEP_FAILED,
        /** No applicable manifest was found that could grant access. */
        NO_APPLICABLE_MANIFEST_FOUND
    }

    /**
     * The overall outcome of the access evaluation.
     */
    Outcome outcome;

    /**
     * The derived Resource Encryption Key (REK), if access was {@link Outcome#GRANTED}.
     * Null otherwise.
     */
    SymmetricKey derivedRek;

    /**
     * The set of effective permissions granted to the identity for the resource,
     * if access was {@link Outcome#GRANTED}. Empty or null otherwise.
     */
    Set<Permission> effectivePermissions;

    /**
     * The identifier of the {@link AccessManifest} that resulted in this decision (the "winning" manifest).
     * Can be null if no manifest was applicable or if access was denied by a default policy.
     */
    Identifier winningManifestId;

    /**
     * Details about a failure, if the outcome is {@link Outcome#PIPELINE_STEP_FAILED}
     * or potentially for other error states. Null otherwise.
     */
    FailureDetailsInfo failureDetails;

    /**
     * If outcome is {@link Outcome#REQUIRES_USER_INPUT}, this field may contain a hint
     * or context for the required input (e.g., from {@link KeySourceInfo#getPromptHint()}).
     */
    String requiredInputPromptHint;
}