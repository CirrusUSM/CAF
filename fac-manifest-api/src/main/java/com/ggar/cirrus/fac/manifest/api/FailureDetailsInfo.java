package com.ggar.cirrus.fac.manifest.api;

import lombok.Builder;
import lombok.Value;

import java.io.Serializable;

/**
 * Provides details about a failure encountered during manifest processing or
 * cryptographic pipeline execution.
 * This class is immutable.
 */
@Value
@Builder
public class FailureDetailsInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The ID of the {@link CryptoStep} that failed, if applicable.
     */
    String failedStepId;

    /**
     * An error code or type indicating the nature of the failure (e.g., "DECRYPTION_ERROR", "INVALID_KEY").
     */
    String errorCode;

    /**
     * A descriptive message about the failure.
     */
    String message;

    /**
     * The underlying exception that caused the failure, if available (for debugging, not for serialization).
     * Marked transient as Exceptions are often not easily serializable or suitable for DTOs.
     */
    transient Throwable cause; // Not typically part of a DTO, but useful for internal error propagation
}