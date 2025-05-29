package com.ggar.cirrus.caf.common;

import lombok.Getter;

/**
 * Base exception for issues encountered during the processing or evaluation
 * of an {@code AccessManifest}, including its cryptographic pipeline.
 */
@Getter
public class ManifestProcessingException extends FacException {

    private static final long serialVersionUID = 1L;
    private final String manifestId;
    private final String resourceId;

    public ManifestProcessingException(String message, String manifestId, String resourceId) {
        super(message);
        this.manifestId = manifestId;
        this.resourceId = resourceId;
    }

    public ManifestProcessingException(String message, String manifestId, String resourceId, Throwable cause) {
        super(message, cause);
        this.manifestId = manifestId;
        this.resourceId = resourceId;
    }
}
