package com.ggar.cirrus.caf.common;

import lombok.Getter;

/**
 * Exception thrown when an access decision results in a denial of access
 * to a Resource.
 * <p>
 * This typically occurs after the {@code AccessDecisionEngine} evaluates
 * all relevant manifests and determines that the requesting Identity
 * is not authorized.
 * </p>
 */
@Getter
public class AccessDeniedException extends FacException {

    private static final long serialVersionUID = 1L;

    private final String resourceId;
    private final String identityId;

    public AccessDeniedException(String message, String resourceId, String identityId) {
        super(message);
        this.resourceId = resourceId;
        this.identityId = identityId;
    }

    public AccessDeniedException(String message, String resourceId, String identityId, Throwable cause) {
        super(message, cause);
        this.resourceId = resourceId;
        this.identityId = identityId;
    }
}
