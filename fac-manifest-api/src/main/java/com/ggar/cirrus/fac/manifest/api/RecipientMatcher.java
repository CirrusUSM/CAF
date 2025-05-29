package com.ggar.cirrus.fac.manifest.api;

import com.ggar.cirrus.caf.common.Identifier; // Assuming IdentityContext will be defined elsewhere or passed in

import java.io.Serializable;

/**
 * Interface for matching an {@link AccessManifest} against a requesting {@link IdentityContext}.
 * Implementations will define specific matching logic (e.g., by identity ID, group membership).
 */
public interface RecipientMatcher extends Serializable {
    /**
     * Checks if this matcher applies to the given identity context.
     *
     * @param identityContext The context of the identity attempting access.
     * @return {@code true} if the manifest applies to the identity, {@code false} otherwise.
     */
    boolean matches(IdentityContext identityContext);

    /**
     * Gets an identifier representing the recipient target of this matcher
     * (e.g., a user ID, a group ID, or a special value like "PUBLIC_LINK").
     * This is useful for indexing and querying manifests.
     *
     * @return A non-null {@link Identifier}.
     */
    Identifier getTargetRecipientIdentifier();
}