package com.ggar.cirrus.fac.manifest.api;

import com.ggar.cirrus.fac.crypto.api.dto.KeyMaterial;

import java.io.Serializable;
import java.util.Optional;

/**
 * Interface to be implemented by the consuming application.
 * The {@code AccessDecisionEngine} uses this resolver when a {@link CryptoStep}'s
 * {@link KeySourceInfo#getType()} is {@link CryptoStepKeySourceType#APPLICATION_RESOLVED_KEY}.
 * <p>
 * This allows the application to integrate with external Key Management Systems (KMS)
 * or implement custom key resolution logic beyond what the standard {@link InputProvider}
 * or {@link IdentityContext} directly offer.
 * </p>
 */
public interface KeySourceResolver extends Serializable {

    /**
     * Resolves an application-specific key identifier to actual {@link KeyMaterial}.
     *
     * @param keySourceIdentifier The application-specific identifier for the key,
     * taken from {@link KeySourceInfo#getIdentifier()}.
     * @param identityContext     The context of the identity attempting access, which might be needed
     * by the resolver to authorize key retrieval.
     * @param accessManifest      The current {@link AccessManifest} being processed, providing further context.
     * @return An {@link Optional} containing the resolved {@link KeyMaterial} if successful,
     * or an empty Optional if the key cannot be resolved or access to it is denied
     * by the resolver's internal logic.
     */
    Optional<KeyMaterial> resolveKey(
            String keySourceIdentifier,
            IdentityContext identityContext,
            AccessManifest accessManifest
    );
}