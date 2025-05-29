package com.ggar.cirrus.fac.manifest.engine.core;

import com.ggar.cirrus.fac.manifest.api.AccessDecision;
import com.ggar.cirrus.fac.manifest.api.AccessManifest;
import com.ggar.cirrus.fac.manifest.api.IdentityContext;
import com.ggar.cirrus.fac.manifest.api.InputProvider;
import com.ggar.cirrus.fac.manifest.api.KeySourceResolver;

import java.util.List;

/**
 * Defines the contract for the core engine that evaluates access to a Resource.
 * It processes a list of candidate {@link AccessManifest}s against an {@link IdentityContext}
 * to determine if access should be granted, and if so, derives the
 * Resource Encryption Key (REK).
 */
public interface AccessDecisionEngine {

    /**
     * Evaluates a list of candidate Access Manifests to determine if the given Identity
     * is authorized to access the underlying Resource Encryption Key (REK).
     * <p>
     * The engine will apply a precedence-based evaluation to the manifests.
     * For the winning manifest (if any grants access), it will attempt to execute
     * its cryptographic pipeline.
     * </p>
     *
     * @param candidateManifests A list of {@link AccessManifest}s that are potentially relevant
     * to the resource and identity. This list is typically pre-fetched
     * and filtered by the consuming application.
     * @param identityContext    The context of the identity attempting access, including their ID,
     * attributes, and any readily available (unlocked) private keys.
     * @param inputProvider      An implementation provided by the consuming application to supply
     * dynamic secrets (e.g., passwords, recovery codes) if required by a
     * {@link com.ggar.cirrus.fac.manifest.api.CryptoStep}.
     * @param keySourceResolver  An optional implementation provided by the consuming application to resolve
     * application-specific key identifiers if a {@link com.ggar.cirrus.fac.manifest.api.CryptoStep}
     * uses {@link com.ggar.cirrus.fac.manifest.api.CryptoStepKeySourceType#APPLICATION_RESOLVED_KEY}.
     * Can be null if not used.
     * @return An {@link AccessDecision} object detailing the outcome (GRANTED, DENIED, etc.),
     * the derived REK if access is granted, effective permissions, and any failure details.
     */
    AccessDecision evaluateAccess(
            List<AccessManifest> candidateManifests,
            IdentityContext identityContext,
            InputProvider inputProvider,
            KeySourceResolver keySourceResolver // Can be null
    );
}