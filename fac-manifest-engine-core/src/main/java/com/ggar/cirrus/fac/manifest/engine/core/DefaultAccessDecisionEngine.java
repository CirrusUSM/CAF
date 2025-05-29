package com.ggar.cirrus.fac.manifest.engine.core;

import com.ggar.cirrus.caf.common.CryptoOperationException;
import com.ggar.cirrus.caf.common.CryptoParameters;
import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.caf.common.Permission;
import com.ggar.cirrus.fac.crypto.api.AsymmetricEncryptionService;
import com.ggar.cirrus.fac.crypto.api.PasswordBasedKeyDerivationService;
import com.ggar.cirrus.fac.crypto.api.SymmetricEncryptionService;
import com.ggar.cirrus.fac.crypto.api.dto.*;
import com.ggar.cirrus.fac.manifest.api.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Default implementation of the {@link AccessDecisionEngine}.
 * It evaluates manifests based on precedence and executes their cryptographic pipelines.
 */
public class DefaultAccessDecisionEngine implements AccessDecisionEngine {

    private final SymmetricEncryptionService symmetricEncryptionService;
    private final AsymmetricEncryptionService asymmetricEncryptionService;
    private final PasswordBasedKeyDerivationService passwordKdfService;
    // Add other crypto services as needed (e.g., HashingService if a step uses it)

    /**
     * Constructs a new DefaultAccessDecisionEngine.
     *
     * @param symmetricEncryptionService Implementation for symmetric crypto operations.
     * @param asymmetricEncryptionService Implementation for asymmetric crypto operations.
     * @param passwordKdfService Implementation for password-based key derivation.
     */
    public DefaultAccessDecisionEngine(
            SymmetricEncryptionService symmetricEncryptionService,
            AsymmetricEncryptionService asymmetricEncryptionService,
            PasswordBasedKeyDerivationService passwordKdfService) {
        this.symmetricEncryptionService = Objects.requireNonNull(symmetricEncryptionService);
        this.asymmetricEncryptionService = Objects.requireNonNull(asymmetricEncryptionService);
        this.passwordKdfService = Objects.requireNonNull(passwordKdfService);
    }

    @Override
    public AccessDecision evaluateAccess(
            List<AccessManifest> candidateManifests,
            IdentityContext identityContext,
            InputProvider inputProvider,
            KeySourceResolver keySourceResolver) {

        Objects.requireNonNull(candidateManifests, "Candidate manifests list cannot be null.");
        Objects.requireNonNull(identityContext, "Identity context cannot be null.");
        Objects.requireNonNull(inputProvider, "Input provider cannot be null.");
        // keySourceResolver can be null

        // 1. Filter by RecipientMatcher and Sort manifests by precedence (lower value = higher priority)
        List<AccessManifest> applicableAndSortedManifests = candidateManifests.stream()
                .filter(manifest -> manifest.getRecipientMatcher() == null || manifest.getRecipientMatcher().matches(identityContext))
                .sorted(Comparator.comparingInt(manifest -> manifest.getManifestType().getPrecedence()))
                .collect(Collectors.toList());

        if (applicableAndSortedManifests.isEmpty()) {
            return AccessDecision.builder()
                    .outcome(AccessDecision.Outcome.NO_APPLICABLE_MANIFEST_FOUND)
                    .build();
        }

        // 2. Iterate and try to process the pipeline of the highest precedence manifest first
        for (AccessManifest manifest : applicableAndSortedManifests) {
            // Handle explicit DENY types first if they are the highest precedence match
            // This logic depends on how ManifestType.getPrecedence() is defined for deny types.
            // Assuming deny types have the absolute highest precedence (lowest number).
            if (isDenyManifest(manifest.getManifestType())) {
                return AccessDecision.builder()
                        .outcome(AccessDecision.Outcome.DENIED)
                        .winningManifestId(manifest.getManifestId())
                        .effectivePermissions(Collections.emptySet()) // Denied means no permissions
                        .build();
            }

            // Attempt to process the pipeline for grant-type manifests
            Map<String, byte[]> pipelineContext = new HashMap<>(); // To store outputs of steps
            SymmetricKey derivedRek = null;
            FailureDetailsInfo failureDetails = null;
            String requiredInputPrompt = null;
            boolean pipelineRequiresInput = false;

            for (CryptoStep step : manifest.getCryptoPipeline()) {
                try {
                    byte[] stepInputData = resolveStepInput(step.getInputSource(), manifest.getEncryptedPayload(), pipelineContext);
                    KeyMaterial stepKeyMaterial = resolveStepKeyMaterial(
                            step.getKeySource(),
                            identityContext,
                            inputProvider,
                            keySourceResolver,
                            manifest,
                            pipelineContext);

                    if (stepKeyMaterial == null && requiresKeyMaterial(step.getKeySource().getType())) {
                        // This can happen if InputProvider returns empty Optional for a required key
                        if (CryptoStepKeySourceType.INPUT_PROVIDER_SECRET.equals(step.getKeySource().getType())) {
                            pipelineRequiresInput = true;
                            requiredInputPrompt = step.getKeySource().getPromptHint();
                            break; // Break from steps loop, requires user input
                        }
                        failureDetails = FailureDetailsInfo.builder()
                                .failedStepId(step.getStepId())
                                .errorCode("KEY_RESOLUTION_FAILED")
                                .message("Failed to resolve key material for step: " + step.getStepId())
                                .build();
                        break; // Break from steps loop, step failed
                    }

                    byte[] stepOutput = executeCryptoStep(step, stepInputData, stepKeyMaterial);

                    if (step.getOutputName() != null) {
                        pipelineContext.put(step.getOutputName(), stepOutput);
                    }

                    // If this is the last step, its output is the REK
                    if (manifest.getCryptoPipeline().indexOf(step) == manifest.getCryptoPipeline().size() - 1) {
                        // Assuming the final output is always a symmetric key (the REK)
                        // A more robust system might have the step declare its output type
                        derivedRek = new SymmetricKey(stepOutput, step.getAlgorithmName()); // Or derive algo from params
                    }
                } catch (CryptoOperationException e) {
                    failureDetails = FailureDetailsInfo.builder()
                            .failedStepId(step.getStepId())
                            .errorCode("CRYPTO_OPERATION_FAILED")
                            .message(e.getMessage())
                            .cause(e)
                            .build();
                    break; // Break from steps loop, step failed
                } catch (Exception e) { // Catch broader exceptions for unexpected issues
                    failureDetails = FailureDetailsInfo.builder()
                            .failedStepId(step.getStepId())
                            .errorCode("UNEXPECTED_PIPELINE_ERROR")
                            .message(e.getMessage())
                            .cause(e)
                            .build();
                    break; // Break from steps loop
                }
            } // End of CryptoStep loop

            if (pipelineRequiresInput) {
                return AccessDecision.builder()
                        .outcome(AccessDecision.Outcome.REQUIRES_USER_INPUT)
                        .winningManifestId(manifest.getManifestId())
                        .requiredInputPromptHint(requiredInputPrompt)
                        .build();
            }

            if (derivedRek != null) { // Pipeline succeeded
                return AccessDecision.builder()
                        .outcome(AccessDecision.Outcome.GRANTED)
                        .derivedRek(derivedRek)
                        .effectivePermissions(manifest.getPermissions())
                        .winningManifestId(manifest.getManifestId())
                        .build();
            } else if (failureDetails != null) { // Pipeline failed at some step
                return AccessDecision.builder()
                        .outcome(AccessDecision.Outcome.PIPELINE_STEP_FAILED)
                        .winningManifestId(manifest.getManifestId())
                        .failureDetails(failureDetails)
                        .build();
            }
            // If we reach here, this manifest didn't lead to a grant or explicit fail,
            // continue to the next manifest in precedence order.
        } // End of Manifest loop

        // If no manifest resulted in a grant or explicit deny (and deny wasn't highest)
        return AccessDecision.builder()
                .outcome(AccessDecision.Outcome.NO_APPLICABLE_MANIFEST_FOUND) // Or DENIED if default policy is deny
                .build();
    }

    private boolean isDenyManifest(ManifestType manifestType) {
        // This logic depends on how DenyTypes are identified.
        // For example, if ManifestType has a method like `isDenial()`
        // or if there's a specific known name/class for deny types.
        // Placeholder for now:
        return manifestType.getName().toUpperCase().contains("DENY");
    }

    private boolean requiresKeyMaterial(CryptoStepKeySourceType sourceType) {
        switch (sourceType) {
            case IDENTITY_IKP_PRIVATE_KEY:
            case GROUP_SYMMETRIC_KEY:
            case PREVIOUS_STEP_OUTPUT_AS_KEY:
            case APPLICATION_RESOLVED_KEY:
            case INPUT_PROVIDER_SECRET: // Secret itself is not key, but leads to key derivation
                return true;
            default:
                return false;
        }
    }


    private byte[] resolveStepInput(InputSourceInfo inputSource, Map<String, byte[]> manifestPayload, Map<String, byte[]> pipelineContext) {
        switch (inputSource.getType()) {
            case MANIFEST_PAYLOAD:
                if (inputSource.getPayloadKey() == null) {
                    throw new IllegalArgumentException("Payload key missing for MANIFEST_PAYLOAD input source.");
                }
                byte[] payloadData = manifestPayload.get(inputSource.getPayloadKey());
                if (payloadData == null) {
                    throw new IllegalArgumentException("No payload found for key: " + inputSource.getPayloadKey());
                }
                return payloadData;
            case PREVIOUS_STEP_OUTPUT:
                if (inputSource.getStepRef() == null) {
                    throw new IllegalArgumentException("Step reference missing for PREVIOUS_STEP_OUTPUT input source.");
                }
                byte[] previousOutput = pipelineContext.get(inputSource.getStepRef());
                if (previousOutput == null) {
                    throw new IllegalStateException("Output from referenced step not found: " + inputSource.getStepRef());
                }
                return previousOutput;
            case CONSTANT_DATA:
                if (inputSource.getConstantData() == null) {
                    throw new IllegalArgumentException("Constant data missing for CONSTANT_DATA input source.");
                }
                return inputSource.getConstantData();
            default:
                throw new UnsupportedOperationException("Unsupported input source type: " + inputSource.getType());
        }
    }

    private KeyMaterial resolveStepKeyMaterial(
            KeySourceInfo keySource,
            IdentityContext identityContext,
            InputProvider inputProvider,
            KeySourceResolver keySourceResolver,
            AccessManifest currentManifest,
            Map<String, byte[]> pipelineContext) {

        switch (keySource.getType()) {
            case IDENTITY_IKP_PRIVATE_KEY:
                return inputProvider.getIdentityPrivateKey(identityContext.getIdentityId(), keySource.getIdentifier())
                        .orElse(null); // Or throw if absolutely required and not found
            case GROUP_SYMMETRIC_KEY:
                return inputProvider.getGroupSymmetricKey(identityContext, new Identifier(keySource.getIdentifier()), null /*version hint*/)
                        .orElse(null);
            case INPUT_PROVIDER_SECRET:
                // This case is special: the secret itself isn't the key, but input to a KDF step.
                // The actual "key" for the KDF step is derived from this secret.
                // So, this method might return null, and the executeCryptoStep for KDF
                // would use the inputProvider to get the password.
                // Or, this method could fetch the secret and return it as a special KeyMaterial type.
                // For now, let's assume KDF steps handle this directly via inputProvider.
                // This indicates that the *key for the step* will be derived using a secret from input provider
                // The actual secret retrieval will happen in executeCryptoStep if operation is KDF.
                // This is a bit of a semantic stretch for "KeyMaterial".
                // A better approach: KDF steps don't have a "keySource" of this type,
                // but their "inputSource" points to the password obtained via inputProvider.
                // Let's refine this: INPUT_PROVIDER_SECRET means the *key itself* is the secret.
                // This is more for things like HMAC keys provided directly.
                // For password-derived keys, the KDF step would take the password as *input data*.

                // Re-thinking: The keySource for a KDF step is effectively the password.
                // The KDF operation then *produces* a key.
                // So, if a step is "DERIVE_KEY_FROM_PASSWORD", its inputSource might be "INPUT_PROVIDER_SECRET".
                // If a step is "SYMMETRIC_DECRYPT" and keySource is "INPUT_PROVIDER_SECRET", it implies the secret *is* the key.
                Optional<char[]> passwordChars = inputProvider.requestPasswordSecret(
                        keySource.getType().name(), // Or a more specific type from keySource.identifier
                        keySource.getPromptHint(),
                        Collections.singletonMap("resourceId", currentManifest.getResourceId().getValue())
                );
                if (passwordChars.isPresent()) {
                    // Convert char[] to SymmetricKey - this is a simplification.
                    // In reality, this password would be input to a KDF step.
                    // This path needs careful design for KDFs.
                    // For now, assume it's a raw symmetric key if used directly.
                    // This is likely incorrect for direct use as key.
                    // Let's assume this path is primarily for KDF input.
                    // The KDF step itself would call inputProvider.
                    // So, if keySource is INPUT_PROVIDER_SECRET for an encryption step, it's an error.
                    // This type should primarily feed a KDF step as *input data*.
                    // Let's return null and let the KDF step handle it.
                    // This means the executeCryptoStep for KDF needs to use inputProvider.
                    // Returning null here means "key must be resolved by the step operation itself using inputProvider"
                    return null; // Signal that the step itself will use InputProvider
                }
                return null;


            case PREVIOUS_STEP_OUTPUT_AS_KEY:
                if (keySource.getStepRef() == null) {
                    throw new IllegalArgumentException("Step reference missing for PREVIOUS_STEP_OUTPUT_AS_KEY key source.");
                }
                byte[] keyBytes = pipelineContext.get(keySource.getStepRef());
                if (keyBytes == null) {
                    throw new IllegalStateException("Key material from referenced step not found: " + keySource.getStepRef());
                }
                // We need to know the algorithm of this derived key.
                // This should ideally be part of the output of the previous step or inferred.
                // For now, a placeholder. This needs a more robust way to carry key algorithm info.
                return new SymmetricKey(keyBytes, "UNKNOWN_DERIVED_ALGORITHM");

            case APPLICATION_RESOLVED_KEY:
                if (keySourceResolver == null) {
                    throw new IllegalStateException("KeySourceResolver is null, but required for APPLICATION_RESOLVED_KEY.");
                }
                return keySourceResolver.resolveKey(keySource.getIdentifier(), identityContext, currentManifest)
                        .orElse(null);
            default:
                throw new UnsupportedOperationException("Unsupported key source type: " + keySource.getType());
        }
    }

    private byte[] executeCryptoStep(CryptoStep step, byte[] inputData, KeyMaterial keyMaterial) throws CryptoOperationException {
        // This is where the actual cryptographic operations happen based on step.getOperationName()
        // It would delegate to the appropriate crypto service.
        // For example:
        String operation = step.getOperationName().toUpperCase();
        CryptoParameters params = step.getCryptoParameters();

        switch (operation) {
            case "SYMMETRIC_DECRYPT":
                if (!(keyMaterial instanceof SymmetricKey)) {
                    throw new CryptoOperationException("Invalid key type for symmetric decryption.", step.getAlgorithmName(), null);
                }
                return symmetricEncryptionService.decrypt(inputData, (SymmetricKey) keyMaterial, params).getPlaintext();
            case "ASYMMETRIC_DECRYPT":
                if (!(keyMaterial instanceof PrivateKeyMaterial)) {
                    throw new CryptoOperationException("Invalid key type for asymmetric decryption.", step.getAlgorithmName(), null);
                }
                return asymmetricEncryptionService.decrypt(inputData, (PrivateKeyMaterial) keyMaterial, params).getPlaintext();
            case "KEY_DERIVATION_FROM_PASSWORD":
                // Here, inputData would be the salt (if not in params), and keyMaterial would be null.
                // The password would be fetched via InputProvider (this logic needs to be integrated,
                // perhaps InputProvider is passed to executeCryptoStep or KDF step handles it).
                // This part of the design needs refinement for KDFs.
                // For now, let's assume password was fetched and is part of a conceptual "secret input"
                // that the KDF service knows how to get via InputProvider if keyMaterial is null
                // and keySource was INPUT_PROVIDER_SECRET.

                // Simplified: Assume password was resolved into keyMaterial for KDF by a previous conceptual step
                // or that passwordKdfService handles the InputProvider interaction.
                // This is a complex interaction point.
                // Let's assume for now that if operation is KDF, inputData contains the salt,
                // and the passwordKdfService will use an InputProvider to get the password.
                // This is a placeholder - the password needs to be passed securely.
                // A char[] password should be passed to passwordKdfService.
                // This requires InputProvider to be accessible here or password to be pre-fetched.

                // For now, this is a simplified placeholder for KDF.
                // A proper KDF step would need the password (char[]) from InputProvider.
                // The current 'inputData' might be the salt from the manifest.
                if (step.getKeySource().getType() == CryptoStepKeySourceType.INPUT_PROVIDER_SECRET) {
                    // This means the passwordKdfService itself should use the inputProvider
                    // Or, the DefaultAccessDecisionEngine should have fetched it.
                    // This is a critical point of interaction.
                    // Let's assume passwordKdfService is given the InputProvider.
                    // This is not ideal. The Engine should orchestrate.
                    // TODO: Refine KDF step handling with InputProvider.
                    // For now, we'll throw, as this needs a clearer flow for password.
                    throw new UnsupportedOperationException("KDF from password step needs refined InputProvider flow.");
                } else {
                    // KDF from other key material? Unlikely for "password" KDF.
                    throw new UnsupportedOperationException("Unsupported KDF input for this step.");
                }

                // Add more operations: SYMMETRIC_ENCRYPT, ASYMMETRIC_ENCRYPT, SIGN, VERIFY, HASH etc.
                // These would be used by the AccessManifestFactory.
            default:
                throw new UnsupportedOperationException("Unsupported crypto operation: " + step.getOperationName());
        }
    }
}