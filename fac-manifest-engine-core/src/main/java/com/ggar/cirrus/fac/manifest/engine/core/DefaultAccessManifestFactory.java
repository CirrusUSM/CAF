package com.ggar.cirrus.fac.manifest.engine.core;

import com.ggar.cirrus.caf.common.CryptoParameters;
import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.caf.common.Permission;
import com.ggar.cirrus.fac.crypto.api.AsymmetricEncryptionService;
import com.ggar.cirrus.fac.crypto.api.PasswordBasedKeyDerivationService;
import com.ggar.cirrus.fac.crypto.api.SymmetricEncryptionService;
import com.ggar.cirrus.fac.crypto.api.dto.EncryptionOutput;
import com.ggar.cirrus.fac.crypto.api.dto.PublicKeyMaterial;
import com.ggar.cirrus.fac.crypto.api.dto.SymmetricKey;
import com.ggar.cirrus.fac.manifest.api.*; // For AccessManifest, CryptoStep, etc.
import lombok.Value;

import java.io.Serializable;
import java.time.Instant;
import java.util.*;

/**
 * Default implementation of {@link AccessManifestFactory}.
 * This factory uses the provided crypto services to perform the necessary
 * encryption operations when creating manifests.
 */
public class DefaultAccessManifestFactory implements AccessManifestFactory {

    private final SymmetricEncryptionService symmetricEncryptionService;
    private final AsymmetricEncryptionService asymmetricEncryptionService;
    private final PasswordBasedKeyDerivationService passwordKdfService;
    private final IdentifierFactory identifierFactory; // To generate manifest IDs

    // Default algorithm names - should be configurable or passed in
    private static final String DEFAULT_REK_ASYMMETRIC_WRAP_ALGO = "RSA-OAEP-SHA256"; // Example
    private static final String DEFAULT_REK_SYMMETRIC_WRAP_ALGO = "AES-GCM";      // Example
    private static final String DEFAULT_PASSWORD_KDF_ALGO = "Argon2id";           // Example
    private static final String DEFAULT_PASSWORD_REK_WRAP_ALGO = "AES-GCM";     // Example
    private static final int DEFAULT_PASSWORD_KDF_ITERATIONS = 100000; // Example
    private static final int DEFAULT_SALT_LENGTH_BYTES = 16; // Example

    /**
     * Interface for generating unique identifiers for manifests.
     * Can be implemented using UUIDs or other schemes.
     */
    public interface IdentifierFactory {
        Identifier create();
    }

    public DefaultAccessManifestFactory(
            SymmetricEncryptionService symmetricEncryptionService,
            AsymmetricEncryptionService asymmetricEncryptionService,
            PasswordBasedKeyDerivationService passwordKdfService,
            IdentifierFactory identifierFactory) {
        this.symmetricEncryptionService = Objects.requireNonNull(symmetricEncryptionService);
        this.asymmetricEncryptionService = Objects.requireNonNull(asymmetricEncryptionService);
        this.passwordKdfService = Objects.requireNonNull(passwordKdfService);
        this.identifierFactory = Objects.requireNonNull(identifierFactory);
    }

    @Override
    public AccessManifest createDirectShareManifest(
            Identifier resourceId,
            SymmetricKey rekToProtect,
            Identifier recipientIdentityId,
            PublicKeyMaterial recipientPublicKey,
            Set<Permission> permissions,
            ManifestType manifestType,
            Map<String, java.io.Serializable> customMetadata) {

        CryptoParameters encParams = CryptoParameters.builder()
                .parameters(new HashMap<>() {{
                    put(CryptoParameters.ALGORITHM_NAME, DEFAULT_REK_ASYMMETRIC_WRAP_ALGO);
                }})
                // Add other necessary params for the chosen asymmetric algorithm if any
                .build();

        EncryptionOutput encryptedRek = asymmetricEncryptionService.encrypt(
                rekToProtect.getEncoded(), recipientPublicKey, encParams);

        List<CryptoStep> pipeline = Collections.singletonList(
                CryptoStep.builder()
                        .stepId("s1_decrypt_rek_asymmetric")
                        .operationName("ASYMMETRIC_DECRYPT")
                        .algorithmName(recipientPublicKey.getAlgorithm()) // Or from encParams
                        .inputSource(InputSourceInfo.builder()
                                .type(CryptoStepInputSourceType.MANIFEST_PAYLOAD)
                                .payloadKey("wrappedREK")
                                .build())
                        .keySource(KeySourceInfo.builder()
                                .type(CryptoStepKeySourceType.IDENTITY_IKP_PRIVATE_KEY)
                                .identifier(recipientIdentityId.getValue()) // Hint for which IKP
                                .build())
                        .cryptoParameters(encryptedRek.getParameters()) // Store params used for encryption (like OAEP label)
                        .outputName("plaintextREK")
                        .build()
        );

        Map<String, byte[]> payload = Collections.singletonMap("wrappedREK", encryptedRek.getCiphertext());

        return new ConcreteAccessManifest( // Assuming a concrete implementation
                identifierFactory.create(),
                resourceId,
                manifestType,
                new ConcreteRecipientMatcher(ConcreteRecipientMatcher.Type.IDENTITY, recipientIdentityId), // Example
                pipeline,
                payload,
                permissions,
                Instant.now(),
                customMetadata != null ? customMetadata : Collections.emptyMap()
        );
    }

    @Override
    public AccessManifest createGroupShareManifest(
            Identifier resourceId,
            SymmetricKey rekToProtect,
            Identifier groupId,
            SymmetricKey groupKey,
            Set<Permission> permissions,
            ManifestType manifestType,
            Map<String, java.io.Serializable> customMetadata) {

        // For symmetric encryption, we need to generate an IV if using modes like GCM/CBC
        // The symmetricEncryptionService.encrypt should handle IV generation and return it
        // in EncryptionOutput.parameters.
        CryptoParameters symEncParams = CryptoParameters.builder()
                .parameters(new HashMap<>() {{
                    put(CryptoParameters.ALGORITHM_NAME, DEFAULT_REK_SYMMETRIC_WRAP_ALGO); // e.g., AES/GCM/NoPadding
                }})
                // IV will be generated by the service and returned in EncryptionOutput
                .build();

        EncryptionOutput encryptedRek = symmetricEncryptionService.encrypt(
                rekToProtect.getEncoded(), groupKey, symEncParams);

        List<CryptoStep> pipeline = Collections.singletonList(
                CryptoStep.builder()
                        .stepId("s1_decrypt_rek_symmetric_group")
                        .operationName("SYMMETRIC_DECRYPT")
                        .algorithmName(groupKey.getAlgorithm()) // Or from symEncParams
                        .inputSource(InputSourceInfo.builder()
                                .type(CryptoStepInputSourceType.MANIFEST_PAYLOAD)
                                .payloadKey("wrappedREK")
                                .build())
                        .keySource(KeySourceInfo.builder()
                                .type(CryptoStepKeySourceType.GROUP_SYMMETRIC_KEY)
                                .identifier(groupId.getValue()) // Group ID to fetch the key
                                .build())
                        .cryptoParameters(encryptedRek.getParameters()) // Contains IV, tag length etc.
                        .outputName("plaintextREK")
                        .build()
        );
        Map<String, byte[]> payload = Collections.singletonMap("wrappedREK", encryptedRek.getCiphertext());

        return new ConcreteAccessManifest(
                identifierFactory.create(),
                resourceId,
                manifestType,
                new ConcreteRecipientMatcher(ConcreteRecipientMatcher.Type.GROUP, groupId), // Example
                pipeline,
                payload,
                permissions,
                Instant.now(),
                customMetadata != null ? customMetadata : Collections.emptyMap()
        );
    }

    @Override
    public AccessManifest createLinkPasswordManifest(
            Identifier resourceId,
            SymmetricKey rekToProtect,
            Identifier linkId,
            char[] password,
            Set<Permission> permissions,
            ManifestType manifestType,
            Map<String, java.io.Serializable> customMetadata) {

        // 1. Derive key from password
        byte[] salt = generateRandomSalt(); // Helper method needed
        CryptoParameters kdfParams = CryptoParameters.builder()
                .parameters(new HashMap<>() {{
                    put(CryptoParameters.ALGORITHM_NAME, DEFAULT_PASSWORD_KDF_ALGO);
                    put(CryptoParameters.SALT, salt);
                    put(CryptoParameters.KDF_ITERATIONS, DEFAULT_PASSWORD_KDF_ITERATIONS);
                    put(CryptoParameters.KEY_LENGTH_BITS, rekToProtect.getAlgorithm().contains("256") ? 256 : 128); // Example
                }})
                .build();
        SymmetricKey derivedKey = passwordKdfService.deriveKeyFromPassword(password, kdfParams);

        // 2. Encrypt REK with derived key
        CryptoParameters rekEncParams = CryptoParameters.builder()
                .parameters(new HashMap<>(){{
                    put(CryptoParameters.ALGORITHM_NAME, DEFAULT_PASSWORD_REK_WRAP_ALGO);
                }})
                .build() // IV will be generated by service
                ;
        EncryptionOutput encryptedRek = symmetricEncryptionService.encrypt(
                rekToProtect.getEncoded(), derivedKey, rekEncParams);

        // 3. Construct pipeline
        List<CryptoStep> pipeline = Arrays.asList(
                CryptoStep.builder()
                        .stepId("s1_derive_key_from_password")
                        .operationName("KEY_DERIVATION_FROM_PASSWORD")
                        .algorithmName(DEFAULT_PASSWORD_KDF_ALGO)
                        .inputSource(InputSourceInfo.builder() // KDF doesn't take typical "input data" but uses password
                                .type(CryptoStepInputSourceType.CONSTANT_DATA) // Or a special type?
                                .constantData(new byte[0]) // Placeholder, password comes from KeySource
                                .build())
                        .keySource(KeySourceInfo.builder() // Password is the "key" source for KDF
                                .type(CryptoStepKeySourceType.INPUT_PROVIDER_SECRET)
                                .promptHint("Enter password for link: " + linkId.getValue())
                                .build())
                        .cryptoParameters(kdfParams) // Contains salt, iterations
                        .outputName("derivedLinkKey")
                        .build(),
                CryptoStep.builder()
                        .stepId("s2_decrypt_rek_with_derived_key")
                        .operationName("SYMMETRIC_DECRYPT")
                        .algorithmName(DEFAULT_PASSWORD_REK_WRAP_ALGO)
                        .inputSource(InputSourceInfo.builder()
                                .type(CryptoStepInputSourceType.MANIFEST_PAYLOAD)
                                .payloadKey("wrappedREK")
                                .build())
                        .keySource(KeySourceInfo.builder()
                                .type(CryptoStepKeySourceType.PREVIOUS_STEP_OUTPUT_AS_KEY)
                                .stepRef("derivedLinkKey")
                                .build())
                        .cryptoParameters(encryptedRek.getParameters()) // Contains IV
                        .outputName("plaintextREK")
                        .build()
        );
        Map<String, byte[]> payload = Collections.singletonMap("wrappedREK", encryptedRek.getCiphertext());
        // Clear sensitive data
        Arrays.fill(password, '\0');
        // derivedKey.getEncoded() should also be zeroized if possible after use,
        // though SymmetricKey DTO is immutable. This highlights a challenge.

        Map<String, java.io.Serializable> manifestMetadata = new HashMap<>(customMetadata != null ? customMetadata : Collections.emptyMap());
        // Store KDF salt and iterations in manifest metadata so client doesn't need to guess
        // Or better, put them in the CryptoParameters of the KDF step.
        // The kdfParams already contains them. The client-side KDF step will use these.

        return new ConcreteAccessManifest(
                identifierFactory.create(),
                resourceId,
                manifestType,
                new ConcreteRecipientMatcher(ConcreteRecipientMatcher.Type.LINK, linkId), // Example
                pipeline,
                payload,
                permissions,
                Instant.now(),
                manifestMetadata
        );
    }

    @Override
    public AccessManifest createDenialManifest(
            Identifier resourceId,
            Identifier recipientIdentifier,
            ManifestType manifestType, // e.g., an instance of a "DenyIdentityType"
            Map<String, java.io.Serializable> customMetadata) {

        return new ConcreteAccessManifest(
                identifierFactory.create(),
                resourceId,
                manifestType,
                new ConcreteRecipientMatcher( // Determine type based on recipient (user/group)
                        inferRecipientType(recipientIdentifier), recipientIdentifier),
                Collections.emptyList(), // No crypto pipeline for denial
                Collections.emptyMap(),  // No encrypted payload
                Collections.emptySet(),  // No permissions granted
                Instant.now(),
                customMetadata != null ? customMetadata : Collections.emptyMap()
        );
    }

    @Override
    public AccessManifest createServerManagedManifest(
            Identifier resourceId,
            ManifestType manifestType,
            Map<String, java.io.Serializable> serverAccessDetails,
            Map<String, java.io.Serializable> customMetadata) {

        Map<String, java.io.Serializable> combinedMetadata = new HashMap<>();
        if (customMetadata != null) {
            combinedMetadata.putAll(customMetadata);
        }
        if (serverAccessDetails != null) {
            // Prefix to avoid clashes, or have a dedicated field in AccessManifest
            serverAccessDetails.forEach((key, value) -> combinedMetadata.put("serverManaged_" + key, value));
        }

        return new ConcreteAccessManifest(
                identifierFactory.create(),
                resourceId,
                manifestType,
                new ConcreteRecipientMatcher(ConcreteRecipientMatcher.Type.ANY, Identifier.randomIdentifier()), // Matches anyone, server enforces
                Collections.emptyList(),
                Collections.emptyMap(),
                Collections.emptySet(), // Permissions are server-side
                Instant.now(),
                combinedMetadata
        );
    }

    // --- Helper methods / Inner classes ---

    private byte[] generateRandomSalt() {
        // Use a secure random generator
        byte[] salt = new byte[DEFAULT_SALT_LENGTH_BYTES];
        new Random().nextBytes(salt); // Replace with SecureRandom in real impl
        return salt;
    }

    private ConcreteRecipientMatcher.Type inferRecipientType(Identifier recipientIdentifier) {
        // This is a placeholder. The application would need a way to know if an ID
        // refers to a user or a group, perhaps by a prefix in the ID string or by
        // querying an identity service. For the factory, it might need to be passed in.
        // For simplicity, assume it can be determined or is passed.
        if (recipientIdentifier.getValue().startsWith("user-")) return ConcreteRecipientMatcher.Type.IDENTITY;
        if (recipientIdentifier.getValue().startsWith("group-")) return ConcreteRecipientMatcher.Type.GROUP;
        return ConcreteRecipientMatcher.Type.IDENTITY; // Default or throw
    }


    /**
     * Example concrete implementation of AccessManifest.
     * In a real scenario, this would be more robust.
     */
    @Value
    private static class ConcreteAccessManifest implements AccessManifest {
        Identifier manifestId;
        Identifier resourceId;
        ManifestType manifestType;
        RecipientMatcher recipientMatcher;
        List<CryptoStep> cryptoPipeline;
        Map<String, byte[]> encryptedPayload;
        Set<Permission> permissions;
        Instant creationTimestamp;
        Map<String, Serializable> metadata;
    }

    /**
     * Example concrete implementation of RecipientMatcher.
     */
    @Value
    private static class ConcreteRecipientMatcher implements RecipientMatcher {
        enum Type { IDENTITY, GROUP, LINK, ANY } // Added ANY for server-managed
        Type type;
        Identifier targetRecipientIdentifier; // For IDENTITY, GROUP, LINK

        @Override
        public boolean matches(IdentityContext identityContext) {
            // Simplified matching logic. Real implementation would be more complex.
            if (type == Type.ANY) return true;
            if (identityContext == null) return false;

            switch (type) {
                case IDENTITY:
                    return targetRecipientIdentifier.equals(identityContext.getIdentityId());
                case GROUP:
                    return identityContext.getAttributes().get("groupMemberships") instanceof Collection &&
                            ((Collection<?>)identityContext.getAttributes().get("groupMemberships"))
                                    .contains(targetRecipientIdentifier.getValue());
                case LINK: // Link matching is usually done by the link ID itself, not against an identity context directly
                    return true; // Or based on some context if link access is tied to a session
                default:
                    return false;
            }
        }
    }
}
