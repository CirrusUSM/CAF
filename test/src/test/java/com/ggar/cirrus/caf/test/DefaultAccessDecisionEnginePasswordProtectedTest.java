package com.ggar.cirrus.caf.test;

import com.ggar.cirrus.caf.common.CryptoOperationException;
import com.ggar.cirrus.caf.common.CryptoParameters;
import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.caf.common.Permission;
import com.ggar.cirrus.fac.crypto.api.PasswordBasedKeyDerivationService;
import com.ggar.cirrus.fac.crypto.api.SymmetricEncryptionService;
import com.ggar.cirrus.fac.crypto.api.AsymmetricEncryptionService; // Added for completeness in constructor
import com.ggar.cirrus.fac.crypto.api.dto.DecryptionOutput;
import com.ggar.cirrus.fac.crypto.api.dto.SymmetricKey;
import com.ggar.cirrus.fac.manifest.api.*; // All DTOs and interfaces from manifest.api

import com.ggar.cirrus.fac.manifest.engine.core.DefaultAccessDecisionEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.Serializable;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify; // For verifying interactions if needed
import static org.mockito.Mockito.times; // For verifying interaction counts

/**
 * Integration test for {@link DefaultAccessDecisionEngine} focusing on the
 * password-protected link scenario.
 * This test verifies the interaction between the engine, crypto services (mocked),
 * and the InputProvider (mocked) to derive a Resource Encryption Key (REK).
 */
@ExtendWith(MockitoExtension.class)
class DefaultAccessDecisionEnginePasswordProtectedTest {

    @Mock
    private SymmetricEncryptionService mockSymmetricEncryptionService;
    @Mock
    private AsymmetricEncryptionService mockAsymmetricEncryptionService; // Mock even if not directly used in every test path
    @Mock
    private PasswordBasedKeyDerivationService mockPasswordKdfService;
    @Mock
    private InputProvider mockInputProvider;
    @Mock
    private KeySourceResolver mockKeySourceResolver; // Can be null if not used by a specific flow

    // The class under test - will be instantiated with mocks
    private DefaultAccessDecisionEngine accessDecisionEngine;

    // Test data constants
    private static final Identifier RESOURCE_ID = Identifier.randomIdentifier();
    private static final Identifier IDENTITY_ID = Identifier.randomIdentifier();
    private static final Identifier LINK_ID = Identifier.randomIdentifier();
    private static final String USER_PASSWORD_FOR_LINK_STRING = "TestPassword123!";
    private static final char[] USER_PASSWORD_FOR_LINK_CHARS = USER_PASSWORD_FOR_LINK_STRING.toCharArray();
    private static final byte[] SALT = "test-salt-1234567890123456".getBytes(); // Ensure salt has appropriate length for some KDFs
    private static final byte[] ENCRYPTED_REK_PAYLOAD = "encrypted-rek-data-bytes-array".getBytes();
    private static final byte[] PLAINTEXT_REK_BYTES = "decrypted-actual-rek-bytes".getBytes();
    private static final String KDF_ALGORITHM = "Argon2id";
    private static final String REK_ENCRYPTION_ALGORITHM = "AES-GCM"; // e.g., AES/GCM/NoPadding
    private static final String DERIVED_KEY_OUTPUT_NAME = "derivedLinkKey";
    private static final String WRAPPED_REK_PAYLOAD_KEY = "wrappedREK";

    private IdentityContext testIdentityContext;
    private AccessManifest passwordProtectedManifest;
    private SymmetricKey derivedKeyFromPassword;
    private SymmetricKey plaintextRek;

    @BeforeEach
    void setUp() {
        accessDecisionEngine = new DefaultAccessDecisionEngine(
                mockSymmetricEncryptionService,
                mockAsymmetricEncryptionService, // Pass the mock
                mockPasswordKdfService
        );

        testIdentityContext = IdentityContext.builder()
                .identityId(IDENTITY_ID)
                .attribute("username", "testUser")
                .build();

        derivedKeyFromPassword = new SymmetricKey(
                "derived-key-bytes-for-aes".getBytes(), // Ensure appropriate length for AES
                REK_ENCRYPTION_ALGORITHM
        );

        plaintextRek = new SymmetricKey(
                PLAINTEXT_REK_BYTES,
                "AES" // Algorithm of the REK itself
        );

        CryptoParameters kdfCryptoParams = CryptoParameters.builder()
                .parameters(new HashMap<>(){{
                    put(CryptoParameters.ALGORITHM_NAME, KDF_ALGORITHM);
                    put(CryptoParameters.SALT, SALT);
                    put(CryptoParameters.KDF_ITERATIONS, 10000);
                    put(CryptoParameters.KEY_LENGTH_BITS, 256); // For AES-256 derived key
                }})
                .build();

        CryptoStep step1_deriveKey = CryptoStep.builder()
                .stepId("S1_DERIVE_KEY")
                .operationName("KEY_DERIVATION_FROM_PASSWORD")
                .algorithmName(KDF_ALGORITHM)
                .inputSource(InputSourceInfo.builder()
                        .type(CryptoStepInputSourceType.CONSTANT_DATA)
                        .constantData(SALT) // Salt passed as constant data to KDF step
                        .build())
                .keySource(KeySourceInfo.builder()
                        .type(CryptoStepKeySourceType.INPUT_PROVIDER_SECRET)
                        .promptHint("Enter password for link " + LINK_ID.getValue())
                        .build())
                .cryptoParameters(kdfCryptoParams)
                .outputName(DERIVED_KEY_OUTPUT_NAME)
                .build();

        byte[] ivForRekDecryption = new byte[12]; // GCM recommended IV size
        new Random().nextBytes(ivForRekDecryption); // Example IV
        CryptoParameters rekDecryptParams = CryptoParameters.builder()
                .parameters(new HashMap<>(){{
                    put(CryptoParameters.ALGORITHM_NAME, REK_ENCRYPTION_ALGORITHM);
                    put(CryptoParameters.IV, ivForRekDecryption);
                    put(CryptoParameters.AEAD_TAG_LENGTH_BITS, 128); // Common for GCM
                }})
                .build();

        CryptoStep step2_decryptRek = CryptoStep.builder()
                .stepId("S2_DECRYPT_REK")
                .operationName("SYMMETRIC_DECRYPT")
                .algorithmName(REK_ENCRYPTION_ALGORITHM)
                .inputSource(InputSourceInfo.builder()
                        .type(CryptoStepInputSourceType.MANIFEST_PAYLOAD)
                        .payloadKey(WRAPPED_REK_PAYLOAD_KEY)
                        .build())
                .keySource(KeySourceInfo.builder()
                        .type(CryptoStepKeySourceType.PREVIOUS_STEP_OUTPUT_AS_KEY)
                        .stepRef(DERIVED_KEY_OUTPUT_NAME)
                        .build())
                .cryptoParameters(rekDecryptParams)
                .build();

        ManifestType linkManifestType = new ManifestType() {
            @Override public String getName() { return "TEST_LINK_PASSWORD_TYPE"; }
            @Override public int getPrecedence() { return 100; }
        };

        RecipientMatcher linkMatcher = new RecipientMatcher() {
            @Override public boolean matches(IdentityContext context) { return true; }
            @Override public Identifier getTargetRecipientIdentifier() { return LINK_ID; }
        };

        passwordProtectedManifest = new AccessManifestImpl(
                Identifier.randomIdentifier(),
                RESOURCE_ID,
                linkManifestType,
                linkMatcher,
                Arrays.asList(step1_deriveKey, step2_decryptRek),
                Collections.singletonMap(WRAPPED_REK_PAYLOAD_KEY, ENCRYPTED_REK_PAYLOAD),
                Collections.singleton(Permission.READ_RESOURCE),
                Instant.now(),
                Collections.emptyMap()
        );
    }

    @Test
    @DisplayName("Should grant access and derive REK for a valid password-protected manifest")
    void evaluateAccess_passwordProtected_success() {
        // Arrange Mocks
        when(mockInputProvider.requestPasswordSecret(
                eq(CryptoStepKeySourceType.INPUT_PROVIDER_SECRET.name()), // Or more specific type if refined
                any(String.class),
                any(Map.class)
        )).thenReturn(Optional.of(USER_PASSWORD_FOR_LINK_CHARS));

        when(mockPasswordKdfService.deriveKeyFromPassword(
                eq(USER_PASSWORD_FOR_LINK_CHARS), // Expect char[]
                any(CryptoParameters.class)
        )).thenReturn(derivedKeyFromPassword);

        when(mockSymmetricEncryptionService.decrypt(
                eq(ENCRYPTED_REK_PAYLOAD),
                eq(derivedKeyFromPassword),
                any(CryptoParameters.class)
        )).thenReturn(new DecryptionOutput(PLAINTEXT_REK_BYTES));

        // Act
        AccessDecision decision = accessDecisionEngine.evaluateAccess(
                Collections.singletonList(passwordProtectedManifest),
                testIdentityContext,
                mockInputProvider,
                mockKeySourceResolver
        );

        // Assert
        assertNotNull(decision, "AccessDecision should not be null");
        assertEquals(AccessDecision.Outcome.GRANTED, decision.getOutcome(), "Outcome should be GRANTED");
        assertNotNull(decision.getDerivedRek(), "Derived REK should not be null");
        assertArrayEquals(PLAINTEXT_REK_BYTES, decision.getDerivedRek().getEncoded(), "Derived REK content mismatch");
        assertEquals(passwordProtectedManifest.getManifestId(), decision.getWinningManifestId(), "Winning manifest ID mismatch");
        assertTrue(decision.getEffectivePermissions().contains(Permission.READ_RESOURCE), "Should have READ permission");
        assertNull(decision.getFailureDetails(), "Failure details should be null on success");
        assertNull(decision.getRequiredInputPromptHint(), "No input should be required after success");

        // Verify interactions
        verify(mockInputProvider, times(1)).requestPasswordSecret(any(), any(), any());
        verify(mockPasswordKdfService, times(1)).deriveKeyFromPassword(any(char[].class), any(CryptoParameters.class));
        verify(mockSymmetricEncryptionService, times(1)).decrypt(any(byte[].class), any(SymmetricKey.class), any(CryptoParameters.class));
    }

    @Test
    @DisplayName("Should return REQUIRES_USER_INPUT if InputProvider returns empty for password")
    void evaluateAccess_passwordProtected_inputProviderReturnsEmpty() {
        // Arrange Mocks
        when(mockInputProvider.requestPasswordSecret(
                any(String.class), any(String.class), any(Map.class)
        )).thenReturn(Optional.empty());

        // Act
        AccessDecision decision = accessDecisionEngine.evaluateAccess(
                Collections.singletonList(passwordProtectedManifest),
                testIdentityContext,
                mockInputProvider,
                mockKeySourceResolver
        );

        // Assert
        assertNotNull(decision);
        assertEquals(AccessDecision.Outcome.REQUIRES_USER_INPUT, decision.getOutcome());
        assertEquals(passwordProtectedManifest.getManifestId(), decision.getWinningManifestId());
        assertNotNull(decision.getRequiredInputPromptHint());
        assertNull(decision.getDerivedRek());
        assertNull(decision.getFailureDetails());

        verify(mockInputProvider, times(1)).requestPasswordSecret(any(), any(), any());
    }

    @Test
    @DisplayName("Should return PIPELINE_STEP_FAILED if KDF fails")
    void evaluateAccess_passwordProtected_kdfFails() {
        // Arrange Mocks
        when(mockInputProvider.requestPasswordSecret(any(), any(), any())).thenReturn(Optional.of(USER_PASSWORD_FOR_LINK_CHARS));
        when(mockPasswordKdfService.deriveKeyFromPassword(any(char[].class), any(CryptoParameters.class)))
                .thenThrow(new CryptoOperationException("KDF failed", KDF_ALGORITHM, new RuntimeException("Simulated KDF error")));

        // Act
        AccessDecision decision = accessDecisionEngine.evaluateAccess(
                Collections.singletonList(passwordProtectedManifest),
                testIdentityContext,
                mockInputProvider,
                mockKeySourceResolver
        );

        // Assert
        assertNotNull(decision);
        assertEquals(AccessDecision.Outcome.PIPELINE_STEP_FAILED, decision.getOutcome());
        assertEquals(passwordProtectedManifest.getManifestId(), decision.getWinningManifestId());
        assertNotNull(decision.getFailureDetails());
        assertEquals("S1_DERIVE_KEY", decision.getFailureDetails().getFailedStepId());
        assertEquals("CRYPTO_OPERATION_FAILED", decision.getFailureDetails().getErrorCode());
        assertNull(decision.getDerivedRek());

        verify(mockInputProvider, times(1)).requestPasswordSecret(any(), any(), any());
        verify(mockPasswordKdfService, times(1)).deriveKeyFromPassword(any(char[].class), any(CryptoParameters.class));
    }

    @Test
    @DisplayName("Should return PIPELINE_STEP_FAILED if REK decryption fails")
    void evaluateAccess_passwordProtected_rekDecryptionFails() {
        // Arrange Mocks
        when(mockInputProvider.requestPasswordSecret(any(), any(), any())).thenReturn(Optional.of(USER_PASSWORD_FOR_LINK_CHARS));
        when(mockPasswordKdfService.deriveKeyFromPassword(any(char[].class), any(CryptoParameters.class)))
                .thenReturn(derivedKeyFromPassword);
        when(mockSymmetricEncryptionService.decrypt(any(byte[].class), eq(derivedKeyFromPassword), any(CryptoParameters.class)))
                .thenThrow(new CryptoOperationException("REK Decryption failed", REK_ENCRYPTION_ALGORITHM, new RuntimeException("Simulated decrypt error")));

        // Act
        AccessDecision decision = accessDecisionEngine.evaluateAccess(
                Collections.singletonList(passwordProtectedManifest),
                testIdentityContext,
                mockInputProvider,
                mockKeySourceResolver
        );

        // Assert
        assertNotNull(decision);
        assertEquals(AccessDecision.Outcome.PIPELINE_STEP_FAILED, decision.getOutcome());
        assertEquals(passwordProtectedManifest.getManifestId(), decision.getWinningManifestId());
        assertNotNull(decision.getFailureDetails());
        assertEquals("S2_DECRYPT_REK", decision.getFailureDetails().getFailedStepId());
        assertEquals("CRYPTO_OPERATION_FAILED", decision.getFailureDetails().getErrorCode());
        assertNull(decision.getDerivedRek());

        verify(mockInputProvider, times(1)).requestPasswordSecret(any(), any(), any());
        verify(mockPasswordKdfService, times(1)).deriveKeyFromPassword(any(char[].class), any(CryptoParameters.class));
        verify(mockSymmetricEncryptionService, times(1)).decrypt(any(byte[].class), any(SymmetricKey.class), any(CryptoParameters.class));
    }

    @lombok.Value
    private static class AccessManifestImpl implements AccessManifest {
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
}
