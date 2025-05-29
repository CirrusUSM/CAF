package com.ggar.cirrus.fac.manifest.api;

import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.caf.common.Permission;
import com.ggar.cirrus.caf.common.CryptoParameters;
// Assuming SymmetricKey and PrivateKeyMaterial will be defined in fac-crypto-api.dto
// For now, let's use placeholder types or fully qualified names if they were already generated.
// For this example, I'll assume they exist in a known location.
import com.ggar.cirrus.fac.crypto.api.dto.SymmetricKey;
import com.ggar.cirrus.fac.crypto.api.dto.PrivateKeyMaterial; // If IdentityContext provides this directly

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;
import lombok.Value;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Defines the type or category of an Access Manifest.
 * Implementations of this interface determine the manifest's intent and its
 * evaluation precedence within the {@code AccessDecisionEngine}.
 * Consuming applications can define their own custom manifest types by implementing this interface.
 */
public interface ManifestType extends Serializable {
    /**
     * Gets the unique name or identifier for this manifest type.
     * This name can be used for logging, debugging, or by the consuming application
     * to understand the nature of the manifest.
     *
     * @return A non-null, non-empty string representing the type name (e.g., "DIRECT_SHARE", "GROUP_KEY_ACCESS").
     */
    String getName();

    /**
     * Gets the precedence value for this manifest type.
     * The {@code AccessDecisionEngine} uses this value to sort candidate manifests
     * and resolve conflicts. Lower values typically indicate higher precedence.
     *
     * @return An integer representing the precedence.
     */
    int getPrecedence();
}