package com.ggar.cirrus.fac.manifest.api;

import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.fac.crypto.api.dto.PrivateKeyMaterial; // Placeholder for actual type

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;
import lombok.ToString;

import java.io.Serializable;
import java.util.Map;
import java.util.Optional;

/**
 * Represents the context of an Identity attempting to access a Resource.
 * This information is provided by the consuming application to the {@code AccessDecisionEngine}.
 * This class is immutable.
 */
@Getter
@Builder
@ToString(exclude = "availablePrivateKeys") // Avoid logging private key material
public class IdentityContext implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The unique identifier of the requesting Identity.
     */
    private final Identifier identityId;

    /**
     * Application-specific attributes of the identity (e.g., group memberships, roles, security clearance).
     * The keys are attribute names, and values are their corresponding serializable values.
     * The {@code RecipientMatcher} implementations will use these attributes.
     */
    @Singular("attribute") // For builder: attribute("key", "value")
    private final Map<String, Serializable> attributes;

    /**
     * A map of any readily available (i.e., already decrypted and held securely in memory by the client)
     * private keys belonging to the identity. The key of the map could be a key alias or fingerprint.
     * This allows the {@code AccessDecisionEngine} to use these keys without needing to
     * re-request them via the {@code InputProvider} if a {@link CryptoStep} requires them.
     * This map should be handled with extreme care by the consuming application.
     */
    @Singular("availablePrivateKey")
    private final Map<String, PrivateKeyMaterial> availablePrivateKeys;

    /**
     * Retrieves an available private key by its alias or identifier.
     *
     * @param keyAlias The alias or identifier of the private key.
     * @return An {@link Optional} containing the {@link PrivateKeyMaterial} if available,
     * or an empty Optional otherwise.
     */
    public Optional<PrivateKeyMaterial> getAvailablePrivateKey(String keyAlias) {
        return Optional.ofNullable(availablePrivateKeys.get(keyAlias));
    }
}