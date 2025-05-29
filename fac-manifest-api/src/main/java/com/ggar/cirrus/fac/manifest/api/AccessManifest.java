package com.ggar.cirrus.fac.manifest.api;

import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.caf.common.Permission;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Represents an Access Manifest, which defines a specific grant or denial of access
 * to a Resource's Resource Encryption Key (REK).
 * It contains a declarative cryptographic pipeline (a list of {@link CryptoStep}s)
 * that, if successfully executed by an authorized identity, yields the plaintext REK.
 */
public interface AccessManifest extends Serializable {

    /**
     * Gets the unique identifier for this manifest.
     *
     * @return The manifest {@link Identifier}.
     */
    Identifier getManifestId();

    /**
     * Gets the identifier of the Resource whose REK this manifest protects or pertains to.
     *
     * @return The resource {@link Identifier}.
     */
    Identifier getResourceId();

    /**
     * Gets the type of this manifest, which influences its evaluation precedence and interpretation.
     *
     * @return The {@link ManifestType}.
     */
    ManifestType getManifestType();

    /**
     * Gets the matcher that determines if this manifest is applicable to a given requesting identity.
     *
     * @return The {@link RecipientMatcher}.
     */
    RecipientMatcher getRecipientMatcher();

    /**
     * Gets the ordered list of cryptographic steps (the pipeline) required to derive the REK.
     * For denial manifests, this list might be empty.
     *
     * @return An unmodifiable list of {@link CryptoStep}s.
     */
    List<CryptoStep> getCryptoPipeline();

    /**
     * Gets the encrypted payload associated with this manifest.
     * This map can contain multiple named byte arrays, such as the encrypted REK,
     * an encrypted KEK, or other cryptographic material needed by the pipeline.
     * Keys in the map can be referenced by {@link InputSourceInfo#getPayloadKey()}.
     *
     * @return An unmodifiable map where keys are strings and values are byte arrays.
     * Returns an empty map if no payload is present (e.g., for some denial manifests).
     */
    Map<String, byte[]> getEncryptedPayload();

    /**
     * Gets the set of granular permissions granted if this manifest successfully yields the REK.
     * For denial manifests, this set would typically be empty or ignored.
     *
     * @return An unmodifiable set of {@link Permission}s.
     */
    Set<Permission> getPermissions();

    /**
     * Gets the timestamp of when this manifest was created or became effective.
     *
     * @return The creation {@link Instant}.
     */
    Instant getCreationTimestamp();

    /**
     * Gets additional application-specific metadata associated with this manifest.
     * This allows consuming applications to store extra information without modifying
     * the core FAC structures. Values should be {@link Serializable}.
     *
     * @return An unmodifiable map of metadata.
     */
    Map<String, Serializable> getMetadata();
}