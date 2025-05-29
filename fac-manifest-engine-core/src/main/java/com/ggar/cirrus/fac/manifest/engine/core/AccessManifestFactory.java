package com.ggar.cirrus.fac.manifest.engine.core;

import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.caf.common.Permission;
import com.ggar.cirrus.fac.crypto.api.dto.SymmetricKey; // For REK
import com.ggar.cirrus.fac.crypto.api.dto.PublicKeyMaterial;
// Other DTOs as needed
import com.ggar.cirrus.fac.manifest.api.AccessManifest;
import com.ggar.cirrus.fac.manifest.api.ManifestType;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Interface for a factory that creates {@link AccessManifest} instances.
 * Implementations will be responsible for constructing the manifest, including
 * defining its {@link com.ggar.cirrus.fac.manifest.api.CryptoStep} pipeline and performing the necessary
 * encryption operations to create the {@link AccessManifest#getEncryptedPayload()}.
 */
public interface AccessManifestFactory {

    /**
     * Creates an AccessManifest for granting direct access to an Identity for a given Resource Encryption Key (REK).
     * The REK will be encrypted with the recipient Identity's public key.
     *
     * @param resourceId The identifier of the Resource.
     * @param rekToProtect The Resource Encryption Key to be protected and shared.
     * @param recipientIdentityId The identifier of the recipient Identity.
     * @param recipientPublicKey The public key of the recipient Identity.
     * @param permissions The set of permissions to grant.
     * @param manifestType The type of manifest to create (should be a direct share type).
     * @param customMetadata Optional custom metadata for the manifest.
     * @return The created {@link AccessManifest}.
     * @throws com.ggar.cirrus.caf.common.exception.CryptoOperationException if encryption fails.
     */
    AccessManifest createDirectShareManifest(
            Identifier resourceId,
            SymmetricKey rekToProtect,
            Identifier recipientIdentityId,
            PublicKeyMaterial recipientPublicKey,
            Set<Permission> permissions,
            ManifestType manifestType, // Application provides its concrete ManifestType instance
            Map<String, java.io.Serializable> customMetadata
    );

    /**
     * Creates an AccessManifest for granting access to members of a Group for a given Resource Encryption Key (REK).
     * The REK will be encrypted with the Group's symmetric key.
     *
     * @param resourceId The identifier of the Resource.
     * @param rekToProtect The Resource Encryption Key to be protected and shared.
     * @param groupId The identifier of the recipient Group.
     * @param groupKey The symmetric key of the Group.
     * @param permissions The set of permissions to grant.
     * @param manifestType The type of manifest to create (should be a group share type).
     * @param customMetadata Optional custom metadata for the manifest.
     * @return The created {@link AccessManifest}.
     * @throws com.ggar.cirrus.caf.common.exception.CryptoOperationException if encryption fails.
     */
    AccessManifest createGroupShareManifest(
            Identifier resourceId,
            SymmetricKey rekToProtect,
            Identifier groupId,
            SymmetricKey groupKey, // The key of the group itself
            Set<Permission> permissions,
            ManifestType manifestType,
            Map<String, java.io.Serializable> customMetadata
    );

    /**
     * Creates an AccessManifest for link-based access protected by a password.
     * The REK will be encrypted with a key derived from the provided password.
     *
     * @param resourceId The identifier of the Resource.
     * @param rekToProtect The Resource Encryption Key to be protected and shared.
     * @param linkId A unique identifier for this link.
     * @param password The password to protect the link. Will be used to derive an encryption key.
     * @param permissions The set of permissions to grant.
     * @param manifestType The type of manifest to create (should be a link share type).
     * @param customMetadata Optional custom metadata for the manifest.
     * @return The created {@link AccessManifest}.
     * @throws com.ggar.cirrus.caf.common.exception.CryptoOperationException if key derivation or encryption fails.
     */
    AccessManifest createLinkPasswordManifest(
            Identifier resourceId,
            SymmetricKey rekToProtect,
            Identifier linkId, // Recipient is the link itself
            char[] password,
            Set<Permission> permissions,
            ManifestType manifestType,
            Map<String, java.io.Serializable> customMetadata
    );


    /**
     * Creates an AccessManifest representing an explicit denial of access for a specific Identity or Group.
     *
     * @param resourceId The identifier of the Resource.
     * @param recipientIdentifier The identifier of the Identity or Group to whom access is denied.
     * @param manifestType The type of manifest to create (should be a deny type).
     * @param customMetadata Optional custom metadata for the manifest.
     * @return The created {@link AccessManifest} for denial.
     */
    AccessManifest createDenialManifest(
            Identifier resourceId,
            Identifier recipientIdentifier, // Can be a user or group ID
            ManifestType manifestType, // Application provides its concrete Deny ManifestType instance
            Map<String, java.io.Serializable> customMetadata
    );

    /**
     * Creates an AccessManifest for a server-managed (unprotected by FAC E2EE) resource.
     *
     * @param resourceId The identifier of the Resource.
     * @param manifestType The type of manifest to create (should be a server-managed type).
     * @param serverAccessDetails Application-specific metadata describing how to access the resource
     * (e.g., a URL, storage pointers).
     * @param customMetadata Optional custom metadata for the manifest.
     * @return The created {@link AccessManifest}.
     */
    AccessManifest createServerManagedManifest(
            Identifier resourceId,
            ManifestType manifestType,
            Map<String, java.io.Serializable> serverAccessDetails, // e.g., URL, path
            Map<String, java.io.Serializable> customMetadata
    );

    // Potentially add methods for more complex KEK-wrapping scenarios if they are common patterns
    // or allow the consuming application to construct the CryptoStep list more directly.
}