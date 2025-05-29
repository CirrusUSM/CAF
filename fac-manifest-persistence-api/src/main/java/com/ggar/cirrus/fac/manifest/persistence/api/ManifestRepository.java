package com.ggar.cirrus.fac.manifest.persistence.api;

import com.ggar.cirrus.caf.common.FacException;
import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.fac.manifest.api.AccessManifest;
import com.ggar.cirrus.fac.manifest.api.ManifestType; // For potential filtering

import java.util.List;
import java.util.Optional;
import java.util.Map; // For query criteria

/**
 * Interface defining the contract for persisting and retrieving {@link AccessManifest} objects.
 * <p>
 * Implementations of this interface will handle the actual storage mechanism
 * (e.g., Neo4j, DynamoDB, relational database, in-memory store), keeping the
 * core FAC engine agnostic of the persistence technology.
 * </p>
 * <p>
 * Operations defined here should be designed to be composable into larger
 * application-level transactions if required by the consuming application.
 * </p>
 */
public interface ManifestRepository {

    /**
     * Saves a new {@link AccessManifest} or updates an existing one.
     * If the manifest has an ID that already exists, it should be updated; otherwise, it should be created.
     *
     * @param manifest The {@link AccessManifest} to save or update. Must not be null.
     * @return The saved or updated {@link AccessManifest}, potentially with a generated ID or updated timestamps.
     * @throws FacException if an error occurs during persistence (e.g., database error, validation failure).
     */
    AccessManifest save(AccessManifest manifest) throws FacException;

    /**
     * Saves a collection of new {@link AccessManifest}s or updates existing ones.
     * This method should ideally be executed atomically if the underlying persistence store supports it,
     * or the consuming application should wrap this in a transaction.
     *
     * @param manifests A list of {@link AccessManifest}s to save or update. Must not be null or contain nulls.
     * @return A list of the saved or updated {@link AccessManifest}s.
     * @throws FacException if an error occurs during persistence.
     */
    List<AccessManifest> saveAll(List<AccessManifest> manifests) throws FacException;

    /**
     * Finds an {@link AccessManifest} by its unique identifier.
     *
     * @param manifestId The {@link Identifier} of the manifest to retrieve. Must not be null.
     * @return An {@link Optional} containing the {@link AccessManifest} if found, or an empty Optional otherwise.
     * @throws FacException if an error occurs during retrieval.
     */
    Optional<AccessManifest> findById(Identifier manifestId) throws FacException;

    /**
     * Finds all {@link AccessManifest}s associated with a specific Resource identifier.
     * <p>
     * This is a primary method used by the consuming application to gather candidate manifests
     * before passing them to the {@code AccessDecisionEngine}.
     * </p>
     *
     * @param resourceId The {@link Identifier} of the Resource. Must not be null.
     * @return A list of {@link AccessManifest}s associated with the resource.
     * Returns an empty list if no manifests are found.
     * @throws FacException if an error occurs during retrieval.
     */
    List<AccessManifest> findAllByResourceId(Identifier resourceId) throws FacException;

    /**
     * Finds all {@link AccessManifest}s associated with a specific Resource identifier
     * AND a specific recipient identifier (which could be an Identity ID or a Group ID).
     *
     * @param resourceId The {@link Identifier} of the Resource. Must not be null.
     * @param recipientIdentifier The {@link Identifier} of the recipient (Identity or Group). Must not be null.
     * @return A list of {@link AccessManifest}s matching the criteria.
     * Returns an empty list if no manifests are found.
     * @throws FacException if an error occurs during retrieval.
     */
    List<AccessManifest> findAllByResourceIdAndRecipient(Identifier resourceId, Identifier recipientIdentifier) throws FacException;

    /**
     * Finds all {@link AccessManifest}s associated with a specific Resource identifier
     * AND a specific {@link ManifestType}.
     *
     * @param resourceId The {@link Identifier} of the Resource. Must not be null.
     * @param manifestType The {@link ManifestType} to filter by. Must not be null.
     * The comparison might be based on {@link ManifestType#getName()}.
     * @return A list of {@link AccessManifest}s matching the criteria.
     * @throws FacException if an error occurs during retrieval.
     */
    List<AccessManifest> findAllByResourceIdAndType(Identifier resourceId, ManifestType manifestType) throws FacException;


    /**
     * Deletes an {@link AccessManifest} by its unique identifier.
     *
     * @param manifestId The {@link Identifier} of the manifest to delete. Must not be null.
     * @throws FacException if an error occurs during deletion or if the manifest is not found (optional behavior).
     */
    void deleteById(Identifier manifestId) throws FacException;

    /**
     * Deletes all {@link AccessManifest}s associated with a specific Resource identifier.
     * This might be used when a Resource is deleted from the system.
     *
     * @param resourceId The {@link Identifier} of the Resource whose manifests are to be deleted. Must not be null.
     * @throws FacException if an error occurs during deletion.
     */
    void deleteAllByResourceId(Identifier resourceId) throws FacException;

    /**
     * Deletes multiple {@link AccessManifest}s by their unique identifiers.
     * This method should ideally be executed atomically if the underlying persistence store supports it.
     *
     * @param manifestIds A list of {@link Identifier}s of the manifests to delete. Must not be null or contain nulls.
     * @throws FacException if an error occurs during deletion.
     */
    void deleteAllByIds(List<Identifier> manifestIds) throws FacException;

    /**
     * (Optional) Provides a more generic query capability for manifests based on a set of criteria.
     * The structure of the criteria map is implementation-dependent and should be documented
     * by the specific persistence implementation.
     * This is for advanced use cases where the standard findBy methods are insufficient.
     *
     * @param queryCriteria A map representing the query criteria.
     * Keys could be field names, and values the criteria for those fields.
     * @return A list of {@link AccessManifest}s matching the criteria.
     * @throws FacException if an error occurs or the query is unsupported/malformed.
     * @deprecated Consider if this is truly needed or if more specific finders are better.
     * If kept, the contract for criteria needs to be well-defined or flexible.
     */
    @Deprecated
    List<AccessManifest> query(Map<String, Object> queryCriteria) throws FacException;
}