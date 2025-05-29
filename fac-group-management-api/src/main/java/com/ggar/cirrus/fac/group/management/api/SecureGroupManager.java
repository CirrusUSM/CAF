package com.ggar.cirrus.fac.group.management.api;

import com.ggar.cirrus.caf.common.FacException;
import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.fac.crypto.api.dto.PublicKeyMaterial;
import com.ggar.cirrus.fac.crypto.api.dto.SymmetricKey;
import com.ggar.cirrus.fac.group.management.api.dto.AddMemberResult;
import com.ggar.cirrus.fac.group.management.api.dto.GroupContext;
import com.ggar.cirrus.fac.group.management.api.dto.GroupMember;
import com.ggar.cirrus.fac.group.management.api.dto.RemoveMemberResult;
import com.ggar.cirrus.fac.manifest.api.AccessManifest;
import com.ggar.cirrus.fac.manifest.api.IdentityContext;


import java.util.Optional;

/**
 * Interface for managing secure cryptographic groups.
 * Implementations are responsible for handling the underlying cryptographic protocols
 * (e.g., inspired by MLS) to ensure efficient and secure key agreement, member addition,
 * and member removal with forward and backward secrecy properties (where applicable
 * for the protocol).
 * <p>
 * The consuming application is typically responsible for persisting the {@link GroupContext}
 * and managing the list of members at an application level. The {@code SecureGroupManager}
 * operates on this context to update cryptographic state.
 * </p>
 */
public interface SecureGroupManager {

    /**
     * Creates a new secure cryptographic group.
     *
     * @param groupId The desired unique identifier for the new group.
     * @param groupName An optional human-readable name for the group.
     * @param initialCreator The {@link GroupMember} information for the identity creating the group,
     * who will be the first member. Their public key is essential.
     * @param initialGroupRek (Optional) A pre-generated symmetric key to be used as the first group REK.
     * If null, the implementation should generate one.
     * @return The initial {@link GroupContext} for the newly created group.
     * @throws FacException if group creation fails.
     */
    GroupContext createGroup(
            Identifier groupId,
            String groupName,
            GroupMember initialCreator,
            Optional<SymmetricKey> initialGroupRek
    ) throws FacException;

    /**
     * Adds a new member to an existing secure group.
     * This operation will typically result in a change to the group's keying material
     * (new epoch, potentially new group REK) to ensure the new member cannot access
     * past messages encrypted with previous group keys (if the protocol supports this aspect of forward secrecy).
     *
     * @param currentGroupContext The current state of the group.
     * @param newMember           The {@link GroupMember} details of the identity to be added,
     * including their public key material.
     * @param actorIdentityContext The context of the identity performing the add operation (must be an authorized member/admin).
     * @return An {@link AddMemberResult} containing the updated group context.
     * @throws FacException if adding the member fails (e.g., actor not authorized, crypto error).
     */
    AddMemberResult addMember(
            GroupContext currentGroupContext,
            GroupMember newMember,
            IdentityContext actorIdentityContext
    ) throws FacException;

    /**
     * Removes a member from an existing secure group.
     * This operation **must** re-key the group to ensure the removed member cannot access
     * future group communications/resources (Forward Secrecy).
     * The result provides information to the application to handle re-keying of existing
     * resources if Backward Secrecy is also desired for data previously shared with the group.
     *
     * @param currentGroupContext The current state of the group.
     * @param memberToRemoveId    The {@link Identifier} of the member to be removed.
     * @param actorIdentityContext The context of the identity performing the remove operation.
     * @return A {@link RemoveMemberResult} containing the updated group context and descriptors
     * for the old and new group keys.
     * @throws FacException if removing the member fails.
     */
    RemoveMemberResult removeMember(
            GroupContext currentGroupContext,
            Identifier memberToRemoveId,
            IdentityContext actorIdentityContext
    ) throws FacException;

    /**
     * Retrieves the group's current Resource Encryption Key (REK), appropriately enveloped
     * (i.e., encrypted) for a specific active member of the group.
     * <p>
     * This is how a member gets the key needed to decrypt resources shared with the group.
     * The "envelope" is effectively an {@link AccessManifest} or the core components of one
     * (encrypted key material + crypto steps for that member to decrypt it).
     * </p>
     *
     * @param groupContext    The current state of the group.
     * @param memberIdentityId The {@link Identifier} of the group member for whom the key is being requested.
     * @param memberPublicKey (Optional) The public key of the member, if needed by the underlying protocol
     * to encrypt the group key specifically for them. Some protocols might derive this
     * from state established when the member joined.
     * @return An {@link Optional} containing an {@link AccessManifest} (or a simpler DTO like
     * {@code EnvelopedGroupKey}) that allows the specified member to decrypt and obtain the
     * current group REK. Returns empty if the identity is not a valid member or the key
     * cannot be provided.
     * @throws FacException if there's an error preparing the key envelope.
     */
    Optional<AccessManifest> getGroupRekEnvelopeForMember(
            GroupContext groupContext,
            Identifier memberIdentityId,
            Optional<PublicKeyMaterial> memberPublicKey
    ) throws FacException;

    // Other potential methods:
    // - updateMemberRoles(GroupContext currentGroupContext, Identifier memberId, Set<String> newRoles, IdentityContext actor)
    // - updateGroupMetadata(GroupContext currentGroupContext, Map<String, Serializable> newMetadata, IdentityContext actor)
    // - getGroupStateForPersistence(GroupContext groupContext): byte[] // If MLS state is opaque
    // - loadGroupFromState(byte[] groupState): GroupContext
}