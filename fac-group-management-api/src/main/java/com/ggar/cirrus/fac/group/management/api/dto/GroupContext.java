package com.ggar.cirrus.fac.group.management.api.dto;

import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.fac.crypto.api.dto.SymmetricKey; // Represents the Group REK
import lombok.Builder;
import lombok.Value;
import lombok.With;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Represents the state and metadata of a secure cryptographic group.
 * This object would typically be managed (created, updated, persisted) by the
 * consuming application, with the {@code SecureGroupManager} operating on it
 * to perform cryptographic group operations.
 * <p>
 * The actual group keying material (e.g., MLS tree state, current epoch key)
 * might be opaque to the consuming application and managed internally by the
 * {@code SecureGroupManager} implementation, or parts of it might be exposed here
 * if needed for persistence or distribution. For simplicity, we represent the
 * current effective group REK here.
 * </p>
 */
@Value
@Builder
@With
public class GroupContext implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The unique identifier for this group.
     */
    Identifier groupId;

    /**
     * A human-readable name for the group (optional, for application use).
     */
    String groupName;

    /**
     * The current version or epoch of the group's keying material.
     * This changes whenever members are added or removed.
     */
    long keyEpoch;

    /**
     * The current symmetric Resource Encryption Key (REK) for this group.
     * Resources shared with the group are protected by encrypting their individual REKs
     * with this group REK.
     * This key itself is what needs to be securely distributed to group members.
     * In a full MLS implementation, this might be derived from the tree's root secret.
     */
    SymmetricKey currentGroupRek;

    /**
     * Timestamp of when this group context (and its key epoch) was last updated.
     */
    Instant lastUpdatedAt;

    /**
     * Timestamp of when the group was created.
     */
    Instant createdAt;

    /**
     * (Optional) List of current members. The SecureGroupManager might operate on a more
     * detailed internal representation (like an MLS tree). This list is more for
     * application-level information if needed.
     * For a pure MLS approach, the manager might not need this list explicitly passed in
     * for every operation if it maintains its own state.
     */
    List<GroupMember> members; // Or just member count, or this is managed by the app

    /**
     * Additional application-specific metadata for the group.
     */
    Map<String, Serializable> metadata;
}