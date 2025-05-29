package com.ggar.cirrus.fac.group.management.api.dto;

import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.fac.crypto.api.dto.PublicKeyMaterial;
import lombok.Builder;
import lombok.Value;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * Represents a member within a secure cryptographic group.
 * This DTO typically carries information about the identity and their public key material
 * relevant for group operations.
 */
@Value
@Builder
public class GroupMember implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The unique identifier of the identity that is a member of the group.
     */
    Identifier identityId;

    /**
     * The public key material of the member, used for operations like adding them
     * to the group or encrypting messages/keys for them within the group context.
     * This might be optional if the system can resolve it from the identityId.
     */
    PublicKeyMaterial publicKeyMaterial;

    /**
     * Application-specific roles or permissions of this member within this specific group.
     * Example: "ADMIN", "EDITOR", "VIEWER".
     * The FAC itself might not enforce these roles directly on resources, but provides
     * this metadata for the consuming application.
     */
    Set<String> rolesInGroup;

    /**
     * Timestamp when the member was added to the group.
     */
    Instant joinedAt;

    /**
     * Additional application-specific metadata associated with this group member.
     */
    Map<String, Serializable> metadata;
}