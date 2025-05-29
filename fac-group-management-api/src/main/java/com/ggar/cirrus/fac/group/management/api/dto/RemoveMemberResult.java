package com.ggar.cirrus.fac.group.management.api.dto;

import lombok.Builder;
import lombok.Value;

import java.io.Serializable;

/**
 * Represents the result of a remove member operation.
 * Crucially includes descriptors for the old and new group keys to facilitate
 * re-keying of resources by the consuming application.
 */
@Value
@Builder
public class RemoveMemberResult implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The updated group context after the member removal and re-keying.
     * This will have a new keyEpoch and a new currentGroupRek.
     */
    GroupContext updatedGroupContext;

    /**
     * Descriptor for the group keying material that was valid *before* this removal operation.
     * This is the key that is now considered compromised with respect to the removed member.
     * The consuming application uses this to identify resources that need re-keying.
     */
    GroupKeyDescriptor oldKeyDescriptor;

    /**
     * Descriptor for the new group keying material that is valid *after* this removal operation,
     * for the remaining members.
     */
    GroupKeyDescriptor newKeyDescriptor;

    /**
     * Indicates if the operation was successful.
     */
    boolean success;
}