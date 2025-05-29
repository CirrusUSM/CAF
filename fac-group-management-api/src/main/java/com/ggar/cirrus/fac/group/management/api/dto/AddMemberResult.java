package com.ggar.cirrus.fac.group.management.api.dto;

import lombok.Builder;
import lombok.Value;

import java.io.Serializable;

/**
 * Represents the result of an add member operation.
 */
@Value
@Builder
public class AddMemberResult implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The updated group context after the member addition.
     * This will likely have a new keyEpoch and potentially an updated currentGroupRek.
     */
    GroupContext updatedGroupContext;

    /**
     * Indicates if the operation was successful.
     * (Alternatively, exceptions can be used for failures).
     */
    boolean success;

    // Potentially include information about the welcome message or keying material
    // that needs to be sent to the new member, if the SecureGroupManager
    // doesn't handle that distribution directly.
}