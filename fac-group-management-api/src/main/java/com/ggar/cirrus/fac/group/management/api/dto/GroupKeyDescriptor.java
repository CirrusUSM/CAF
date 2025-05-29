package com.ggar.cirrus.fac.group.management.api.dto;

import com.ggar.cirrus.caf.common.Identifier;
import lombok.Builder;
import lombok.Value;

import java.io.Serializable;

/**
 * A descriptor that uniquely identifies a specific version of a group's keying material.
 * This is used, for example, when a group is re-keyed after a member removal,
 * to distinguish between the old (compromised) key and the new key.
 */
@Value
@Builder
public class GroupKeyDescriptor implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The identifier of the group.
     */
    Identifier groupId;

    /**
     * The epoch or version of the keying material.
     */
    long keyEpoch;

    /**
     * (Optional) The algorithm of the group key, if relevant for identification.
     * Typically, the group key itself (SymmetricKey) would contain this.
     */
    String keyAlgorithm;
}