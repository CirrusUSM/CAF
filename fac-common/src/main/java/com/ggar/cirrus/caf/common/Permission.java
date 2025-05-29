package com.ggar.cirrus.caf.common;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;

/**
 * Represents a specific permission that can be granted or denied for a Resource.
 * Permissions are typically strings and are defined by the consuming application,
 * though the FAC may define some common ones.
 * <p>
 * This class is immutable. Examples could be "READ_RESOURCE", "WRITE_RESOURCE",
 * "DELETE_RESOURCE", "COMMENT_ON_RESOURCE", "SHARE_RESOURCE".
 * </p>
 * <p>
 * It is recommended that consuming applications define their permissions as constants
 * or enums and wrap them in this class for use with the FAC.
 * </p>
 */
@Getter
@ToString
@EqualsAndHashCode(of = "name") // Only use 'name' for equals and hashCode
public final class Permission implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String name;

    /**
     * Constructs a new Permission with the given name.
     *
     * @param name The name of the permission (e.g., "READ_RESOURCE"). Must not be null or empty.
     * @throws IllegalArgumentException if the name is null or empty.
     */
    public Permission(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Permission name cannot be null or empty.");
        }
        this.name = name;
    }

    // Standard FAC Permissions (examples, consuming applications can define more)
    public static final Permission READ_RESOURCE = new Permission("FAC_READ_RESOURCE");
    public static final Permission WRITE_RESOURCE = new Permission("FAC_WRITE_RESOURCE");
    public static final Permission MANAGE_ACCESS = new Permission("FAC_MANAGE_ACCESS");
}