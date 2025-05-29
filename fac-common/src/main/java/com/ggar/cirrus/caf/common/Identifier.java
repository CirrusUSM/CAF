package com.ggar.cirrus.caf.common;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;
import java.util.UUID;

/**
 * Represents a generic, immutable identifier for various entities within the FAC,
 * such as Resources, Identities, Groups, or Manifests.
 * <p>
 * It encapsulates a string value, often a UUID, to ensure uniqueness.
 * This class is designed to be a simple wrapper to provide type safety and clarity
 * when passing identifiers around, rather than using raw strings.
 * </p>
 * <p>
 * For specific entity types, it's recommended to create concrete subclasses or
 * use this class directly with a clear understanding of what the ID represents in context.
 * For example, {@code new Identifier(resourceUUID.toString())} for a resource.
 * </p>
 *
 * @see java.util.UUID
 */
@Getter
@ToString
@EqualsAndHashCode(of = "value") // Only use 'value' for equals and hashCode
public final class Identifier implements Serializable, Comparable<Identifier> {

    private static final long serialVersionUID = 1L;

    private final String value;

    /**
     * Constructs a new Identifier with the given string value.
     * It is recommended that the value be a globally unique identifier, such as a UUID.
     *
     * @param value The string representation of the identifier. Must not be null or empty.
     * @throws IllegalArgumentException if the value is null or empty.
     */
    public Identifier(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Identifier value cannot be null or empty.");
        }
        this.value = value;
    }

    /**
     * Creates a new Identifier with a randomly generated UUID value.
     *
     * @return A new Identifier instance.
     */
    public static Identifier randomIdentifier() {
        return new Identifier(UUID.randomUUID().toString());
    }

    @Override
    public int compareTo(Identifier other) {
        return this.value.compareTo(other.value);
    }
}