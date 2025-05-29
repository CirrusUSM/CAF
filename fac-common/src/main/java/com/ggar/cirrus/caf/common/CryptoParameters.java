package com.ggar.cirrus.caf.common;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Singular;

import java.io.Serializable;
import java.util.Map;
import java.util.Optional;

/**
 * A data transfer object (DTO) for holding various cryptographic parameters
 * required for specific operations. This class is designed to be flexible
 * and can carry parameters like algorithm names, key lengths, initialization vectors (IVs),
 * salts, iteration counts for KDFs, context information for AEAD ciphers, etc.
 * <p>
 * The parameters are stored in a map, allowing for extensibility.
 * It is immutable.
 * </p>
 * <p>
 * Standardized key names for common parameters should be defined as constants
 * to ensure consistency across the FAC and consuming applications.
 * </p>
 */
@Getter
@EqualsAndHashCode(of = "parameters")
public final class CryptoParameters implements Serializable {

    private static final long serialVersionUID = 1L;

    // Standardized keys for common crypto parameters
    public static final String ALGORITHM_NAME = "algorithmName";
    public static final String KEY_LENGTH_BITS = "keyLengthBits";
    public static final String IV = "initializationVector"; // byte[]
    public static final String SALT = "salt"; // byte[]
    public static final String KDF_ITERATIONS = "kdfIterations"; // Integer
    public static final String AEAD_TAG_LENGTH_BITS = "aeadTagLengthBits"; // Integer
    public static final String AEAD_ASSOCIATED_DATA = "aeadAssociatedData"; // byte[]
    public static final String PQC_SCHEME_OID = "pqcSchemeOid"; // String for Post-Quantum Crypto schemes
    public static final String RSA_OAEP_HASH_ALGORITHM = "rsaOaepHashAlgorithm"; // e.g., "SHA-256"
    public static final String RSA_OAEP_MGF_ALGORITHM = "rsaOaepMgfAlgorithm"; // e.g., "MGF1"
    public static final String RSA_OAEP_MGF_HASH_ALGORITHM = "rsaOaepMgfHashAlgorithm"; // e.g., "SHA-256"
    // Add more as needed

    private final Map<String, Object> parameters;

    /**
     * Private constructor, use the Lombok Builder to create instances.
     * @param parameters The map of parameters.
     */
    @Builder
    private CryptoParameters(@Singular Map<String, Object> parameters) {
        // Lombok's @Singular for Map will ensure the map is unmodifiable upon creation.
        this.parameters = parameters;
    }

    /**
     * Gets a parameter value by its key.
     *
     * @param key The key of the parameter.
     * @return An Optional containing the parameter value if present, or an empty Optional otherwise.
     */
    public Optional<Object> getParameter(String key) {
        return Optional.ofNullable(parameters.get(key));
    }

    /**
     * Gets a parameter value by its key, casting it to the specified type.
     *
     * @param key The key of the parameter.
     * @param type The class of the type to cast to.
     * @param <T> The type of the parameter.
     * @return An Optional containing the typed parameter value if present and of the correct type,
     * or an empty Optional otherwise.
     */
    @SuppressWarnings("unchecked")
    public <T> Optional<T> getParameter(String key, Class<T> type) {
        Object value = parameters.get(key);
        if (type.isInstance(value)) {
            return Optional.of((T) value);
        }
        return Optional.empty();
    }

    /**
     * Gets all parameters as an unmodifiable map.
     * Note: With Lombok @Builder and @Singular, the map is already unmodifiable.
     *
     * @return An unmodifiable map of all parameters.
     */
    public Map<String, Object> getAllParameters() {
        return parameters; // Already unmodifiable due to @Singular
    }

    @Override
    public String toString() {
        // Avoid printing sensitive values like actual IVs or salts in logs.
        // This toString is more for structure debugging.
        return "CryptoParameters{parameterKeys=" + parameters.keySet() + "}";
    }
}