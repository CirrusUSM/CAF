package com.ggar.cirrus.fac.manifest.api;

import com.ggar.cirrus.caf.common.Identifier;
import com.ggar.cirrus.fac.crypto.api.dto.PrivateKeyMaterial;
import com.ggar.cirrus.fac.crypto.api.dto.SymmetricKey;

import java.io.Serializable;
import java.util.Map;
import java.util.Optional;

/**
 * Interface to be implemented by the consuming application.
 * The {@code AccessDecisionEngine} uses this provider to request dynamic secrets or key material
 * required during the execution of a {@link CryptoStep} pipeline.
 * <p>
 * For example, if a {@link CryptoStepKeySourceType} is {@code IDENTITY_IKP_PRIVATE_KEY},
 * the engine will call {@link #getIdentityPrivateKey(Identifier, String)} to obtain it.
 * If it's {@code INPUT_PROVIDER_SECRET}, it will call {@link #requestSecret(String, String, Map)}.
 * </p>
 */
public interface InputProvider extends Serializable {

    /**
     * Retrieves the primary private key (IKP private key) for a given identity.
     * The implementation is responsible for any necessary unlocking mechanisms
     * (e.g., prompting for a Master Password, biometric authentication).
     *
     * @param identityId The identifier of the identity whose private key is needed.
     * @param keyAlias   An optional alias or hint for the specific IKP if the identity has multiple. Can be null.
     * @return An {@link Optional} containing the {@link PrivateKeyMaterial} if successfully retrieved and unlocked,
     * or an empty Optional if not available or if the user cancels.
     */
    Optional<PrivateKeyMaterial> getIdentityPrivateKey(Identifier identityId, String keyAlias);

    /**
     * Retrieves a symmetric group key for a given group and identity.
     * The implementation is responsible for verifying the identity's membership and
     * providing the appropriate group key.
     *
     * @param identityContext The context of the identity requesting the group key.
     * @param groupId         The identifier of the group whose symmetric key is needed.
     * @param keyVersionHint  An optional hint for a specific version of the group key. Can be null.
     * @return An {@link Optional} containing the {@link SymmetricKey} for the group if the identity
     * is a member and the key is available, or an empty Optional otherwise.
     */
    Optional<SymmetricKey> getGroupSymmetricKey(IdentityContext identityContext, Identifier groupId, String keyVersionHint);

    /**
     * Requests a generic secret from the user or a secure store.
     * This is used for {@link CryptoStepKeySourceType#INPUT_PROVIDER_SECRET}, such as passwords for links
     * or recovery codes. The returned secret is typically then used as input to a key derivation step.
     *
     * @param secretType A string identifying the type of secret being requested (e.g., "LINK_PASSWORD", "RECOVERY_CODE").
     * This helps the provider show an appropriate prompt.
     * @param promptHint An optional hint for the UI to display to the user.
     * @param context    Additional application-specific context that might be needed to retrieve the secret.
     * @return An {@link Optional} containing the secret as a char array (for passwords, to allow zeroization)
     * or byte array. Returns empty if the user cancels or the secret cannot be provided.
     * The caller is responsible for handling the char[] securely.
     */
    Optional<char[]> requestPasswordSecret(String secretType, String promptHint, Map<String, Serializable> context);

    /**
     * Retrieves other types of secret material if passwords are not appropriate.
     *
     * @param secretType A string identifying the type of secret being requested.
     * @param promptHint An optional hint for the UI.
     * @param context    Additional application-specific context.
     * @return An {@link Optional} containing the secret as byte array.
     */
    Optional<byte[]> requestGenericSecret(String secretType, String promptHint, Map<String, Serializable> context);

}