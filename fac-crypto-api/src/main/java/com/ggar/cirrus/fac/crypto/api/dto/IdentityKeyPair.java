package com.ggar.cirrus.fac.crypto.api.dto;

import lombok.Value;
import java.io.Serializable;

/**
 * Represents an immutable asymmetric key pair for an Identity (IKP).
 * Contains both the public and private key material.
 */
@Value
public class IdentityKeyPair implements Serializable {
    private static final long serialVersionUID = 1L;

    PublicKeyMaterial publicKey;
    PrivateKeyMaterial privateKey;
}