## Cryptographic Access Framework (FAC): Encryption Scheme and Access Policies

Version: 1.0
Date: May 29, 2025

### 1. Core Principles

The FAC is built upon the following core cryptographic and access control principles:

* End-to-End Encryption (E2EE) Focus: The primary goal is to enable consuming applications to protect Resources such
    that only authorized Identities can access their plaintext content. The FAC itself, and the server components
    of the consuming application, should not have access to plaintext Resource Encryption Keys (REKs) or Resource content
    when operating in a Zero-Knowledge Model (ZKM).
* Zero-Knowledge Model (ZKM) Capability: For human Identities, the FAC must support a model where the Identity's
    primary private key (part of their Identity Key Pair - IKP) is protected by a secret known only to that Identity
    (e.g., a Master Password).
* Enterprise Key Management (EKM) Capability: The FAC must also be compatible with scenarios where an organization
    retains a recovery mechanism for an Identity's IKP, as per the consuming application's policy.
* Crypto-Agility: The framework must allow for the use of multiple cryptographic algorithms and be adaptable
    to future cryptographic standards (e.g., Post-Quantum Cryptography) without requiring a full redesign.
* Policy-Driven Access: Access to Resources is determined by explicit rules (Access Manifests) rather than
    implicit application logic.
* Granular Control: The system should allow for fine-grained permissions beyond simple read access.

### 2. Key Hierarchy and Types

The FAC operates with two primary types of keys:

* Identity Key Pair (IKP):
    * An asymmetric key pair (public and private key) unique to each Identity (human user, service account, device).
    * The public key of the IKP is used to encrypt REKs (or intermediate keys) for direct shares to that Identity.
    * The private key of the IKP is used to decrypt these REKs. Its protection is paramount and depends on the
        Identity's trust model (ZKM or EKM).
    * IKPs are also used for digital signatures if the application requires them for integrity or non-repudiation.

* Resource Encryption Key (REK):
    * A strong symmetric key (e.g., AES-256) generated uniquely for each Resource that needs protection.
    * The REK is used to directly encrypt and decrypt the content of the Resource.
    * The REK itself is the secret that Access Manifests are designed to protect and securely distribute.
    * Note: An IKP's private key or a Group Key can also be considered a "Resource" protected by its own REK in abstract terms (e.g., the REK for an IKP private key is derived from a Master Password).

### 3. Access Manifests: The Core of Access Control

An Access Manifest is a declarative metadata object that describes how a specific Identity (or a set of Identities,
e.g., a group) can gain access to a particular Resource Encryption Key (REK).

#### 3.1. Purpose

* To securely "envelope" or "wrap" a REK for one or more recipients.
* To define the exact cryptographic steps required to "unwrap" or decrypt the REK.
* To associate permissions with a specific access grant.
* To allow for multiple, independent access paths to the same REK.

#### 3.2. Structure

An Access Manifest typically contains:

* manifestId: A unique identifier for the manifest.
* resourceId: An identifier for the Resource whose REK this manifest protects.
* manifestType: (Interface) Defines the nature or intent of the manifest (e.g., DirectShareType, GroupKeyType, DenyType). This influences its evaluation precedence.
* recipientMatcher: (Object) Criteria to determine if this manifest applies to a given IdentityContext (e.g., specific Identity ID, group ID, or other conditions).
* cryptoPipeline: (List of CryptoStep objects) An ordered sequence of cryptographic operations that, if successfully executed, will yield the plaintext REK.
* encryptedPayload: (Bytes) The encrypted data that the cryptoPipeline operates on. This typically contains the encrypted REK, potentially wrapped with intermediate keys.
* permissions: (List of Strings) The set of granular permissions granted if this manifest successfully yields the REK (e.g., READ_RESOURCE, WRITE_RESOURCE).
* precedence: (Number) A value indicating the manifest's priority in the access decision process, often derived from its manifestType.
* creationTimestamp: Date of manifest creation.
* metadata: A generic object/map for application-specific extensions or additional context.

#### 3.3. CryptoStep Details

Each CryptoStep in the cryptoPipeline defines a single cryptographic operation:

* stepId: A unique identifier for the step within the pipeline.
* operation: The cryptographic operation to perform (e.g., ASYMMETRIC_DECRYPT, SYMMETRIC_DECRYPT, KEY_DERIVATION).
* algorithmIdentifier: Specifies the algorithm and its parameters (e.g., "RSA-OAEP-SHA256", "AES-256-GCM").
* inputSource: Defines where to get the data for this step's operation (e.g., from encryptedPayload of the manifest, or the output of a PREVIOUS_STEP_OUTPUT).
* keySource: Defines where to get the key for this step's operation (e.g., IKP_PRIVATE of the current Identity, INPUT_PROVIDER_SECRET like a password, or PREVIOUS_STEP_OUTPUT_AS_KEY).
* parameters: Additional cryptographic parameters for the operation (e.g., IV, salt, KDF iterations, context info).
* outputName: (Optional) A name to reference the output of this step if it's used as input or key for a subsequent step. The final step's output is the REK.

### 4. Access Decision Logic

Access to a Resource's REK is determined by the AccessDecisionEngine.

#### 4.1. Inputs to the Engine

1.  List<AccessManifest>: A list of all potentially relevant manifests for the target Resource and requesting Identity. This list is typically pre-fetched by the consuming application (e.g., via a graph query).
2.  IdentityContext: Contains information about the requesting Identity, including their ID, attributes (like group memberships), and any readily available private keys (e.g., an unlocked IKP private key if the user has already authenticated and decrypted it).
3.  InputProvider: (Interface) An object implemented by the consuming application. The engine uses this to request dynamic secrets (like a Master Password, a link password, or a recovery code) from the user if a CryptoStep requires it.
4.  KeySourceResolver: (Interface, Optional) An object implemented by the consuming application to resolve abstract key identifiers in a KeySourceInfo to actual KeyMaterial if not directly available in IdentityContext or from InputProvider.

#### 4.2. Evaluation Process

1.  Filtering (Optional Pre-step): The engine might first filter the provided list of manifests using the recipientMatcher of each manifest against the IdentityContext.
2.  Sorting by Precedence: The remaining manifests are sorted according to their precedence value (derived from manifestType).
3.  Iterative Evaluation: The engine iterates through the sorted manifests:
    a. For the highest-priority manifest, it attempts to execute its cryptoPipeline.
    b. If a CryptoStep requires dynamic input, the engine calls the InputProvider.
    c. If the pipeline executes successfully, yielding the REK, an AccessDecision of "GRANTED" is made. The winning manifest's permissions become the effective permissions.
    d. If the pipeline fails for a manifest (e.g., wrong key, invalid input), the engine proceeds to the next manifest in precedence order.
    e. If an EXPLICIT_DENY manifest is the highest priority applicable manifest, an AccessDecision of "DENIED" is made immediately.
4.  Default Outcome: If no manifest grants access, the default outcome is "DENIED".

#### 4.3. Output: AccessDecision

The engine returns an AccessDecision object containing:
* outcome: "GRANTED", "DENIED", "REQUIRES_INPUT" (if a pipeline is paused waiting for user input), "PIPELINE_STEP_FAILED".
* derivedRek: The plaintext REK (if GRANTED).
* effectivePermissions: The permissions from the winning manifest.
* winningManifestId: The ID of the manifest that resulted in the decision.
* failureDetails: Information if a pipeline step failed.

### 5. Enveloping Resource Encryption Keys (REKs)

The FAC supports flexible REK enveloping using the AccessManifest and CryptoStep pipeline:

* Direct Share (Asymmetric Envelope):
    * The REK is encrypted using the recipient Identity's IKP public key.
    * The cryptoPipeline in the manifest will have one step: decrypt the payload using the recipient's IKP private key.

* Group Share (Symmetric Envelope via Group REK):
    * The Resource's REK is encrypted using a symmetric Group REK.
    * The cryptoPipeline will have one step: decrypt the payload using the Group REK (which the Identity obtains via their membership manifest for the group itself).

* KEK (Key Encryption Key) Wrapping (Asymmetric + Symmetric Envelope):
    * A KEK (symmetric) is generated. The Resource's REK is encrypted with this KEK.
    * The KEK is then encrypted with the recipient Identity's IKP public key.
    * The cryptoPipeline will have two steps:
        1. Decrypt the KEK using the recipient's IKP private key.
        2. Decrypt the Resource's REK using the now-plaintext KEK.

* Password-Protected Link (Symmetric Envelope via Derived Key):
    * The REK is encrypted using a symmetric key derived from a shared password (e.g., via Argon2).
    * The cryptoPipeline will have one step: derive the key from the password (obtained via InputProvider) and use it to decrypt the payload.

The CryptoStep keySource and inputSource fields, along with the ability to chain outputs, allow for these and more complex enveloping schemes to be declaratively defined.

### 6. Policy Enforcement and Granular Permissions

* Decryption as Read Access: Successfully executing a manifest's cryptoPipeline to obtain the REK inherently grants the ability to decrypt and thus "read" the Resource.
* Application-Enforced Permissions: Other permissions (e.g., WRITE_RESOURCE, DELETE_RESOURCE, SHARE_RESOURCE) are listed in the AccessManifest. The FAC provides this information in the AccessDecision. It is the consuming application's responsibility to enforce these higher-level permissions (e.g., by enabling/disabling UI elements or validating API calls).
* Denial Rules: EXPLICIT_DENY manifest types, when evaluated with highest precedence, ensure that specific Identities or groups cannot access a Resource, even if other manifests would grant them access.

### 7. Relationship to Authentication and Application Logic

* Authentication Precedes Authorization: The FAC is an authorization framework. It assumes the IdentityContext passed to it represents an Identity already authenticated by the consuming application (e.g., via SSO, session tokens).
* Application Orchestrates Persistence and Graph Logic: The FAC defines how manifests are structured and evaluated. The consuming application is responsible for:
    * Storing and retrieving manifests (using an implementation of ManifestRepository).
    * Modeling relationships between Identities, Resources, and Groups (e.g., in a graph database).
    * Querying this model to provide the AccessDecisionEngine with the relevant list of candidate manifests.

This scheme provides a flexible, secure, and extensible foundation for managing cryptographic access control.