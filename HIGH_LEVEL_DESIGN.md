# Cryptographic Access Framework (FAC) - High-Level Design (v1.1)

## 0. Technological Context (Reference Implementation Preferences)

While the FAC's design aims to be language-agnostic in its core interfaces, the following preferences are noted for a potential reference implementation or initial examples:
* **Language:** Java 17
* **Build Tool:** Gradle (with Groovy for build scripts)
* **Reactive Programming:** Project Reactor
* **Dependency Injection/Framework:** Spring/Spring Boot

These points do not alter the fundamental API design of FAC but serve as implementation guidance.

## 1. Overview

This document outlines the high-level design for the Cryptographic Access Framework (FAC). 
FAC aims to provide a reusable, application-agnostic solution for managing cryptographic access control to Resources.

## 2. Core Architectural Principles (Recap)

* Enables Trust Models (FAC provides tools for ZKM, EKM)
* Crypto-Agility
* Decoupling of Layers
* Policy-Driven Access (via Access Manifests)
* Extensible Types

## 3. Modules and APIs

The FAC will be structured into the following primary modules:

### 3.1. `fac-common`
    * **Purpose:** Provides common data structures, identifiers, and custom exceptions used across the framework.
    * **Key Components:**
        * `ResourceId`, `IdentityId`, `ManifestId`, `GroupId` (Standardized identifier formats)
        * `AlgorithmIdentifier` (A structure to specify cryptographic algorithms and their essential parameters, e.g., "AES/GCM/NoPadding", curve name for EC, hash for RSA-OAEP. It must be sufficient for the `fac-crypto-api` implementation to act unambiguously, but without library-specific details.)
        * `FacException` (Base class for FAC errors, with defined error codes)
        * Common DTOs for inter-module communication if not covered by specific APIs.

### 3.2. `fac-crypto-api`
    * **Purpose:** Defines interfaces for all cryptographic operations, allowing for pluggable implementations.
    * **Key Interfaces/Operations (Illustrative):**
        * `KeyGenerator`:
            * `generateIdentityKeyPair(spec): IKP` (FAC-RF-KM-001)
            * `generateResourceEncryptionKey(spec): REK` (FAC-RF-KM-002)
        * `AsymmetricCrypter`:
            * `encrypt(publicKey, data, algorithmIdentifier): Ciphertext`
            * `decrypt(privateKey, ciphertext, algorithmIdentifier): Plaintext`
        * `SymmetricCrypter`:
            * `encrypt(key, data, algorithmIdentifierWithParams): CiphertextWithIV`
            * `decrypt(key, ciphertextWithIV, algorithmIdentifierWithParams): Plaintext`
        * `KeyDerivationFunction (KDF)`:
            * `deriveKey(secret, algorithmIdentifierWithParams): DerivedKey` (e.g., for passwords FAC-RF-KM-003.3)
    * **Implementation Note:** Each operation must handle the algorithm specification clearly via `AlgorithmIdentifier` and associated parameters.

### 3.3. `fac-manifest-api`
    * **Purpose:** Defines the structure of `AccessManifest` and `CryptoStep`, which form the core of the access policies.
    * **Key Data Structures:**
        * **`AccessManifest`**: (Designed for efficient retrieval, see FAC-RF-AM-006)
            * `manifestId: string` (Unique manifest identifier)
            * `resourceId: string` (Identifier of the resource it protects, **key for indexing**)
            * `manifestType: string` (e.g., "DirectShare", "GroupKey", "PasswordProtected", "RecoveryCode", "DenyUser". FAC may define constants for common types, but the logic associated with custom types belongs to the application. **Key for indexing and precedence logic**.)
            * `recipientMatcher: object` (Defines matching criteria, e.g., `{ type: "identity", id: "userId" }`, `{ type: "group", id: "groupId" }`, `{ type: "passwordProtected" }`. Internal fields like `id` are **keys for indexing**.)
            * `cryptoPipeline: CryptoStep[]` (FAC-RF-AM-001.1)
            * `encryptedPayload: bytes` (The encrypted REK or intermediate key) (FAC-RF-AM-001.2.d)
            * `permissions: string[]` (e.g., ["READ", "WRITE"]) (FAC-RF-ADL-003)
            * `precedence: number` (Optional, can be derived from the type or configured by the application)
            * `creationTimestamp: date`
            * `metadata: object` (Application-specific, may contain fields for additional indexing)
        * **`CryptoStep`**:
            * `stepId: string` (Unique identifier within the pipeline)
            * `operation: string` (e.g., "ASYMMETRIC_DECRYPT", "SYMMETRIC_DECRYPT", "KDF_DERIVE_KEY")
            * `algorithmIdentifier: object` (Specifies the algorithm, like "RSA-OAEP-2048-SHA256", "AES-256-GCM", "Argon2id") (FAC-RF-CA-002)
            * `inputSource: { type: "MANIFEST_PAYLOAD" | "PREVIOUS_STEP_OUTPUT" | "CONSTANT", value?: any, stepRef?: string }`
            * `keySource: { type: "IKP_PRIVATE" | "INPUT_PROVIDER_SECRET" | "PREVIOUS_STEP_OUTPUT_AS_KEY" | "GROUP_KEY_VIA_INPUT_PROVIDER" | "APPLICATION_RESOLVED_KEY", identifier?: string, stepRef?: string, promptHint?: string }` (e.g., `IKP_PRIVATE` from `IdentityContext`, `INPUT_PROVIDER_SECRET` by calling `InputProvider`. `APPLICATION_RESOLVED_KEY` could be a new type to delegate resolution to an injected `KeySourceResolver`.) (FAC-RF-AM-001.3.c)
            * `parameters: object` (e.g., `{ iv: bytes, salt: bytes, iterations: number, contextInfo: bytes }`) (FAC-RF-AM-001.3.d)
            * `outputName: string` (Name to reference this step's output)

### 3.4. `fac-manifest-engine-core`
    * **Purpose:** Contains the `AccessDecisionEngine` and related logic for evaluating manifests and executing crypto pipelines.
    * **Key Components:**
        * **`AccessDecisionEngine`**:
            * `evaluateAccess(manifests: AccessManifest[], identityContext: IdentityContext, inputProvider: InputProvider, keySourceResolver?: KeySourceResolver): Promise<AccessDecision>` (FAC-RF-ADL-001). The `keySourceResolver` is optional and would allow the application to customize key retrieval for certain `keySource.type`.
            * The engine executes the manifest matching and pipeline execution logic. The *interpretation* of `ManifestType` for precedence or additional business logic can be extended/configured by the consuming application.
        * **`InputProvider` (Interface)**: (FAC-RF-ADL-001.3)
            * `requestSecret(type: string, promptHint?: string, context?: object): Promise<SecretMaterial>` (Invoked by the engine when a `CryptoStep.keySource` is of type `INPUT_PROVIDER_SECRET` to dynamically fetch passwords, recovery codes, etc.)
        * **`KeySourceResolver` (Optional Interface)**:
            * `resolveKey(keySourceIdentifier: string, identityContext: IdentityContext, manifest?: AccessManifest): Promise<KeyMaterial>` (Invoked by the engine if a `CryptoStep.keySource.type` is `APPLICATION_RESOLVED_KEY`).
        * **`IdentityContext` (Data Structure)**:
            * `identityId: string`
            * `attributes: object` (e.g., group memberships, roles)
            * `availablePrivateKeys: Map<string, PrivateKeyMaterial>` (Key: key identifier/alias, Value: actual private key bytes, potentially unlocked)
        * **`AccessDecision` (Data Structure)**:
            * `resourceId: string`
            * `identityId: string`
            * `outcome: "GRANTED" | "DENIED" | "REQUIRES_INPUT" | "PIPELINE_STEP_FAILED"` (More granular outcome)
            * `derivedRek?: bytes` (If GRANTED)
            * `effectivePermissions?: string[]`
            * `winningManifestId?: string`
            * `failureDetails?: { stepId?: string, errorCode?: string, message?: string }` (Details in case of failure)
    * **Helper Services:**
        * `ManifestRekeyService` (or similar):
            * `rekeyManifestPayload(manifest: AccessManifest, newKeyMaterial: KeyMaterial, oldKeyResolver: (manifest: AccessManifest, identityContext: IdentityContext, inputProvider: InputProvider) => Promise<KeyMaterial>): Promise<AccessManifest>` (FAC-RF-AM-004): Helps re-encrypt the manifest's `encryptedPayload`. The `oldKeyResolver` could use the `InputProvider` or `IdentityContext` to get the old key needed to decrypt the payload before re-encrypting it with `newKeyMaterial`.
    * **Core Logic:**
        1. Sort manifests by precedence (FAC-RF-ADL-002), configurable by the application.
        2. Iteratively match manifests against `IdentityContext`.
        3. For the winning manifest, execute the `CryptoStep` pipeline (using `InputProvider` or `KeySourceResolver` if applicable).
        4. Invoke `fac-crypto-api` for operations.

### 3.5. `fac-manifest-persistence-api`
    * **Purpose:** Defines interfaces for storing and retrieving `AccessManifest` objects.
    * **Key Interface (`ManifestRepository`):** (FAC-RF-AM-003)
        * `save(manifest: AccessManifest): Promise<void>`
        * `findByResourceId(resourceId: string): Promise<AccessManifest[]>`
        * `findById(manifestId: string): Promise<AccessManifest | null>`
        * `delete(manifestId: string): Promise<void>`
        * `update(manifest: AccessManifest): Promise<void>`
        * `query(criteria: object): Promise<AccessManifest[]>` (Flexible querying, allowing the application to build complex queries based on indexable manifest fields)

### 3.6. `fac-group-management-api` (Conceptual)
    * **Purpose:** Defines interfaces for secure group key management.
    * **Key Interface (`SecureGroupManager`):** (FAC-RF-SGM-001)
        * `createGroup(initialMembers: IdentityContext[]): Promise<GroupContext>`
        * `addMember(groupContext: GroupContext, newMember: IdentityContext, adminContext?: IdentityContext): Promise<GroupContextWithKeyInfo>`
        * `removeMember(groupContext: GroupContext, memberToRemove: IdentityId, adminContext?: IdentityContext): Promise<GroupContextWithKeyInfo>` (Implies re-keying. FAC-RF-SGM-001.c: Must return information about the old and new key).
        * `getGroupKeyEnvelopeForMember(groupContext: GroupContext, memberId: IdentityId): Promise<EncryptedKeyEnvelope>` (Provides the group REK wrapped for the member)
    * **`GroupContext`**: Contains group ID, current group REK (or its protected form), member list, etc.
    * **`GroupContextWithKeyInfo`**: Extends `GroupContext` to include `oldKeyDescriptor` and `newKeyDescriptor` after re-keying operations.
    * **Note:** The FAC itself might not provide a full implementation of group logic but rather the hooks and expectations for how group shares are represented in manifests.

## 4. Key Workflows

### 4.1. Protecting a Resource & Creating Manifests (Enveloping)
(No significant changes from v1, logic remains valid)

### 4.2. Accessing a Resource (Decision & Unsealing)
(Adapted to reflect the more granular `AccessDecision` and optional `KeySourceResolver`)
1. **Application Gathers Inputs:** `AccessManifest[]`, `IdentityContext`, `InputProvider`, optionally `KeySourceResolver`.
2. **Invoke FAC Engine:** `AccessDecisionEngine.evaluateAccess(manifests, identityContext, inputProvider, keySourceResolver)`.
3. **Engine Processing:**
   ...

### 4.3. Identity Key Pair (IKP) Management & Recovery
(Text corrected, logic maintained)
...

## 5. Enabling Trust Models (ZKM vs. EKM)

* The FAC *enables* the implementation of various trust models, including ZKM and EKM, rather than implementing them directly. It does so through:
  * **Flexible Cryptographic Pipelines (`CryptoStep`):** Allow defining how a key is protected and accessed.
  * **`InputProvider`:** Allows the application to request secrets directly from the user (for ZKM) or through other mechanisms.
  * **`KeySourceResolver` (Optional):** Allows the application to integrate more complex or domain-specific key retrieval logic.
  * **Multiple Manifests:** Different `AccessManifests` can be created for the same secret.
* The consuming application is responsible for defining and managing the manifests that correspond to the desired trust model.

## 6. Extensibility Points

* **`fac-crypto-api` implementations:** Swap crypto libraries.
* **`fac-manifest-persistence-api` implementations:** Connect to different storage backends.
* **`ManifestType` definitions (FAC-RF-AM-002):** Applications define the semantics and business logic for their custom manifest types.
* **`SecureGroupManager` implementations (FAC-RF-SGM-002):** Different group management schemes.
* **`InputProvider` implementations:** Customize how dynamic secrets are collected.
* **`KeySourceResolver` implementations (Optional):** Customize how specific keys are retrieved for a `CryptoStep`.
* **Manifest Precedence Configuration:** The application can influence the evaluation order.
* **Logging Service:** FAC can emit structured log events, or a `LogService` interface implemented by the application can be injected.

## 7. Further Discussion & Design Decisions

* **`AlgorithmIdentifier` Granularity:** Reaffirmed. It must be sufficient for the crypto API to act unambiguously but without being tied to specific library internals.
* **Standard `ManifestType` Constants Library:** Reaffirmed. FAC could provide a set of recommended string constants to foster interoperability, but the business logic remains the application's responsibility.
* **IKP Private Key Unlocking Flow:** Reaffirmed. Managed as a standard call to the `AccessDecisionEngine`, treating the IKP private key as a resource protected by its own manifests.
* **Error Handling and Reporting & Logging:** Reaffirmed. FAC will define a set of internal, structured error codes. For logging, an injectable `LogService` interface is the preferred approach for integration with the application's logging infrastructure (e.g., SLF4J in a Java context).
* **`keySource` Resolution in `CryptoStep`:**
    * Basic types are resolved directly by the engine.
    * `INPUT_PROVIDER_SECRET` is resolved via the `InputProvider` interface.
    * **New Consideration:** For more complex scenarios, the optional `KeySourceResolver` interface is introduced. A new `keySource.type` like `APPLICATION_RESOLVED_KEY` would delegate key retrieval to this application-provided implementation.
* **Group Re-keying Complexity (FAC-RF-SGM-001.3):** Reaffirmed. The `SecureGroupManager` must return old/new key information. FAC must provide a `ManifestRekeyService` helper. The large-scale orchestration is the application's responsibility.
* **Transactional Manifest Operations:** Reaffirmed. FAC's APIs operate on single entities, allowing the consuming application to wrap multiple calls within its own database transactions for atomicity.
* **Performance Considerations for Manifest Retrieval (FAC-RF-AM-006):** Reaffirmed. The `AccessManifest` design must include easily indexable key fields.
* **Compatibility with Reference Tech Stack (Java/Spring/Reactor):** While FAC's interfaces are generic, reference implementations should integrate naturally with patterns from this stack (e.g., using `Mono`/`Flux`, Spring beans, etc.).

This high-level design provides a starting point for the FAC's architecture. Each module and component will require further detailed design.
