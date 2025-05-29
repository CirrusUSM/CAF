# Cryptographic Access Framework (FAC) - High-Level Design (v1.1)

## 0. Technological Context (Reference Implementation Preferences)

While the FAC's design aims to be language-agnostic in its core interfaces, the following preferences are noted for a potential reference implementation or initial examples:
* Language: Java 17
* Build Tool: Gradle (with Groovy for build scripts)
* Reactive Programming: Project Reactor
* Dependency Injection/Framework: Spring/Spring Boot

These points do not alter the fundamental API design of FAC but serve as implementation guidance.

## 1. Overview

This document outlines the high-level design for the Cryptographic Access Framework (FAC). FAC aims to provide a reusable,
application-agnostic solution for managing cryptographic access control to Resources.
FAC operates on the assumption that identities are authenticated by the consuming application
before interacting with the framework (as per FAC-RF-FBR-001).

## 2. Core Architectural Principles (Recap)

* Enables Trust Models (FAC provides tools for ZKM, EKM)
* Crypto-Agility
* Decoupling of Layers
* Policy-Driven Access (via Access Manifests)
* Extensible Types

## 3. Modules and APIs

The FAC will be structured into the following primary modules:

### 3.1. fac-common
    * Purpose: Provides common data structures, identifiers, and custom exceptions used across the framework.
    * Key Components:
        * ResourceId, IdentityId, ManifestId, GroupId (Standardized identifier formats)
        * AlgorithmIdentifier (A structure to specify cryptographic algorithms and their essential parameters, e.g., "AES/GCM/NoPadding", curve name for EC, hash for RSA-OAEP. It must be sufficient for the fac-crypto-api implementation to act unambiguously, but without library-specific details.)
        * FacException (Base class for FAC errors, with defined error codes)
        * Common DTOs for inter-module communication if not covered by specific APIs.

### 3.2. fac-crypto-api
    * Purpose: Defines interfaces for all cryptographic operations, allowing for pluggable implementations (FAC-RF-CA-001). This module provides the primitives for key generation (FAC-RF-KM-001, FAC-RF-KM-002) and generic key protection mechanisms (FAC-RF-KM-003).
    * Key Interfaces/Operations (Illustrative):
        * KeyGenerator:
            * generateIdentityKeyPair(spec): IKP
            * generateResourceEncryptionKey(spec): REK
        * AsymmetricCrypter:
            * encrypt(publicKey, data, algorithmIdentifier): Ciphertext
            * decrypt(privateKey, ciphertext, algorithmIdentifier): Plaintext
        * SymmetricCrypter:
            * encrypt(key, data, algorithmIdentifierWithParams): CiphertextWithIV
            * decrypt(key, ciphertextWithIV, algorithmIdentifierWithParams): Plaintext
        * KeyDerivationFunction (KDF):
            * deriveKey(secret, algorithmIdentifierWithParams): DerivedKey
    * Implementation Note: Each operation must handle the algorithm specification clearly via AlgorithmIdentifier and associated parameters, ensuring self-describing cryptography (FAC-RF-CA-002).

### 3.3. fac-manifest-api
    * Purpose: Defines the structure of AccessManifest and CryptoStep, which form the core of the access policies (FAC-RF-AM-001).
    * Key Data Structures:
        * AccessManifest: (Designed for efficient retrieval, see FAC-RF-AM-006)
            * manifestId: string (Unique manifest identifier)
            * resourceId: string (Identifier of the resource it protects, key for indexing)
            * manifestType: string (e.g., "DirectShare", "GroupKey", "PasswordProtected", "RecoveryCode", "DenyUser". FAC may define constants for common types, but the logic associated with custom types belongs to the application (FAC-RF-AM-002). Key for indexing and precedence logic.)
            * recipientMatcher: object (Defines matching criteria, e.g., { type: "identity", id: "userId" }, { type: "group", id: "groupId" }, { type: "passwordProtected" }. Internal fields like id are keys for indexing.)
            * cryptoPipeline: CryptoStep[] (The declarative cryptographic pipeline)
            * encryptedPayload: bytes (The encrypted REK or intermediate key)
            * permissions: string[] (e.g., ["READ", "WRITE"]) (FAC-RF-ADL-003)
            * precedence: number (Optional, can be derived from the type or configured by the application for manifest evaluation FAC-RF-ADL-002)
            * creationTimestamp: date
            * metadata: object (Application-specific, may contain fields for additional indexing)
        * CryptoStep:
            * stepId: string (Unique identifier within the pipeline)
            * operation: string (e.g., "ASYMMETRIC_DECRYPT", "SYMMETRIC_DECRYPT", "KDF_DERIVE_KEY")
            * algorithmIdentifier: object (Specifies the algorithm, like "RSA-OAEP-2048-SHA256", "AES-256-GCM", "Argon2id") (FAC-RF-CA-002)
            * inputSource: { type: "MANIFEST_PAYLOAD" | "PREVIOUS_STEP_OUTPUT" | "CONSTANT", value?: any, stepRef?: string }
            * keySource: { type: "IKP_PRIVATE" | "INPUT_PROVIDER_SECRET" | "PREVIOUS_STEP_OUTPUT_AS_KEY" | "GROUP_KEY_VIA_INPUT_PROVIDER" | "APPLICATION_RESOLVED_KEY", identifier?: string, stepRef?: string, promptHint?: string } (e.g., IKP_PRIVATE from IdentityContext, INPUT_PROVIDER_SECRET by calling InputProvider. APPLICATION_RESOLVED_KEY could be a new type to delegate resolution to an injected KeySourceResolver.)
            * parameters: object (e.g., { iv: bytes, salt: bytes, iterations: number, contextInfo: bytes })
            * outputName: string (Name to reference this step's output)

### 3.4. fac-manifest-engine-core
    * Purpose: Contains the AccessDecisionEngine and related logic for evaluating manifests and executing crypto pipelines (FAC-RF-ADL-001).
    * Key Components:
        * AccessDecisionEngine:
            * evaluateAccess(manifests: AccessManifest[], identityContext: IdentityContext, inputProvider: InputProvider, keySourceResolver?: KeySourceResolver): Promise<AccessDecision> . The keySourceResolver is optional and would allow the application to customize key retrieval for certain keySource.type.
            * The engine executes the manifest matching and pipeline execution logic. The interpretation of ManifestType for precedence or additional business logic can be extended/configured by the consuming application.
        * InputProvider (Interface): (FAC-RF-ADL-001.3)
            * requestSecret(type: string, promptHint?: string, context?: object): Promise<SecretMaterial> (Invoked by the engine when a CryptoStep.keySource is of type INPUT_PROVIDER_SECRET to dynamically fetch passwords, recovery codes, etc., as needed for secret recovery (FAC-RF-SR-001) or other operations.)
        * KeySourceResolver (Optional Interface):
            * resolveKey(keySourceIdentifier: string, identityContext: IdentityContext, manifest?: AccessManifest): Promise<KeyMaterial> (Invoked by the engine if a CryptoStep.keySource.type is APPLICATION_RESOLVED_KEY).
        * IdentityContext (Data Structure):
            * identityId: string
            * attributes: object (e.g., group memberships, roles)
            * availablePrivateKeys: Map<string, PrivateKeyMaterial> (Key: key identifier/alias, Value: actual private key bytes, potentially unlocked)
        * AccessDecision (Data Structure):
            * resourceId: string
            * identityId: string
            * outcome: "GRANTED" | "DENIED" | "REQUIRES_INPUT" | "PIPELINE_STEP_FAILED" (More granular outcome)
            * derivedRek?: bytes (If GRANTED)
            * effectivePermissions?: string[] (Derived from the winning manifest, FAC-RF-ADL-003)
            * winningManifestId?: string
            * failureDetails?: { stepId?: string, errorCode?: string, message?: string } (Details in case of failure)
    * Helper Services:
        * ManifestRekeyService (or similar):
            * rekeyManifestPayload(manifest: AccessManifest, newKeyMaterial: KeyMaterial, oldKeyResolver: (manifest: AccessManifest, identityContext: IdentityContext, inputProvider: InputProvider) => Promise<KeyMaterial>): Promise<AccessManifest> (FAC-RF-AM-004): Helps re-encrypt the manifest's encryptedPayload. The oldKeyResolver could use the InputProvider or IdentityContext to get the old key needed to decrypt the payload before re-encrypting it with newKeyMaterial.
    * Core Logic:
        1. Sort manifests by precedence (FAC-RF-ADL-002), configurable by the application.
        2. Iteratively match manifests against IdentityContext.
        3. For the winning manifest, execute the CryptoStep pipeline (using InputProvider or KeySourceResolver if applicable).
        4. Invoke fac-crypto-api for operations.

### 3.5. fac-manifest-persistence-api
    * Purpose: Defines interfaces for storing and retrieving AccessManifest objects (FAC-RF-AM-003). The consuming application is responsible for implementing this interface to interact with its chosen persistence layer (FAC-RF-FBR-002).
    * Key Interface (ManifestRepository):         * save(manifest: AccessManifest): Promise<void>
        * findByResourceId(resourceId: string): Promise<AccessManifest[]>
        * findById(manifestId: string): Promise<AccessManifest | null>
        * delete(manifestId: string): Promise<void>
        * update(manifest: AccessManifest): Promise<void>
        * query(criteria: object): Promise<AccessManifest[]> (Flexible querying, allowing the application to build complex queries based on indexable manifest fields (FAC-RF-AM-006))

### 3.6. fac-group-management-api (Conceptual)
    * Purpose: Defines interfaces for secure group key management (FAC-RF-SGM-001), allowing for pluggable implementations (FAC-RF-SGM-002).
    * Key Interface (SecureGroupManager):         * createGroup(initialMembers: IdentityContext[]): Promise<GroupContext>
        * addMember(groupContext: GroupContext, newMember: IdentityContext, adminContext?: IdentityContext): Promise<GroupContextWithKeyInfo>
        * removeMember(groupContext: GroupContext, memberToRemove: IdentityId, adminContext?: IdentityContext): Promise<GroupContextWithKeyInfo> (Implies re-keying. FAC-RF-SGM-001.c: Must return information about the old and new key).
        * getGroupKeyEnvelopeForMember(groupContext: GroupContext, memberId: IdentityId): Promise<EncryptedKeyEnvelope> (Provides the group REK wrapped for the member)
    * GroupContext: Contains group ID, current group REK (or its protected form), member list, etc.
    * GroupContextWithKeyInfo: Extends GroupContext to include oldKeyDescriptor and newKeyDescriptor after re-keying operations.
    * Note: The FAC itself might not provide a full implementation of group logic but rather the hooks and expectations for how group shares are represented in manifests. A default implementation (e.g., inspired by MLS, as per FAC-RF-SGM-002) could be offered as a separate, optional module.

## 4. Key Workflows

### 4.1. Protecting a Resource & Creating Manifests (Enveloping)
This workflow describes the "enveloping phase" (FAC-RF-AM-001.2) where a resource's REK is protected.
1. Generate Resource Encryption Key (REK_Resource): Use fac-crypto-api (FAC-RF-KM-002).
2. Encrypt Resource Content: (Responsibility of the consuming application using REK_Resource).
3. For each recipient/access method:
   a.  Define the decryption CryptoStep[] pipeline the recipient will use.
   b.  Perform inverse encryption operations to generate the encryptedPayload (e.g., encrypt REK_Resource with recipient's public key, a group key, or a password-derived key).
   c.  Construct the AccessManifest with manifestType, recipientMatcher, cryptoPipeline, encryptedPayload, and permissions.
   d.  Persist the AccessManifest using fac-manifest-persistence-api.

### 4.2. Accessing a Resource (Decision & Unsealing)
This workflow describes how the AccessDecisionEngine processes manifests to grant or deny access (FAC-RF-ADL-001).
1. Application Gathers Inputs:    * Retrieves all AccessManifest[] for the target ResourceId (using fac-manifest-persistence-api).
   * Constructs IdentityContext for the current (assumed authenticated) identity.
   * Provides an InputProvider implementation.
   * Optionally provides a KeySourceResolver implementation.
2. Invoke FAC Engine: AccessDecisionEngine.evaluateAccess(manifests, identityContext, inputProvider, keySourceResolver).
3. Engine Processing:
   a.  Sorts manifests according to precedence rules (FAC-RF-ADL-002).
   b.  Finds the first manifest matching the IdentityContext.
   c.  If a "Deny" manifest matches first, returns AccessDecision with outcome: "DENIED".
   d.  If a "Grant" manifest matches:
       i.  Executes its cryptoPipeline step-by-step. If a step fails (e.g., incorrect password, crypto error), returns AccessDecision with outcome: "PIPELINE_STEP_FAILED" and failureDetails. If input is required and cannot be obtained, the outcome might be REQUIRES_INPUT or PIPELINE_STEP_FAILED.
       ii. If the pipeline succeeds, the final output is the decrypted Resource Encryption Key (REK).
       iii. Returns AccessDecision with outcome: "GRANTED", derivedRek, and effectivePermissions.
   e.  If no "Grant" manifest matches, returns outcome: "DENIED".

### 4.3. Identity Key Pair (IKP) Management & Recovery
This outlines IKP generation (FAC-RF-KM-001) and how secret recovery (FAC-RF-SR-001) is handled by treating the IKP's private key as a resource.
* IKP Generation: Use fac-crypto-api.generateIdentityKeyPair().
* IKP Private Key Protection: The IKP private key is a critical secret, treated as a "Resource" protected by its own REK (e.g., REK_IKPprivate).
* Manifests for REK_IKPprivate:
  * Enabling ZKM: Manifests to decrypt REK_IKPprivate using a key derived from the user's master password (via InputProvider), or via single-use recovery codes (each recovery code manifest having a CryptoStep that uses InputProvider to obtain the code).
  * Enabling EKM: An additional manifest might exist allowing decryption of REK_IKPprivate via an organizationally controlled mechanism/key.
* Unlocking IKP Private Key: When an operation requires the IKP private key:
  1. Treat the IKP private key as the target resource.
  2. Gather its AccessManifests (for password, recovery codes, etc.).
  3. Call AccessDecisionEngine.evaluateAccess(...) for these manifests.
  4. If GRANTED, the engine returns the decrypted REK_IKPprivate, which is then used to decrypt the actual IKP private key.

## 5. Enabling Trust Models (ZKM vs. EKM)

* The FAC enables the implementation of various trust models, including Zero-Knowledge Mode (ZKM) and Enterprise Key Management (EKM), rather than implementing them directly. It does so through:
  * Flexible Cryptographic Pipelines (CryptoStep): Allow defining how a key (e.g., the IKP private key) is protected and accessed.
  * InputProvider: Allows the application to request secrets directly from the user (crucial for ZKM) or through other mechanisms.
  * KeySourceResolver (Optional): Allows the application to integrate more complex or domain-specific key retrieval logic, potentially supporting diverse EKM scenarios.
  * Multiple Manifests: Different AccessManifests can be created for the same secret (e.g., one for user password access, another for enterprise recovery), allowing different paths to the same key based on policy and context.
* The consuming application is responsible for defining and managing the manifests that correspond to the desired trust model for each Identity or Resource.

## 6. Extensibility Points

* fac-crypto-api implementations: Swap crypto libraries (FAC-RF-CA-001).
* fac-manifest-persistence-api implementations: Connect to different storage backends (FAC-RF-AM-003, FAC-RF-FBR-002).
* ManifestType definitions (FAC-RF-AM-002): Applications define the semantics and business logic for their custom manifest types. FAC focuses on executing the cryptoPipeline.
* SecureGroupManager implementations (FAC-RF-SGM-002): Different group management schemes.
* InputProvider implementations: Customize how dynamic secrets are collected.
* KeySourceResolver implementations (Optional): Customize how specific keys are retrieved for a CryptoStep.
* Manifest Precedence Configuration: The application can influence the evaluation order (FAC-RF-ADL-002).
* Logging Service: FAC can emit structured log events, or a LogService interface implemented by the application can be injected.
* The framework is designed to enable various application-level features like offline mode or federation by providing the core cryptographic and access control primitives (FAC-RF-FBR-003).

## 7. Further Discussion & Design Decisions

* AlgorithmIdentifier Granularity: Reaffirmed. It must be sufficient for the crypto API to act unambiguously (e.g., specifying the full algorithm like "AES/GCM/NoPadding", curve name for EC, or hash and MGF algorithm for RSA-OAEP), but without being tied to specific library internals, ensuring crypto-agility (FAC-RF-CA-002).
* Standard ManifestType Constants Library: Reaffirmed. FAC could provide a set of recommended string constants for common types (e.g., fac.manifest.type.DIRECT_SHARE, fac.manifest.type.GROUP_KEY, fac.manifest.type.PASSWORD_PROTECTED) to foster interoperability and ease precedence configuration, but the business logic tied to these types (beyond pipeline execution) remains the application's responsibility (FAC-RF-AM-002).
* IKP Private Key Unlocking Flow: Reaffirmed. Managed as a standard call to the AccessDecisionEngine, treating the IKP private key as a resource protected by its own manifests, aligning with secret recovery principles (FAC-RF-SR-001).
* Error Handling and Reporting & Logging: Reaffirmed. FAC will define a set of internal, structured error codes within FacException and AccessDecision.failureDetails. For logging, an injectable LogService interface is preferred for integration with the application's logging infrastructure (e.g., SLF4J in a Java context).
* keySource Resolution in CryptoStep:
    * Basic types like IKP_PRIVATE (from IdentityContext.availablePrivateKeys) and PREVIOUS_STEP_OUTPUT_AS_KEY are resolved directly by the engine.
    * INPUT_PROVIDER_SECRET (for passwords, recovery codes, etc.) is resolved via the application-implemented InputProvider interface.
    * New Consideration: For more complex scenarios or greater application flexibility in key retrieval (e.g., externally managed group keys, complex session-derived keys), the optional KeySourceResolver interface is introduced. A new keySource.type like APPLICATION_RESOLVED_KEY would delegate key retrieval to this application-provided implementation.
* Group Re-keying Complexity (FAC-RF-SGM-001.3): Reaffirmed. SecureGroupManager.removeMember() (and addMember if re-keying) must return old/new key descriptors. FAC must provide a ManifestRekeyService helper (rekeyManifestPayload) for re-encrypting individual manifest payloads (FAC-RF-AM-004). The consuming application orchestrates finding all affected manifests and managing the (potentially background) re-keying process.
* Transactional Manifest Operations: Reaffirmed. FAC's APIs (e.g., ManifestRepository.save, ManifestRekeyService.rekeyManifestPayload) operate on individual entities or return new entities. The consuming application is responsible for invoking these within its own database transactions for atomicity when multiple entities are modified.
* Performance Considerations for Manifest Retrieval (FAC-RF-AM-006): Reaffirmed. The AccessManifest structure must include key fields (resourceId, recipientMatcher fields, manifestType) designed for easy indexing by the application's persistence layer to allow efficient candidate manifest retrieval.
* Compatibility with Reference Tech Stack (Java/Spring/Reactor): While FAC's interfaces are generic, reference implementations or examples should demonstrate natural integration with patterns from this stack (e.g., using Mono/Flux for asynchronous operations, Spring beans for FAC services, configuring InputProvider and KeySourceResolver as Spring components).

This high-level design provides a starting point for the FAC's architecture. Each module and component will require further detailed design.