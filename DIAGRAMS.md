# FAC - UML Diagrams (Conceptual)
 
This document contains conceptual UML diagrams for the Cryptographic Access Framework (FAC) to visualize its core components and interactions.
 
## 1. Simplified Class Diagram
 
This diagram focuses on the main classes/interfaces and their primary relationships, incorporating detailed feedback.
 
```mermaid
classDiagram
    direction LR

    class AccessDecisionEngine {
        +evaluateAccess(manifests: List~AccessManifest~, context: IdentityContext, provider: InputProvider, resolver: KeySourceResolver) AccessDecision
    }

    class AccessManifest {
        +manifestId: string
        +resourceId: string
        +manifestType: ManifestType
        +recipientMatcher: RecipientMatcher
        +cryptoPipeline: List~CryptoStep~
        +encryptedPayload: Map~string,bytes~
        +permissions: List~string~
        +creationTimestamp: date
    }

    class CryptoStep {
        +stepId: string
        +operation: string
        +algorithmIdentifier: AlgorithmIdentifierInfo
        +inputSource: InputSourceInfo
        +keySource: KeySourceInfo
        +parameters: CryptoStepParams
        +outputName: string
    }
    
    class AccessDecision {
        +outcome: string
        +derivedRek: SymmetricKey
        +effectivePermissions: List~string~
        +winningManifestId: string
        +failureDetails: FailureDetailsInfo 
    }

    class IdentityContext {
        +identityId: string
        +attributes: IdentityAttributes 
        +availablePrivateKeys: Map~string,PrivateKeyMaterial~
    }

    class InputSourceInfo {
        +type: string // e.g., "MANIFEST_PAYLOAD", "PREVIOUS_STEP_OUTPUT"
        +payloadKey: string // optional, for "MANIFEST_PAYLOAD" type
        +stepRef: string // optional, for "PREVIOUS_STEP_OUTPUT" type
    }

    class IKP {
      +publicKey: KeyMaterial
      +privateKey: PrivateKeyMaterial
    }

    class KeyMaterial
    <<interface>> KeyMaterial
    class SecretMaterial
    class PrivateKeyMaterial
    PrivateKeyMaterial --|> KeyMaterial
    class SymmetricKey
    SymmetricKey --|> KeyMaterial
    class DerivedKey
    DerivedKey --|> SymmetricKey
    class Plaintext
    class Ciphertext
    class CiphertextWithIV


    namespace Contracts {
        class ManifestType {
            <<interface>> ManifestType
            +getName(): string
            +getPrecedence(): number
        }
        class ManifestRepository {
            <<interface>> ManifestRepository
            +findByResourceId(resourceId: string) List~AccessManifest~
            // +save(manifest: AccessManifest) void // Save operation moved to application layer
        }
        class InputProvider {
            <<interface>> InputProvider
            +requestSecret(type: string, promptHint: string, context: object) SecretMaterial
        }
        class CryptoAPI {
            <<interface>> CryptoAPI
            +generateIdentityKeyPair(spec: AlgorithmIdentifierInfo) IKP
            +generateResourceEncryptionKey(spec: AlgorithmIdentifierInfo) SymmetricKey
            +encrypt(publicKey: KeyMaterial, data: bytes, params: CryptoStepParams) Ciphertext
            +decrypt(privateKey: PrivateKeyMaterial, ciphertext: Ciphertext, params: CryptoStepParams) Plaintext
            +encryptSymmetric(key: SymmetricKey, data: bytes, params: CryptoStepParams) CiphertextWithIV
            +decryptSymmetric(key: SymmetricKey, ciphertextWithIV: CiphertextWithIV, params: CryptoStepParams) Plaintext
            +deriveKey(secret: SecretMaterial, kdfParams: CryptoStepParams) DerivedKey
        }
        class KeySourceResolver {
            <<interface>> KeySourceResolver
            +resolveKey(keySourceIdentifier: string, identityContext: IdentityContext, manifest: AccessManifest) KeyMaterial
        }
    }

    AccessDecisionEngine --|> InputProvider : uses
    AccessDecisionEngine --|> CryptoAPI : uses
    AccessDecisionEngine --|> KeySourceResolver : uses

    AccessDecisionEngine ..> AccessManifest : processes
    AccessDecisionEngine ..> IdentityContext : uses
    AccessDecisionEngine ..> AccessDecision : returns

    AccessManifest "1" *-- "0..*" CryptoStep : contains
    AccessManifest "1" *-- "1" ManifestType

    class RecipientMatcher
    class AlgorithmIdentifierInfo
    class KeySourceInfo
    class CryptoStepParams
    class FailureDetailsInfo
    class IdentityAttributes

    AccessManifest *-- RecipientMatcher
    AccessDecision *-- FailureDetailsInfo
    IdentityContext *-- IdentityAttributes
    CryptoStep *-- AlgorithmIdentifierInfo
    CryptoStep *-- InputSourceInfo
    CryptoStep *-- KeySourceInfo
    CryptoStep *-- CryptoStepParams

```
 
## 2. Sequence Diagram: `evaluateAccess` Flow (Password-Protected Example)
 
**Description:** This diagram details the collaboration for accessing a resource protected by a password. The `AccessDecisionEngine` processes a manifest of a type like "PasswordProtected". The key for decryption is derived from a password obtained via the `InputProvider`.
**Use Case:** A user attempts to access a file or secret that they (or someone else) previously protected with a password. The user will be prompted for this password during the access attempt.
 
```mermaid
sequenceDiagram
    participant App as Consuming Application
    participant Engine as AccessDecisionEngine
    participant Provider as Contracts.InputProvider
    participant Crypto as Contracts.CryptoAPI
    participant Resolver as Contracts.KeySourceResolver

    Note over App: 1. Application is responsible for fetching relevant manifests (e.g., via ManifestRepository).
    App->>+Engine: evaluateAccess(manifests, context, provider, resolver)
    
    Engine->>Engine: 2. Sort manifests based on ManifestType precedence.
    
    loop 3. For each manifest (candidate)
        Engine->>Engine: Does manifest.recipientMatcher match IdentityContext? (Logic internal to Engine)
    end

    Note over Engine: 4. Winning manifest found (e.g., type 'PasswordProtected'). Start processing its cryptoPipeline.
    
    loop 5. For each CryptoStep in pipeline (A pipeline can have multiple steps, each potentially interacting with Provider, Crypto, or Resolver)
        alt keySource.type is INPUT_PROVIDER_SECRET
            Note over Engine: Example: Step requires password for KDF.
            Engine->>+Provider: requestSecret(keySource.type, keySource.promptHint, stepContext)
            Provider-->>-Engine: secretMaterial (password)
        else keySource.type is APPLICATION_RESOLVED_KEY and resolver is not null
            Note over Engine: Example: Step requires key from an external KMS via KeySourceResolver. (This path is not taken in the current password-protected example).
            Engine->>+Resolver: resolveKey(keySource.identifier, context, currentManifest)
            Resolver-->>-Engine: resolvedKeyMaterial
        else keySource.type is IKP_PRIVATE
             Note over Engine: Step requires IKP_PRIVATE from IdentityContext.
             Engine->>Engine: getKeyFromContext(context, keySource.identifier)
        else keySource.type is PREVIOUS_STEP_OUTPUT
             Note over Engine: Step uses output from a previous step as key.
             Engine->>Engine: getOutputFromPreviousStep(keySource.stepRef)
        end
        
        alt operation is KDF_DERIVE_KEY
            Engine->>+Crypto: deriveKey(secretMaterial, step.algorithmIdentifier, step.parameters)
            Crypto-->>-Engine: derivedKey
            Engine->>Engine: storeOutput(step.outputName, derivedKey)
        else operation is SYMMETRIC_DECRYPT
            Engine->>+Crypto: decryptSymmetric(step.inputSourceData, keyForDecryption, step.algorithmIdentifier, step.parameters)
            Crypto-->>-Engine: plaintextData
            Engine->>Engine: storeOutput(step.outputName, plaintextData)
        else operation is ASYMMETRIC_DECRYPT
            Engine->>+Crypto: decrypt(step.inputSourceData, keyForDecryption, step.algorithmIdentifier, step.parameters)
            Crypto-->>-Engine: plaintextData
            Engine->>Engine: storeOutput(step.outputName, plaintextData)
        end
    end
    
    Note over Engine: 6. Pipeline executed successfully. Final output is the derived REK (SymmetricKey). (For simplicity, failure paths are not detailed in this specific diagram but are crucial for a complete model and would result in AccessDecision with outcome like PIPELINE_STEP_FAILED).
    Engine-->>-App: AccessDecision(outcome="GRANTED", derivedRek=finalPipelineOutput)
```
 
## 3. Sequence Diagram: Manifest Creation (Enveloping/Write Path)
 
**Description:** This diagram illustrates the "inverse operation" or "enveloping phase" of creating an `AccessManifest` to grant a specific type of access to a resource (e.g., direct share using a recipient's public key). It assumes a helper service or component within the consuming application, or a dedicated FAC utility module (e.g., `AccessManifestFactory`), orchestrates this process. The application remains responsible for persisting the created manifest.
**Use Case:** An application user wants to share a file with another user ("Bob"). The application needs to create an `AccessManifest` that encrypts the file's REK with Bob's public key and defines the decryption steps Bob's client will perform.
 
```mermaid
sequenceDiagram
    participant App as Consuming Application
    participant ManifestFactory as AccessManifestFactory (Helper/Utility)
    participant Crypto as Contracts.CryptoAPI
    participant AppRepo as ApplicationManifestRepository (App's implementation of Contracts.ManifestRepository)
    participant ResTypeProvider as ManifestTypeProvider (App's way to get ManifestType instances)

    App->>+ManifestFactory: createDirectShareManifest(resourceId, recipientPublicKeyMaterial, rekToProtect, permissions)
    Note over ManifestFactory: rekToProtect is the SymmetricKey of the resource.

    Note over ManifestFactory: Define CryptoStep pipeline for recipient (e.g., ASYMMETRIC_DECRYPT with recipient's private key).
    ManifestFactory->>ManifestFactory: defineDecryptionPipelineForRecipient()
    ManifestFactory-->>ManifestFactory: decryptionPipeline : List~CryptoStep~

    ManifestFactory->>+Crypto: encrypt(recipientPublicKeyMaterial, rekToProtect.getBytes(), encryptParams)
    Crypto-->>-ManifestFactory: encryptedRekBytes : Ciphertext

    ManifestFactory->>+ResTypeProvider: getManifestType("DirectShare") 
    ResTypeProvider-->>-ManifestFactory: directShareManifestType : ManifestType

    ManifestFactory->>ManifestFactory: assembleAccessManifest(manifestId, resourceId, directShareManifestType, recipientMatcherForRecipient, decryptionPipeline, {"mainKey": encryptedRekBytes}, permissions)
    ManifestFactory-->>App: newAccessManifest : AccessManifest

    Note over App: Application is responsible for persisting the newAccessManifest.
    App->>+AppRepo: save(newAccessManifest) 
    AppRepo-->>-App: saveConfirmation

```
 
## 4. Component Diagram (High-Level Architecture)
 
**Description:** This diagram shows the major conceptual modules of the FAC and their primary dependencies. "Impl" modules represent potential concrete implementations that a consuming application might provide or use.
**Objective:** To visually represent the modular and layered structure of the FAC, highlighting the separation of concerns (API, core logic, implementation).
 
```mermaid
C4Context
    [fac-common] <<Library>>
    [fac-crypto-api] <<Library>>
    [fac-manifest-api] <<Library>>
    [fac-manifest-engine-core] <<Library>>

    [fac-crypto-impl-bouncycastle] <<Example Implementation>>
    [fac-manifest-persistence-api] <<Library>> // Interface defined by FAC
    [app-manifest-persistence-impl] <<Application Implementation>> // App implements persistence
    [fac-group-management-api] <<Library>> // Optional module
    [fac-group-management-impl-example] <<Example Implementation>> // Optional

    [Consuming Application] <<Application>>

    [fac-manifest-engine-core] --> [fac-manifest-api]
    [fac-manifest-engine-core] --> [fac-crypto-api]
    [fac-manifest-engine-core] --> [fac-common]

    [fac-manifest-api] --> [fac-common]
    [fac-crypto-api] --> [fac-common]

    [fac-crypto-impl-bouncycastle] ..|> [fac-crypto-api] : implements
    [app-manifest-persistence-impl] ..|> [fac-manifest-persistence-api] : implements
    [fac-manifest-persistence-api] --> [fac-manifest-api] // Persistence API needs to know about AccessManifest structure

    [fac-group-management-api] --> [fac-common]
    [fac-group-management-api] --> [fac-crypto-api] // For group key operations
    [fac-group-management-api] --> [fac-manifest-api] // For creating group key envelopes/manifests
    [fac-group-management-impl-example] ..|> [fac-group-management-api] : implements

    [Consuming Application] --> [fac-manifest-engine-core]
    [Consuming Application] --> [fac-manifest-persistence-api] // App uses this interface, provides impl
    [Consuming Application] --> [fac-crypto-api] // App might use crypto primitives directly
    [Consuming Application] --> [fac-group-management-api] // App uses group management

```
 
## 5. Sequence Diagram: `evaluateAccess` - Group Key Scenario
 
**Description:** This diagram illustrates how the `AccessDecisionEngine` evaluates access when the winning manifest is of a type like `GroupKeyType`. The group's symmetric key is required to decrypt the manifest's payload, which in turn contains the resource's REK (encrypted with the group key).
**Use Case:** A user attempts to access a resource shared with a group they are a member of. The FAC needs to obtain the group's symmetric key to ultimately decrypt the resource's REK. This key might be fetched via `InputProvider` (e.g., if it needs to be unlocked per session) or `KeySourceResolver` (for more complex group key management).
 
```mermaid
sequenceDiagram
    participant App as Consuming Application
    participant Engine as AccessDecisionEngine
    participant Provider as Contracts.InputProvider
    participant Resolver as Contracts.KeySourceResolver
    participant Crypto as Contracts.CryptoAPI

    App->>+Engine: evaluateAccess(manifests, context, provider, resolver)
    Engine->>Engine: Sort manifests Winning manifest is 'GroupKeyType' for 'group-finance'.
    
    Note over Engine: Pipeline: Step 1 (SYMMETRIC_DECRYPT) uses group key to get resource REK.
    Note over Engine: CryptoStep.keySource specifies how to get 'group-finance' key.

    alt keySource.type is INPUT_PROVIDER_SECRET (e.g., group key needs unlocking)
        Engine->>+Provider: requestSecret("groupKey", "group-finance-key-prompt", context)
        Provider-->>-Engine: groupSymmetricKeyMaterial : SecretMaterial
        Engine->>Engine: groupKeyToUse = groupSymmetricKeyMaterial
    else keySource.type is APPLICATION_RESOLVED_KEY (e.g., complex group key lookup)
        Engine->>+Resolver: resolveKey("group:group-finance", context, winningManifest)
        Resolver-->>-Engine: groupSymmetricKey : KeyMaterial
        Engine->>Engine: groupKeyToUse = groupSymmetricKey
    end

    Note over Engine: CryptoStep.inputSource points to manifest.encryptedPayload["resourceRekEnvelope"]
    Engine->>+Crypto: decryptSymmetric(manifest.encryptedPayload["resourceRekEnvelope"], groupKeyToUse, step.algorithmIdentifier, step.parameters)
    Crypto-->>-Engine: resourceRek : SymmetricKey
    
    Engine-->>-App: AccessDecision(outcome="GRANTED", derivedRek=resourceRek)
```
 
## 6. Sequence Diagram: `evaluateAccess` - KEK Wrapping Scenario
 
**Description:** This diagram shows a multi-step cryptographic pipeline where a Key Encryption Key (KEK) is used to wrap the final Resource Encryption Key (REK). First, the KEK is decrypted (e.g., using the user's IKP private key), and then the plaintext KEK is used as the key in a subsequent step to decrypt the REK. This illustrates the `PREVIOUS_STEP_OUTPUT_AS_KEY` mechanism.
**Use Case:** A resource's REK is protected by a KEK for an additional layer of security or for specific key management reasons. The KEK itself is protected by the user's asymmetric key pair.
 
```mermaid
sequenceDiagram
    participant App as Consuming Application
    participant Engine as AccessDecisionEngine
    participant Crypto as Contracts.CryptoAPI

    App->>+Engine: evaluateAccess(manifests, context, provider, resolver)
    Engine->>Engine: Sort manifests Winning manifest has a 2-step pipeline.

    Note over Engine: --- Pipeline Step 1: Decrypt KEK ---
    Note over Engine: CryptoStep1: operation=ASYMMETRIC_DECRYPT, keySource.type=IKP_PRIVATE, inputSource.payloadKey="encryptedKEK", outputName="plaintextKEK"
    Engine->>Engine: Get IKP_PRIVATE from context.availablePrivateKeys
    Engine->>+Crypto: decrypt(manifest.encryptedPayload["encryptedKEK"], ikpPrivateKey, step1.algorithmIdentifier, step1.parameters)
    Crypto-->>-Engine: decryptedKekBytes : Plaintext
    Engine->>Engine: storeOutput("plaintextKEK", decryptedKekBytes as SymmetricKey)

    Note over Engine: --- Pipeline Step 2: Decrypt REK using KEK ---
    Note over Engine: CryptoStep2: operation=SYMMETRIC_DECRYPT, keySource.type=PREVIOUS_STEP_OUTPUT_AS_KEY, keySource.stepRef="plaintextKEK", inputSource.payloadKey="encryptedREK"
    Engine->>Engine: Get key "plaintextKEK" from previous step's output
    Engine->>+Crypto: decryptSymmetric(manifest.encryptedPayload["encryptedREK"], plaintextKEK, step2.algorithmIdentifier, step2.parameters)
    Crypto-->>-Engine: finalResourceRek : SymmetricKey
    
    Engine-->>-App: AccessDecision(outcome="GRANTED", derivedRek=finalResourceRek)
```
 
## 7. Sequence Diagram: `evaluateAccess` - Explicit Deny Scenario
 
**Description:** This diagram illustrates how an `AccessManifest` of a type signifying explicit denial (e.g., `DenyUserType`, `DenyGroupType`) with high precedence short-circuits the evaluation process. If such a manifest matches the user, access is immediately denied without processing further manifests or cryptographic pipelines.
**Use Case:** An administrator explicitly revokes a user's or group's access to a specific resource. This denial must take precedence over any existing grants.
 
```mermaid
sequenceDiagram
    participant App as Consuming Application
    participant Engine as AccessDecisionEngine
    participant DenyType as Contracts.ManifestType

    App->>+Engine: evaluateAccess(manifestsIncludingDeny, context, provider, resolver)
    
    Engine->>DenyType: manifest.manifestType.getPrecedence() // (Conceptual: Engine checks precedence)
    DenyType-->>Engine: highestPrecedenceValue

    Engine->>Engine: Sort manifests DenyManifest (for current user/group) is now first due to high precedence.
    
    Note over Engine: Evaluating DenyManifest.
    Engine->>Engine: Does DenyManifest.recipientMatcher match IdentityContext? -> Yes
    
    Note over Engine: DenyManifest matches and its type indicates denial. Access is denied immediately.
    Engine-->>-App: AccessDecision(outcome="DENIED", winningManifestId=DenyManifest.id, failureDetails={message:"Explicitly denied by policy."})

```
