# Cryptographic Access Framework (FAC) - Diseño de Alto Nivel (v1.1)

## 0. Contexto Tecnológico (Preferencias de Implementación de Referencia)

Si bien el diseño de FAC busca ser agnóstico al lenguaje en sus interfaces principales, se toma nota de las siguientes preferencias para una posible implementación de referencia o para los ejemplos iniciales:
* Lenguaje: Java 17
* Construcción: Gradle (con Groovy para scripts de build)
* Programación Reactiva: Project Reactor
* Inyección de Dependencias/Framework: Spring/Spring Boot

Estos puntos no alteran el diseño de las API fundamentales del FAC, pero sirven de guía para la concreción.

## 1. Visión General

Este documento describe el diseño de alto nivel para el Cryptographic Access Framework (FAC),
basado en los requisitos funcionales (v1.6) y el feedback recibido. FAC tiene como objetivo proporcionar una solución reutilizable,
agnóstica a la aplicación, para gestionar el control de acceso criptográfico a Recursos.

## 2. Principios Arquitectónicos Clave (Recordatorio)

* Modelos de Confianza Habilitados (FAC provee herramientas para ZKM, EKM)
* Agilidad Criptográfica
* Desacoplamiento de Capas
* Acceso Dirigido por Políticas (mediante Access Manifests)
* Tipos Extensibles

## 3. Módulos y APIs

El FAC se estructurará en los siguientes módulos primarios:

### 3.1. fac-common
    * Propósito: Proporciona estructuras de datos comunes, identificadores y excepciones personalizadas utilizadas en todo el framework.
    * Componentes Clave:
        * ResourceId, IdentityId, ManifestId, GroupId (Formatos de identificador estandarizados)
        * AlgorithmIdentifier (Estructura para especificar algoritmos criptográficos y sus parámetros esenciales, ej: "AES/GCM/NoPadding", nombre de curva para EC, hash para RSA-OAEP. Debe ser suficiente para que la implementación de fac-crypto-api actúe sin ambigüedad, pero sin detalles específicos de una librería concreta.)
        * FacException (clase base para errores de FAC, con códigos de error definidos)
        * DTOs comunes para comunicación intermódulos si no están cubiertos por APIs específicas.

### 3.2. fac-crypto-api
    * Propósito: Define interfaces para todas las operaciones criptográficas, permitiendo implementaciones conectables.
    * Interfaces/Operaciones Clave (Ilustrativo):
        * KeyGenerator:
            * generateIdentityKeyPair(spec): IKP (FAC-RF-KM-001)
            * generateResourceEncryptionKey(spec): REK (FAC-RF-KM-002)
        * AsymmetricCrypter:
            * encrypt(publicKey, data, algorithmIdentifier): Ciphertext
            * decrypt(privateKey, ciphertext, algorithmIdentifier): Plaintext
        * SymmetricCrypter:
            * encrypt(key, data, algorithmIdentifierWithParams): CiphertextWithIV
            * decrypt(key, ciphertextWithIV, algorithmIdentifierWithParams): Plaintext
        * KeyDerivationFunction (KDF):
            * deriveKey(secret, algorithmIdentifierWithParams): DerivedKey (ej., para contraseñas FAC-RF-KM-003.3)
    * Nota de Implementación: Cada operación debe manejar la especificación del algoritmo claramente mediante AlgorithmIdentifier y parámetros asociados.

### 3.3. fac-manifest-api
    * Propósito: Define la estructura de AccessManifest y CryptoStep, que forman el núcleo de las políticas de acceso.
    * Estructuras de Datos Clave:
        * AccessManifest: (Diseñado para recuperación eficiente, ver FAC-RF-AM-006)
            * manifestId: string (Identificador único del manifiesto)
            * resourceId: string (Identificador del recurso al que protege, clave para indexación)
            * manifestType: string (ej., "DirectShare", "GroupKey", "PasswordProtected", "RecoveryCode", "DenyUser". FAC puede definir constantes para tipos comunes, pero la lógica asociada a tipos personalizados es de la aplicación. Clave para indexación y lógica de precedencia.)
            * recipientMatcher: object (Define criterios para la coincidencia, ej., { type: "identity", id: "userId" }, { type: "group", id: "groupId" }, { type: "passwordProtected" }. Los campos internos como id son claves para indexación.)
            * cryptoPipeline: CryptoStep[] (FAC-RF-AM-001.1)
            * encryptedPayload: bytes (La REK cifrada o clave intermedia) (FAC-RF-AM-001.2.d)
            * permissions: string[] (ej., ["READ", "WRITE"]) (FAC-RF-ADL-003)
            * precedence: number (Opcional, puede derivarse del tipo o configurarse por la aplicación)
            * creationTimestamp: date
            * metadata: object (Específico de la aplicación, puede contener campos para indexación adicional)
        * CryptoStep:
            * stepId: string (Identificador único dentro del pipeline)
            * operation: string (ej., "ASYMMETRIC_DECRYPT", "SYMMETRIC_DECRYPT", "KDF_DERIVE_KEY")
            * algorithmIdentifier: object (Especifica el algoritmo como "RSA-OAEP-2048-SHA256", "AES-256-GCM", "Argon2id") (FAC-RF-CA-002)
            * inputSource: { type: "MANIFEST_PAYLOAD" | "PREVIOUS_STEP_OUTPUT" | "CONSTANT", value?: any, stepRef?: string } (ej., "MANIFEST_PAYLOAD", "PREVIOUS_STEP_OUTPUT", "CONSTANT")
            * keySource: { type: "IKP_PRIVATE" | "INPUT_PROVIDER_SECRET" | "PREVIOUS_STEP_OUTPUT_AS_KEY" | "GROUP_KEY_VIA_INPUT_PROVIDER" | "APPLICATION_RESOLVED_KEY", identifier?: string, stepRef?: string, promptHint?: string } (ej., "IKP_PRIVATE", "INPUT_PROVIDER_SECRET" (para contraseñas, códigos de recuperación), "PREVIOUS_STEP_OUTPUT_AS_KEY"). El AccessDecisionEngine resuelve esto: IKP_PRIVATE desde IdentityContext, INPUT_PROVIDER_SECRET llamando a InputProvider. APPLICATION_RESOLVED_KEY podría ser un nuevo tipo para delegar la resolución a un KeySourceResolver inyectado. (FAC-RF-AM-001.3.c)
            * parameters: object (ej., { iv: bytes, salt: bytes, iterations: number, contextInfo: bytes }) (FAC-RF-AM-001.3.d)
            * outputName: string (Nombre para referenciar la salida de este paso)

### 3.4. fac-manifest-engine-core
    * Propósito: Contiene el AccessDecisionEngine y la lógica relacionada para evaluar manifiestos y ejecutar pipelines criptográficos.
    * Componentes Clave:
        * AccessDecisionEngine:
            * evaluateAccess(manifests: AccessManifest[], identityContext: IdentityContext, inputProvider: InputProvider, keySourceResolver?: KeySourceResolver): Promise<AccessDecision> (FAC-RF-ADL-001). El keySourceResolver es opcional y permitiría a la aplicación personalizar la obtención de claves para ciertos keySource.type.
            * El motor ejecuta la lógica de coincidencia de manifiestos y la ejecución del pipeline. La interpretación de ManifestType para la precedencia o lógica de negocio adicional puede ser extendida/configurada por la aplicación consumidora.
        * InputProvider (Interfaz): (FAC-RF-ADL-001.3)
            * requestSecret(type: string, promptHint?: string, context?: object): Promise<SecretMaterial> (Invocado por el motor cuando un CryptoStep.keySource es de tipo INPUT_PROVIDER_SECRET para obtener dinámicamente contraseñas, códigos de recuperación, etc.)
        * KeySourceResolver (Interfaz Opcional):
            * resolveKey(keySourceIdentifier: string, identityContext: IdentityContext, manifest?: AccessManifest): Promise<KeyMaterial> (Invocado por el motor si un CryptoStep.keySource.type es APPLICATION_RESOLVED_KEY).
        * IdentityContext (Estructura de Datos):
            * identityId: string
            * attributes: object (ej., membresías de grupo, roles)
            * availablePrivateKeys: Map<string, PrivateKeyMaterial> (Clave: identificador/alias de clave, Valor: bytes de la clave privada real, potencialmente desbloqueada)
        * AccessDecision (Estructura de Datos):
            * resourceId: string
            * identityId: string
            * outcome: "GRANTED" | "DENIED" | "REQUIRES_INPUT" | "PIPELINE_STEP_FAILED" (Outcome más granular)
            * derivedRek?: bytes (Si GRANTED)
            * effectivePermissions?: string[]
            * winningManifestId?: string
            * failureDetails?: { stepId?: string, errorCode?: string, message?: string } (Detalles en caso de fallo)
    * Servicios de Ayuda (Helpers):
        * ManifestRekeyService (o similar):
            * rekeyManifestPayload(manifest: AccessManifest, newKeyMaterial: KeyMaterial, oldKeyResolver: (manifest: AccessManifest, identityContext: IdentityContext, inputProvider: InputProvider) => Promise<KeyMaterial>): Promise<AccessManifest> (FAC-RF-AM-004): Ayuda a re-cifrar el encryptedPayload de un manifiesto. El oldKeyResolver podría usar el InputProvider o IdentityContext para obtener la clave antigua necesaria para descifrar el payload antes de re-cifrarlo con newKeyMaterial.
    * Lógica Central:
        1.  Ordenación de Manifiestos por Precedencia (FAC-RF-ADL-002), configurable por la aplicación.
        2.  Coincidencia iterativa de manifiestos contra IdentityContext.
        3.  Para el manifiesto ganador, ejecutar el pipeline CryptoStep:
            * Resolver datos de entrada y material de clave para cada paso (usando InputProvider o KeySourceResolver si aplica).
            * Invocar fac-crypto-api para las operaciones.

### 3.5. fac-manifest-persistence-api
    * Propósito: Define interfaces para almacenar y recuperar objetos AccessManifest.
    * Interfaz Clave (ManifestRepository): (FAC-RF-AM-003)
        * save(manifest: AccessManifest): Promise<void>
        * findByResourceId(resourceId: string): Promise<AccessManifest[]>
        * findById(manifestId: string): Promise<AccessManifest | null>
        * delete(manifestId: string): Promise<void>
        * update(manifest: AccessManifest): Promise<void>
        * query(criteria: object): Promise<AccessManifest[]> (Consulta flexible, permitiendo a la aplicación construir consultas complejas basadas en campos indexables del manifiesto)

### 3.6. fac-group-management-api (Conceptual)
    * Propósito: Define interfaces para la gestión segura de claves de grupo.
    * Interfaz Clave (SecureGroupManager): (FAC-RF-SGM-001)
        * createGroup(initialMembers: IdentityContext[]): Promise<GroupContext>
        * addMember(groupContext: GroupContext, newMember: IdentityContext, adminContext?: IdentityContext): Promise<GroupContextWithKeyInfo>
        * removeMember(groupContext: GroupContext, memberToRemove: IdentityId, adminContext?: IdentityContext): Promise<GroupContextWithKeyInfo> (Implica re-keying. FAC-RF-SGM-001.c: Debe devolver información sobre la clave antigua y la nueva).
        * getGroupKeyEnvelopeForMember(groupContext: GroupContext, memberId: IdentityId): Promise<EncryptedKeyEnvelope> (Proporciona la REK del grupo envuelta para el miembro)
    * GroupContext: Contiene ID de grupo, REK de grupo actual (o su forma protegida), lista de miembros, etc.
    * GroupContextWithKeyInfo: Extiende GroupContext para incluir oldKeyDescriptor y newKeyDescriptor tras operaciones de re-keying.
    * Nota: El FAC en sí podría no proporcionar una implementación completa de la lógica de grupo, sino los ganchos y expectativas sobre cómo se representan los compartidos de grupo en los manifiestos.

## 4. Flujos de Trabajo Clave

### 4.1. Proteger un Recurso y Crear Manifiestos (Enveloping)

(Sin cambios significativos respecto a v1, la lógica sigue siendo válida)

1. Generar REK_Recurso: Usar fac-crypto-api (FAC-RF-KM-002).

2. Cifrar Contenido del Recurso: (Responsabilidad de la aplicación consumidora usando REK_Recurso).

3. Para cada destinatario/método de acceso:
   a.  Definir Pipeline de Descifrado (CryptoStep[]).
   b.  Realizar Operaciones Inversas (Cifrado) para generar encryptedPayload.
   c.  Construir AccessManifest.
   d.  Persistir Manifiesto.

### 4.2. Acceder a un Recurso (Decisión y Descifrado)

(Adaptado para reflejar el AccessDecision más granular y el KeySourceResolver opcional)

1. Aplicación Recopila Entradas: AccessManifest[], IdentityContext, InputProvider, opcionalmente KeySourceResolver.

2. Invocar Motor FAC: AccessDecisionEngine.evaluateAccess(manifests, identityContext, inputProvider, keySourceResolver).

3. Procesamiento del Motor:
   a.  Ordena manifiestos.
   b.  Encuentra manifiesto coincidente.
   c.  Si "Deny", devuelve AccessDecision con outcome: "DENIED".
   d.  Si "Grant":
   i.  Ejecuta cryptoPipeline. Si un paso falla, devuelve AccessDecision con outcome: "PIPELINE_STEP_FAILED" y failureDetails. Si requiere input y no se puede obtener, podría ser REQUIRES_INPUT o PIPELINE_STEP_FAILED.
   ii. Si éxito, devuelve AccessDecision con outcome: "GRANTED", derivedRek, effectivePermissions.
   e.  Si ningún manifiesto "Grant" coincide, devuelve outcome: "DENIED".

### 4.3. Gestión y Recuperación del Par de Claves de Identidad (IKP)

(Corrección de texto y manteniendo la lógica)

* Generación de IKP (FAC-RF-KM-001): fac-crypto-api.generateIdentityKeyPair().

* Protección de la Clave Privada IKP: Tratarla como un "Recurso" con su propia REK_IKPpriv.

* Manifiestos para REK_IKPpriv:

  * Habilitando ZKM: Manifiestos para descifrar REK_IKPpriv con clave derivada de contraseña maestra (vía InputProvider), o mediante códigos de recuperación (cada uno un manifiesto con CryptoStep usando InputProvider).

  * Habilitando EKM: Manifiesto adicional para descifrar REK_IKPpriv mediante mecanismo controlado por la organización.

* Desbloqueo de la Clave Privada IKP:

  1. Tratar IKP privada como recurso.

  2. Recopilar sus AccessManifests.

  3. Llamar a AccessDecisionEngine.evaluateAccess(...) para estos manifiestos.

  4. Si GRANTED, usar REK_IKPpriv devuelta para descifrar la IKP privada.

## 5. Habilitación de Modelos de Confianza (ZKM vs. EKM)

* El FAC habilita la implementación de diversos modelos de confianza, incluyendo ZKM y EKM, en lugar de implementarlos directamente. Lo hace a través de:

  * Pipelines Criptográficos Flexibles (CryptoStep): Permiten definir cómo se protege y accede a una clave (ej. la REK_IKPpriv).

  * InputProvider: Permite que la aplicación solicite secretos directamente al usuario (para ZKM) o a través de otros mecanismos.
  * KeySourceResolver (Opcional): Permite a la aplicación integrar lógicas de obtención de claves más complejas o específicas de su dominio.

  * Manifiestos Múltiples: Se pueden crear diferentes AccessManifests para el mismo secreto (ej. REK_IKPpriv), uno para acceso por contraseña de usuario (ZKM) y otro para recuperación empresarial (EKM). El AccessDecisionEngine evaluará el que corresponda según el contexto.

* La aplicación consumidora es responsable de definir y gestionar los manifiestos que corresponden al modelo de confianza deseado para cada Identidad o Recurso.

## 6. Puntos de Extensibilidad

* Implementaciones de fac-crypto-api: Intercambiar bibliotecas criptográficas.

* Implementaciones de fac-manifest-persistence-api: Conectar a diferentes backends de almacenamiento.

* Definiciones de ManifestType (FAC-RF-AM-002): Las aplicaciones definen la semántica y lógica de negocio para sus tipos de manifiesto personalizados. FAC se centra en la ejecución del cryptoPipeline.

* Implementaciones de SecureGroupManager (FAC-RF-SGM-002): Diferentes esquemas de gestión de grupos.

* Implementaciones de InputProvider: Personalizar cómo se recopilan los secretos dinámicos del usuario/entorno.
* Implementaciones de KeySourceResolver (Opcional): Personalizar cómo se obtienen claves específicas para CryptoStep.

* Configuración de Precedencia de Manifiestos: La aplicación puede influir en el orden de evaluación.

* Servicio de Logging: FAC puede emitir eventos/datos estructurados de log, o se le puede inyectar una interfaz LogService implementada por la aplicación para integrarse con su sistema de logging.

## 7. Discusión Adicional y Decisiones de Diseño

* Granularidad de AlgorithmIdentifier: Reafirmado. Debe ser suficiente para que la implementación de fac-crypto-api actúe sin ambigüedad (ej., especificando el algoritmo completo como "AES/GCM/NoPadding", el nombre de la curva para EC, o el algoritmo de hash y MGF para RSA-OAEP), pero sin atarse a detalles internos de una librería criptográfica específica.

* Biblioteca Estándar de Constantes ManifestType: Reafirmado. FAC podría proporcionar un conjunto de strings constantes recomendados para tipos comunes (ej., fac.manifest.type.DIRECT_SHARE, fac.manifest.type.GROUP_KEY, fac.manifest.type.PASSWORD_PROTECTED) para fomentar la interoperabilidad y facilitar la configuración de la precedencia, pero la lógica de negocio asociada a estos tipos (más allá de la ejecución del pipeline) sigue siendo responsabilidad de la aplicación.

* Flujo de Desbloqueo de Clave Privada IKP: Reafirmado. Se gestiona como una llamada estándar (potencialmente recursiva/anidada conceptualmente) al AccessDecisionEngine, tratando la IKP privada como un recurso protegido por sus propios manifiestos.

* Manejo e Informe de Errores y Logging: Reafirmado. FAC definirá un conjunto de códigos de error internos y estructurados en FacException y AccessDecision.failureDetails. Para el logging, se considera preferible una interfaz LogService inyectable por la aplicación consumidora, permitiendo la integración con su infraestructura de logging (ej., SLF4J en un contexto Java). Alternativamente, FAC podría emitir eventos de log estructurados que la aplicación puede capturar.

* Resolución de keySource en CryptoStep:
    * Los tipos básicos como IKP_PRIVATE (obtenido de IdentityContext.availablePrivateKeys) y PREVIOUS_STEP_OUTPUT_AS_KEY son resueltos directamente por el motor.
    * INPUT_PROVIDER_SECRET (para contraseñas, códigos de recuperación, etc.) se resuelve mediante la interfaz InputProvider implementada por la aplicación.
    * Nueva Consideración: Para escenarios más complejos o para permitir a la aplicación una mayor flexibilidad en cómo se obtienen ciertas claves (ej., claves de grupo gestionadas externamente, claves derivadas de atributos de sesión complejos), se introduce la idea de un KeySourceResolver opcional.
        * Se añadiría un nuevo keySource.type como APPLICATION_RESOLVED_KEY.
        * Si este tipo se usa y se proporciona un KeySourceResolver al AccessDecisionEngine, el motor delegaría la obtención de esta clave a dicha interfaz, pasándole el keySource.identifier y el IdentityContext.
        * Esto mantiene el núcleo del motor simple para los casos comunes pero ofrece un punto de extensión potente.

* Complejidad del Re-keying de Grupo (FAC-RF-SGM-001.3): Reafirmado. El SecureGroupManager.removeMember() (y addMember si implica re-keying) debe devolver información sobre la clave antigua (invalidada) y la nueva. FAC debe ofrecer un ManifestRekeyService con una función helper (rekeyManifestPayload) que tome un manifiesto, la nueva clave y un medio para resolver la clave antigua (posiblemente usando InputProvider o IdentityContext a través de un oldKeyResolver lambda), y devuelva el manifiesto con su payload re-cifrado. La orquestación de encontrar todos los manifiestos afectados por un cambio de clave de grupo y aplicar esta re-clave es responsabilidad de la aplicación consumidora (posiblemente mediante tareas en segundo plano).

* Transaccionalidad para Operaciones de Manifiesto: Reafirmado. Las APIs de FAC (ej., ManifestRepository.save, ManifestRekeyService.rekeyManifestPayload) operan sobre entidades individuales o devuelven nuevas entidades. La aplicación consumidora es responsable de invocar estas operaciones dentro de sus propias transacciones de base de datos para asegurar la atomicidad cuando múltiples manifiestos o entidades relacionadas se modifican (ej., al añadir un miembro a un grupo y actualizar tanto el estado del grupo como crear/actualizar manifiestos).

* Consideraciones de Rendimiento para la Recuperación de Manifiestos (FAC-RF-AM-006): Reafirmado. El diseño de AccessManifest debe incluir campos clave (resourceId, recipientMatcher (con sus subcampos como id), manifestType) que sean fácilmente indexables por la capa de persistencia de la aplicación para permitir una recuperación eficiente de los manifiestos candidatos.

* Compatibilidad con Stack Tecnológico de Referencia (Java/Spring/Reactor): Aunque las interfaces de FAC son genéricas, al diseñar las implementaciones de referencia o ejemplos, se debe considerar cómo se integran naturalmente con patrones comunes en este stack (ej., uso de Mono/Flux de Project Reactor para operaciones asíncronas, beans de Spring para servicios FAC, configuración de InputProvider y KeySourceResolver como componentes Spring).

Este diseño de alto nivel proporciona un punto de partida para la arquitectura del FAC. Cada módulo y componente requerirá un diseño detallado adicional.