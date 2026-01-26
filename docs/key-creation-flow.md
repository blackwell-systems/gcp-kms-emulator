# GCP KMS Key Creation Flow

This document explains the complete flow for creating cryptographic keys in Google Cloud KMS, from KeyHandle through CryptoKeyVersion.

## Resource Hierarchy

```mermaid
flowchart TB
    subgraph folder["Folder (Autokey Config)"]
        config[Autokey Configuration<br/>Specifies key project]
    end
    
    subgraph resourceProject["Resource Project"]
        keyhandle[KeyHandle<br/>Triggers auto-provisioning]
    end
    
    subgraph keyProject["Key Project (Centralized)"]
        subgraph location["Location"]
            keyring[KeyRing<br/>Logical grouping]
            
            subgraph cryptokey["CryptoKey"]
                version1[CryptoKeyVersion 1<br/>Primary]
                version2[CryptoKeyVersion 2]
                version3[CryptoKeyVersion N]
            end
        end
    end
    
    config --> keyhandle
    keyhandle -.->|Auto-provisions| keyring
    keyring --> cryptokey
    cryptokey --> version1
    cryptokey --> version2
    cryptokey --> version3
    
    style folder fill:#3A4A5C,stroke:#6b7280,color:#f0f0f0
    style resourceProject fill:#3A4C43,stroke:#6b7280,color:#f0f0f0
    style keyProject fill:#4C4538,stroke:#6b7280,color:#f0f0f0
    style location fill:#3A4A5C,stroke:#6b7280,color:#f0f0f0
    style cryptokey fill:#4C3A3C,stroke:#6b7280,color:#f0f0f0
```

## Complete Key Creation Flow

```mermaid
sequenceDiagram
    participant Admin
    participant Folder
    participant Client
    participant KMS as Cloud KMS
    participant KeyProject
    
    Note over Admin,Folder: Step 1: Configure Autokey
    Admin->>Folder: UpdateAutokeyConfig
    Folder->>Folder: Store key project ID
    
    Note over Client,KMS: Step 2: Create KeyHandle
    Client->>KMS: CreateKeyHandle(resource_project, location)
    KMS->>Folder: Check Autokey config
    Folder-->>KMS: Return key project ID
    
    Note over KMS,KeyProject: Step 3: Auto-Provision Resources
    KMS->>KeyProject: Check if KeyRing exists
    alt KeyRing doesn't exist
        KMS->>KeyProject: Create KeyRing
    end
    
    KMS->>KeyProject: Create CryptoKey
    KMS->>KeyProject: Create initial CryptoKeyVersion
    KeyProject-->>KMS: Resources created
    
    KMS-->>Client: Return KeyHandle
    
    Note over Client,KMS: Step 4: Use Key
    Client->>KMS: Encrypt(key_handle)
    KMS->>KeyProject: Resolve KeyHandle to CryptoKey
    KMS->>KeyProject: Use CryptoKeyVersion (primary)
    KeyProject-->>KMS: Encrypted data
    KMS-->>Client: Return ciphertext
```

## Resource Relationships

### KeyHandle
- **Purpose:** Lightweight reference triggering automatic key provisioning
- **Location:** Resource project (where application lives)
- **Contains:** Pointer to actual CryptoKey in key project
- **Lifecycle:** Created by client, triggers Autokey

### KeyRing
- **Purpose:** Logical grouping of CryptoKeys
- **Location:** Key project (centralized)
- **Immutable:** Cannot be deleted once created
- **Naming:** projects/{project}/locations/{location}/keyRings/{keyring}

### CryptoKey
- **Purpose:** Logical key that can have multiple versions
- **Location:** Inside KeyRing
- **Properties:** Purpose (encrypt/decrypt, sign/verify), rotation schedule
- **Naming:** projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}

### CryptoKeyVersion
- **Purpose:** Actual cryptographic key material
- **Location:** Inside CryptoKey
- **Lifecycle:** Created → Enabled → Disabled → Destroyed
- **Primary version:** The version used for new operations
- **Naming:** {cryptoKey}/cryptoKeyVersions/{version}

## Key Creation Process (Detailed)

### Phase 1: Autokey Configuration (One-Time Setup)

```
Folder
  └─ Autokey Configuration
       └─ Key Project: "central-keys-project"
```

**API Call:**
```
UpdateAutokeyConfig(
  parent: "folders/123456",
  keyProject: "projects/central-keys-project"
)
```

### Phase 2: KeyHandle Creation (Per Application)

```
Resource Project: "my-app-project"
  └─ KeyHandle: "my-database-key-handle"
       └─ Location: "us-east1"
```

**API Call:**
```
CreateKeyHandle(
  parent: "projects/my-app-project/locations/us-east1",
  keyHandleId: "my-database-key-handle"
)
```

### Phase 3: Automatic Provisioning (Behind the Scenes)

**KMS Autokey automatically creates:**

```
Key Project: "central-keys-project"
  └─ Location: "us-east1"
       └─ KeyRing: "autokey-keyring"
            └─ CryptoKey: "generated-key-abc123"
                 └─ CryptoKeyVersion: "1" (primary, enabled)
```

**Resources created:**
1. KeyRing (if doesn't exist): `projects/central-keys-project/locations/us-east1/keyRings/autokey-keyring`
2. CryptoKey: `{keyring}/cryptoKeys/generated-key-abc123`
3. CryptoKeyVersion: `{cryptoKey}/cryptoKeyVersions/1`

### Phase 4: Key Usage

**Client code:**
```go
// Encrypt using KeyHandle
req := &kmspb.EncryptRequest{
    Name: "projects/my-app-project/locations/us-east1/keyHandles/my-database-key-handle",
    Plaintext: []byte("sensitive data"),
}
response, _ := client.Encrypt(ctx, req)
```

**Behind the scenes:**
1. KMS resolves KeyHandle → CryptoKey in key project
2. Uses primary CryptoKeyVersion for encryption
3. Returns ciphertext

## Key Concepts

### Autokey Benefits
- **Centralized management:** All keys in one project
- **Automatic provisioning:** No manual KeyRing/CryptoKey creation
- **Resource separation:** Application project ≠ key project
- **On-demand creation:** Keys created when first needed

### KeyHandle vs Direct CryptoKey
- **KeyHandle:** Indirect reference, triggers auto-provisioning
- **Direct CryptoKey:** Must create KeyRing, CryptoKey, CryptoKeyVersion manually
- **Trade-off:** Convenience vs control

### Resource Naming
```
KeyHandle:
  projects/{resource-project}/locations/{location}/keyHandles/{handle-id}

CryptoKey (auto-created):
  projects/{key-project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}

CryptoKeyVersion:
  {cryptoKey}/cryptoKeyVersions/{version}
```

## State Diagram: CryptoKeyVersion Lifecycle

```mermaid
stateDiagram-v2
    [*] --> PendingGeneration: Create
    PendingGeneration --> Enabled: Generation Complete
    Enabled --> Disabled: Disable
    Disabled --> Enabled: Enable
    Disabled --> ScheduledDestruction: Destroy
    ScheduledDestruction --> Destroyed: After 24h
    Destroyed --> [*]
    
    note right of Enabled: Can encrypt/decrypt
    note right of Disabled: Cannot use, but can re-enable
    note right of Destroyed: Permanent, cannot recover
```

## Implementation Considerations for Emulator

### Minimum Viable KMS Emulator

**Must implement:**
1. KeyRing management (create, get, list)
2. CryptoKey management (create, get, list, update)
3. CryptoKeyVersion management (create, destroy, enable, disable)
4. Encryption operations (encrypt, decrypt)
5. Version state transitions (pending → enabled → disabled → destroyed)

**Optional for v1:**
- KeyHandle + Autokey (complex, can start with direct CryptoKey creation)
- Signing operations (asymmetric keys)
- MAC operations
- Import/export functionality
- HSM integration (not needed for local testing)

### Complexity Comparison

**Secret Manager:**
- 12 API methods total
- Simple CRUD operations
- One resource type (secrets + versions)

**KMS:**
- 50+ API methods
- Complex cryptographic operations
- Multiple resource types (KeyRing, CryptoKey, CryptoKeyVersion, KeyHandle)
- Actual encryption/decryption (need crypto library)
- State machine management (version lifecycle)

**KMS is significantly more complex than Secret Manager.**
