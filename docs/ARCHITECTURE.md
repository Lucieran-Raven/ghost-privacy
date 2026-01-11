# Ghost Privacy Architecture

```mermaid
graph LR
  subgraph Client_Device_A[Client Device (Sender)]
    A[User Browser / App UI]
    M1[Plaintext in RAM]
    B[Encryption + Key Management\n(ECDH P-256, AES-256-GCM)]
    P1[nuclearPurge() / Teardown]
    A --> M1
    M1 --> B
    P1 -->|Best-effort memory cleanup| M1
    P1 -->|Key teardown| B
  end

  subgraph Supabase[Supabase (Coordination Only)]
    F[Edge Functions\ncreate/validate/extend/delete session]
    DB[(Postgres\nSession metadata only)]
    R[Realtime Channels\nCiphertext delivery]
    F <--> DB
    F --> R
  end

  subgraph Client_Device_B[Client Device (Recipient)]
    D[Recipient Browser / App UI]
    E[Decrypt in RAM]
    M2[Plaintext in RAM]
    D --> E
    E --> M2
  end

  B -->|Ciphertext + Capability Token| R
  R -->|Ciphertext| D

  A -->|Session create/join\n(capability token + fingerprint)| F
  D -->|Session join/extend/delete\n(capability token + fingerprint)| F

  F -->|Enforces:\n- capability token hash\n- fingerprint binding\n- IP-hash binding (HMAC-SHA256, truncated)| DB
```

## Key boundaries

- **Plaintext stays client-side**
  - Messages are encrypted/decrypted on the client.
  - The server never receives plaintext or private keys.

- **Server sees ciphertext + minimal session metadata only**
  - Stored metadata is limited to session coordination and anti-hijacking enforcement (e.g. `session_id`, `capability_hash`, `ip_hash`, `expires_at`).

- **Best-effort cleanup on session end**
  - `nuclearPurge()` is designed to wipe in-app state and teardown keys.
  - OS/browser behavior (swap/pagefile, crash dumps, GC, extensions) can create artifacts outside application control.
