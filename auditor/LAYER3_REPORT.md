# Ghost Privacy — Layer 3 Runtime/UI Hardening Report

This report documents the Layer 3 hardening work focused on runtime behavior, UI artifact reduction, and upload/download safety.

## Scope (Layer 3)

- Runtime messaging/session behavior:
  - `src/lib/realtimeManager.ts`
  - `src/lib/sessionService.ts`
  - `src/utils/clientMessageQueue.ts`
- UI/runtime surfaces:
  - `src/components/Ghost/ChatInterface.tsx`
  - `src/components/Ghost/FilePreviewCard.tsx`
  - `src/components/Ghost/KeyVerificationModal.tsx`
  - `src/components/Ghost/SessionCreator.tsx`
  - `src/components/Ghost/FakeApiDocs.tsx`

## Key invariants (Layer 3)

- Incoming realtime messages must have replay/duplicate suppression to reduce CPU/memory abuse.
- File transfer must be bounded (chunk count, chunk size, metadata lengths).
- Runtime crypto must not depend on platform globals (`atob`/`btoa`).
- UI/runtime must minimize artifacts:
  - limit downloads to explicit `blob:`/`data:` URLs
  - revoke object URLs on teardown and eviction
  - reduce clipboard persistence (best-effort)
- Link preview should avoid downgrade/phishing surfaces (HTTPS only).

## Hardening timeline (commits)

Repository: https://github.com/Lucieran-Raven/ghost-privacy

- `c3bbb75` — Layer3: replay guard, file transfer bounds, and base64 codec parity
- `2442cf2` — Layer3: wipe file transfer buffers and clear replay cache on disconnect
- `a58ca16` — Layer3: restrict downloads to blob/data URLs (avoid blob from arbitrary strings)
- `9f157c9` — Layer3: clipboard auto-clear and stricter download guards
- `ef260ac` — Layer3: only allow https link previews
- `97ebe4c` — Layer3: only allow https link previews in chat
- `025191a` — Layer3: revoke object URLs on eviction; file metadata bounds and MIME sniffing

## Notable fixes

- Realtime replay suppression:
  - Drop duplicate `(senderId, nonce)` within a TTL window.
  - Added unit test coverage.

- File transfer DoS hardening:
  - Caps on `totalChunks`.
  - Bounds on per-chunk string size.
  - Bounds on `fileId` and `iv` lengths.

- File-type safety:
  - Prefer content-sniffed MIME for decrypted payloads (PDF/PNG/JPEG/GIF/WebP), otherwise `application/octet-stream`.
  - Normalize displayed filename extension to match sniffed MIME.

- UI artifact reduction:
  - Downloads only permitted for `blob:`/`data:`.
  - Clipboard auto-clear best-effort after 30s on copy actions.
  - Object URLs revoked on session teardown and on message eviction.

## Remaining considerations

- Browser and OS behavior can still persist artifacts outside app control (downloads are OS-level persistence once initiated; OS swap/hibernation, browser caches, immutable JS strings).
- Mitigations here focus on fail-closed validation, strict bounds, and minimizing avoidable artifacts.
