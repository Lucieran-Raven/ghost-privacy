# Certificate Pinning (Soft)

Ghost Privacy implements **soft certificate pinning** in native builds.

- The app **detects** certificate pin mismatches and shows a **non-blocking warning**.
- The app **must never block** connectivity or crash due to pin mismatch.

This feature is intended to help users detect potential man-in-the-middle (MITM) attacks while avoiding outages when certificates rotate.

## What is pinned

We pin **SPKI SHA-256** fingerprints (the SHA-256 hash of the SubjectPublicKeyInfo DER).

Targets:

- `ghostprivacy.netlify.app`
- `muirdvibzicpedfmqdrf.supabase.co`

## Where pins live

Pins are configured in:

- `public/cert_pins.json`

Format:

- `expires`: policy expiration date (informational; used for pin management)
- `domains.<host>.pins`: primary SPKI pins
- `domains.<host>.backupPins`: backup SPKI pins (recommended for rotations)

## How checks run

- **Android (Capacitor):** `CertPinning.verifyCertPinning()` performs a best-effort HTTPS probe to each host and computes the observed SPKI pin. Results are compared to the config and reported to JS.
- **Tauri:** `verify_cert_pinning` (Rust command) uses `reqwest` with TLS info enabled to fetch the peer leaf certificate, computes the observed SPKI pin, compares to config, and reports results to JS.
- **Frontend:** `runCertificatePinningCheck()` runs at startup and shows a persistent toast warning if any host is a mismatch.

The UI warning is informational; the app continues to function.

## Obtaining pins

Use OpenSSL to compute the SPKI pin (base64 of sha256(SPKI DER)):

### ghostprivacy.netlify.app

```bash
openssl s_client -servername ghostprivacy.netlify.app -connect ghostprivacy.netlify.app:443 < /dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

### muirdvibzicpedfmqdrf.supabase.co

```bash
openssl s_client -servername muirdvibzicpedfmqdrf.supabase.co -connect muirdvibzicpedfmqdrf.supabase.co:443 < /dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

Add at least:

- One **current** pin in `pins`
- One **backup** pin in `backupPins` (next cert/public key) if you control rotation; otherwise, keep the existing key as long as possible.

## Rotation process

- **Before rotation:** add the new key’s pin into `backupPins`.
- **Rotate certificate/public key.**
- **After rotation:** move the new pin into `pins` and keep the old pin in `backupPins` for a grace period.
- Update `expires` when you refresh your policy.

## Limitations

- Soft pinning does not prevent all MITM attacks; it is a detection mechanism.
- If an attacker can serve a valid chain and also match one of the configured pins, the check will not warn.
- JavaScript/UI warnings can be suppressed by compromised client environments; treat warnings as a signal, not a guarantee.
