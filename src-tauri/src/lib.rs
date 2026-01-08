use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tauri::RunEvent;
use tauri_plugin_log::{Target, TargetKind};
use zeroize::{Zeroize, Zeroizing};

static KEY_VAULT: OnceLock<KeyVault> = OnceLock::new();

struct KeyVault {
  keys: Mutex<HashMap<String, Zeroizing<[u8; 32]>>>,
}

impl KeyVault {
  fn new() -> Self {
    Self {
      keys: Mutex::new(HashMap::new()),
    }
  }

  fn set_key(&self, session_id: String, key: [u8; 32]) {
    let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
    keys.insert(session_id, Zeroizing::new(key));
  }

  fn get_key(&self, session_id: &str) -> Option<Zeroizing<[u8; 32]>> {
    let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
    keys.get(session_id).cloned()
  }

  fn purge(&self) {
    let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
    keys.clear();
  }
}
fn purge_cleanup_plan() {
  if let Some(vault) = KEY_VAULT.get() {
    vault.purge();
  }
}

fn decode_b64(s: &str) -> Result<Vec<u8>, String> {
  BASE64.decode(s.as_bytes()).map_err(|_| "invalid base64".to_string())
}

fn encode_b64(bytes: &[u8]) -> String {
  BASE64.encode(bytes)
}

fn decode_b64url_like_browser(s: &str) -> Result<Vec<u8>, String> {
  // Mirrors TS behavior:
  // value.replace(/-/g, '+').replace(/_/g, '/').padEnd(..., '='); atob(padded)
  let mut normalized = s.replace('-', "+").replace('_', "/");
  let rem = normalized.len() % 4;
  if rem != 0 {
    normalized.extend(std::iter::repeat('=').take(4 - rem));
  }

  decode_b64(&normalized)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len() * 2);
  for b in bytes {
    out.push_str(&format!("{:02x}", b));
  }
  out
}

fn hmac_sha256_hex(key: &[u8], message: &str) -> Result<String, String> {
  type HmacSha256 = Hmac<Sha256>;
  let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| "invalid hmac key".to_string())?;
  mac.update(message.as_bytes());
  let mut digest = mac.finalize().into_bytes();
  let out = bytes_to_hex(&digest);
  digest.zeroize();
  Ok(out)
}

#[tauri::command]
fn secure_panic_wipe() {
  purge_cleanup_plan();
}

#[tauri::command]
fn vault_set_key(session_id: String, key_base64: String) -> Result<(), String> {
  let raw = Zeroizing::new(decode_b64(&key_base64)?);
  if raw.len() != 32 {
    return Err("key must be 32 bytes".to_string());
  }

  let mut key = [0u8; 32];
  key.copy_from_slice(raw.as_slice());

  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  vault.set_key(session_id, key);
  Ok(())
}

#[tauri::command]
fn vault_encrypt(session_id: String, plaintext_base64: String) -> Result<serde_json::Value, String> {
  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  let key_bytes = vault.get_key(&session_id).ok_or_else(|| "missing session key".to_string())?;

  let plaintext = Zeroizing::new(decode_b64(&plaintext_base64)?);
  let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes.as_ref()));

  let mut nonce_bytes = [0u8; 12];
  OsRng.fill_bytes(&mut nonce_bytes);
  let nonce = Nonce::from_slice(&nonce_bytes);

  let ciphertext = cipher
    .encrypt(nonce, plaintext.as_ref())
    .map_err(|_| "encrypt failed".to_string())?;

  Ok(serde_json::json!({
    "ciphertext": encode_b64(&ciphertext),
    "iv": encode_b64(&nonce_bytes)
  }))
}

#[tauri::command]
fn vault_encrypt_utf8(session_id: String, plaintext: String) -> Result<serde_json::Value, String> {
  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  let key_bytes = vault.get_key(&session_id).ok_or_else(|| "missing session key".to_string())?;

  let plaintext = Zeroizing::new(plaintext);

  let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes.as_ref()));

  let mut nonce_bytes = [0u8; 12];
  OsRng.fill_bytes(&mut nonce_bytes);
  let nonce = Nonce::from_slice(&nonce_bytes);

  let ciphertext = cipher
    .encrypt(nonce, plaintext.as_bytes())
    .map_err(|_| "encrypt failed".to_string())?;

  Ok(serde_json::json!({
    "ciphertext": encode_b64(&ciphertext),
    "iv": encode_b64(&nonce_bytes)
  }))
}

#[tauri::command]
fn vault_decrypt(session_id: String, ciphertext_base64: String, iv_base64: String) -> Result<String, String> {
  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  let key_bytes = vault.get_key(&session_id).ok_or_else(|| "missing session key".to_string())?;

  let ciphertext = decode_b64(&ciphertext_base64)?;
  let iv = decode_b64(&iv_base64)?;
  if iv.len() != 12 {
    return Err("iv must be 12 bytes".to_string());
  }

  let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes.as_ref()));
  let nonce = Nonce::from_slice(&iv);

  let plaintext = Zeroizing::new(
    cipher
    .decrypt(nonce, ciphertext.as_ref())
    .map_err(|_| "decrypt failed".to_string())?
  );

  let out = encode_b64(plaintext.as_ref());
  Ok(out)
}

#[tauri::command]
fn vault_decrypt_utf8(session_id: String, ciphertext_base64: String, iv_base64: String) -> Result<String, String> {
  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  let key_bytes = vault.get_key(&session_id).ok_or_else(|| "missing session key".to_string())?;

  let ciphertext = decode_b64(&ciphertext_base64)?;
  let iv = decode_b64(&iv_base64)?;
  if iv.len() != 12 {
    return Err("iv must be 12 bytes".to_string());
  }

  let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes.as_ref()));
  let nonce = Nonce::from_slice(&iv);

  let plaintext = Zeroizing::new(
    cipher
      .decrypt(nonce, ciphertext.as_ref())
      .map_err(|_| "decrypt failed".to_string())?,
  );

  let out = std::str::from_utf8(plaintext.as_ref())
    .map_err(|_| "invalid utf-8".to_string())?
    .to_string();
  Ok(out)
}

#[tauri::command]
fn derive_realtime_channel_name(session_id: String, capability_token: String) -> Result<String, String> {
  let key_bytes = Zeroizing::new(match decode_b64url_like_browser(&capability_token) {
    Ok(b) => b,
    Err(_) => capability_token.as_bytes().to_vec(),
  });

  let mac_hex = hmac_sha256_hex(key_bytes.as_slice(), &session_id)?;
  let tag = mac_hex
    .get(0..32)
    .ok_or_else(|| "invalid hmac output".to_string())?;

  Ok(format!("ghost-session-{}-{}", session_id, tag))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  std::panic::set_hook(Box::new(|_| {
    purge_cleanup_plan();
  }));

  let app = tauri::Builder::default()
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::new()
            .targets([Target::new(TargetKind::Stdout)])
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }

      Ok(())
    })
    .on_window_event(|_window, event| {
      if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
        purge_cleanup_plan();
      }
    })
    .invoke_handler(tauri::generate_handler![
      secure_panic_wipe,
      vault_set_key,
      vault_encrypt,
      vault_encrypt_utf8,
      vault_decrypt,
      vault_decrypt_utf8,
      derive_realtime_channel_name
    ])
    .build(tauri::generate_context!())
    .expect("error while building tauri application");

  app.run(|_app, event| {
    if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
      purge_cleanup_plan();
    }
  });
}
