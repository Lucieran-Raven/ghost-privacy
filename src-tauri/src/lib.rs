use std::collections::HashMap;
#[cfg(not(windows))]
use std::{fs::File, io::Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use reqwest::redirect::Policy;
use sha2::{Digest, Sha256};
use tauri::RunEvent;
use tauri_plugin_log::{Target, TargetKind};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::{Zeroize, Zeroizing};

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use windows_sys::core::GUID;
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
  CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CryptMsgClose,
  CryptMsgGetParam, CryptQueryObject, CERT_FIND_SUBJECT_CERT, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
  CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
};
#[cfg(windows)]
use windows_sys::Win32::Security::WinTrust::{
  WinVerifyTrust, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
  WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

mod memory_lock {
  #[derive(Clone, Copy)]
  pub struct LockError;

  pub struct LockedRegion {
    ptr: usize,
    len: usize,
  }

  impl LockedRegion {
    pub fn lock(ptr: *const u8, len: usize) -> Result<Self, LockError> {
      if ptr.is_null() || len == 0 {
        return Err(LockError);
      }
      lock_raw(ptr, len)?;
      Ok(Self { ptr: ptr as usize, len })
    }
  }

  impl Drop for LockedRegion {
    fn drop(&mut self) {
      if self.ptr == 0 || self.len == 0 {
        return;
      }
      let _ = unlock_raw(self.ptr as *const u8, self.len);
    }
  }

  #[cfg(unix)]
  fn lock_raw(ptr: *const u8, len: usize) -> Result<(), LockError> {
    let rc = unsafe { libc::mlock(ptr as *const core::ffi::c_void, len) };
    if rc == 0 { Ok(()) } else { Err(LockError) }
  }

  #[cfg(unix)]
  fn unlock_raw(ptr: *const u8, len: usize) -> Result<(), LockError> {
    let rc = unsafe { libc::munlock(ptr as *const core::ffi::c_void, len) };
    if rc == 0 { Ok(()) } else { Err(LockError) }
  }

  #[cfg(windows)]
  fn lock_raw(ptr: *const u8, len: usize) -> Result<(), LockError> {
    let ok = unsafe {
      windows_sys::Win32::System::Memory::VirtualLock(ptr as *const core::ffi::c_void, len)
    };
    if ok != 0 { Ok(()) } else { Err(LockError) }
  }

  #[cfg(windows)]
  fn unlock_raw(ptr: *const u8, len: usize) -> Result<(), LockError> {
    let ok = unsafe {
      windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *const core::ffi::c_void, len)
    };
    if ok != 0 { Ok(()) } else { Err(LockError) }
  }

  #[cfg(not(any(unix, windows)))]
  fn lock_raw(_ptr: *const u8, _len: usize) -> Result<(), LockError> {
    Err(LockError)
  }

  #[cfg(not(any(unix, windows)))]
  fn unlock_raw(_ptr: *const u8, _len: usize) -> Result<(), LockError> {
    Err(LockError)
  }
}

static KEY_VAULT: OnceLock<KeyVault> = OnceLock::new();
static MLOCK_WARNED: AtomicBool = AtomicBool::new(false);

const MAX_SESSION_ID_LEN: usize = 32;
const MAX_CAPABILITY_TOKEN_LEN: usize = 256;
const MAX_B64_INPUT_LEN: usize = 24 * 1024 * 1024;
const MAX_VAULT_PLAINTEXT_BYTES: usize = 12 * 1024 * 1024;
const MAX_VAULT_UTF8_BYTES: usize = 256 * 1024;
const MAX_VAULT_KEYS: usize = 128;

struct LockedKey {
  _lock: Option<memory_lock::LockedRegion>,
  key: Box<Zeroizing<[u8; 32]>>,
}

struct KeyVault {
  keys: Mutex<HashMap<String, LockedKey>>,
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
  if session_id.is_empty() {
    return Err("empty session id".to_string());
  }
  if session_id.len() > MAX_SESSION_ID_LEN {
    return Err("session id too large".to_string());
  }

  let bytes = session_id.as_bytes();
  if bytes.len() != 15 {
    return Err("invalid session id".to_string());
  }
  if &bytes[0..6] != b"GHOST-" {
    return Err("invalid session id".to_string());
  }
  if bytes[10] != b'-' {
    return Err("invalid session id".to_string());
  }
  for &b in bytes[6..10].iter().chain(bytes[11..15].iter()) {
    let ok = matches!(b, b'A'..=b'Z' | b'0'..=b'9');
    if !ok {
      return Err("invalid session id".to_string());
    }
  }
  Ok(())
}

impl KeyVault {
  fn new() -> Self {
    Self {
      keys: Mutex::new(HashMap::new()),
    }
  }

  fn set_key(&self, session_id: String, key: [u8; 32]) -> Result<(), String> {
    let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
    if keys.len() >= MAX_VAULT_KEYS && !keys.contains_key(&session_id) {
      return Err("vault full".to_string());
    }
    let mut key = key;
    let key_box: Box<Zeroizing<[u8; 32]>> = Box::new(Zeroizing::new(key));
    key.zeroize();

    let key_bytes: &[u8; 32] = &*key_box;
    let lock = match memory_lock::LockedRegion::lock(key_bytes.as_ptr(), 32) {
      Ok(l) => Some(l),
      Err(_) => {
        #[cfg(debug_assertions)]
        {
          if !MLOCK_WARNED.swap(true, Ordering::Relaxed) {
            eprintln!("[WARN] mlock/VirtualLock failed; running in best-effort mode");
          }
        }
        None
      }
    };

    keys.insert(session_id, LockedKey { _lock: lock, key: key_box });
    Ok(())
  }

  fn with_key<T>(&self, session_id: &str, f: impl FnOnce(&[u8; 32]) -> Result<T, String>) -> Result<T, String> {
    let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
    let locked = keys.get(session_id).ok_or_else(|| "missing session key".to_string())?;
    let key_ref: &[u8; 32] = &*locked.key;
    f(key_ref)
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

fn decode_b64_limited(s: &str, max_input_len: usize, max_decoded_len: usize) -> Result<Vec<u8>, String> {
  if s.is_empty() {
    return Err("empty base64".to_string());
  }
  if s.len() > max_input_len {
    return Err("base64 input too large".to_string());
  }
  let decoded = decode_b64(s)?;
  if decoded.len() > max_decoded_len {
    return Err("decoded payload too large".to_string());
  }
  Ok(decoded)
}

fn encode_b64(bytes: &[u8]) -> String {
  BASE64.encode(bytes)
}

fn decode_b64url_like_browser(s: &str) -> Result<Vec<u8>, String> {
  if s.is_empty() {
    return Err("empty token".to_string());
  }
  if s.len() > MAX_CAPABILITY_TOKEN_LEN {
    return Err("token too large".to_string());
  }
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

#[cfg(windows)]
fn to_wide_null(s: &std::path::Path) -> Vec<u16> {
  let mut v: Vec<u16> = s.as_os_str().encode_wide().collect();
  v.push(0);
  v
}

#[cfg(windows)]
fn wintrust_action_generic_verify_v2() -> GUID {
  GUID {
    data1: 0x00AAC56B,
    data2: 0xCD44,
    data3: 0x11D0,
    data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
  }
}

#[cfg(windows)]
fn verify_windows_authenticode_and_get_signer_cert_sha256(exe_path: &std::path::Path) -> Result<String, String> {
  let exe_wide = to_wide_null(exe_path);

  let mut file_info = WINTRUST_FILE_INFO {
    cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
    pcwszFilePath: exe_wide.as_ptr(),
    hFile: std::ptr::null_mut(),
    pgKnownSubject: std::ptr::null_mut(),
  };

  let action = wintrust_action_generic_verify_v2();

  let mut trust_data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
  trust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
  trust_data.dwUIChoice = WTD_UI_NONE;
  trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
  trust_data.dwUnionChoice = WTD_CHOICE_FILE;
  trust_data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file_info };
  trust_data.dwStateAction = WTD_STATEACTION_VERIFY;

  let status = unsafe {
    WinVerifyTrust(
      std::ptr::null_mut(),
      &action as *const GUID as *mut GUID,
      &mut trust_data as *mut WINTRUST_DATA as *mut c_void,
    )
  };
  if status != 0 {
    // best-effort close
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
      WinVerifyTrust(
        std::ptr::null_mut(),
        &action as *const GUID as *mut GUID,
        &mut trust_data as *mut WINTRUST_DATA as *mut c_void,
      );
    }
    return Err("authenticode verification failed".to_string());
  }

  let observed = (|| {
    let mut encoding: u32 = 0;
    let mut content_type: u32 = 0;
    let mut format_type: u32 = 0;
    let mut store: HCERTSTORE = std::ptr::null_mut();
    let mut msg: *mut c_void = std::ptr::null_mut();
    let mut ctx: *mut c_void = std::ptr::null_mut();

    let ok = unsafe {
      CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        exe_wide.as_ptr() as *const c_void,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &mut encoding,
        &mut content_type,
        &mut format_type,
        &mut store,
        &mut msg,
        &mut ctx,
      )
    };
    if ok == 0 {
      return Err("CryptQueryObject failed".to_string());
    }

    let mut signer_info_len: u32 = 0;
    let ok = unsafe {
      CryptMsgGetParam(
        msg,
        CMSG_SIGNER_INFO_PARAM,
        0,
        std::ptr::null_mut(),
        &mut signer_info_len,
      )
    };
    if ok == 0 || signer_info_len == 0 {
      unsafe {
        if !store.is_null() { CertCloseStore(store, 0); }
        if !msg.is_null() { CryptMsgClose(msg); }
      }
      return Err("CryptMsgGetParam size failed".to_string());
    }

    let mut signer_buf = vec![0u8; signer_info_len as usize];
    let ok = unsafe {
      CryptMsgGetParam(
        msg,
        CMSG_SIGNER_INFO_PARAM,
        0,
        signer_buf.as_mut_ptr() as *mut c_void,
        &mut signer_info_len,
      )
    };
    if ok == 0 {
      unsafe {
        if !store.is_null() { CertCloseStore(store, 0); }
        if !msg.is_null() { CryptMsgClose(msg); }
      }
      return Err("CryptMsgGetParam data failed".to_string());
    }

    let signer_info = signer_buf.as_ptr() as *const CMSG_SIGNER_INFO;
    if signer_info.is_null() {
      unsafe {
        if !store.is_null() { CertCloseStore(store, 0); }
        if !msg.is_null() { CryptMsgClose(msg); }
      }
      return Err("signer info missing".to_string());
    }

    let mut cert_info = unsafe { std::mem::zeroed::<windows_sys::Win32::Security::Cryptography::CERT_INFO>() };
    unsafe {
      cert_info.Issuer = (*signer_info).Issuer;
      cert_info.SerialNumber = (*signer_info).SerialNumber;
    }

    let cert_ctx = unsafe {
      CertFindCertificateInStore(
        store,
        encoding,
        0,
        CERT_FIND_SUBJECT_CERT,
        &cert_info as *const _ as *const c_void,
        std::ptr::null(),
      )
    };
    if cert_ctx.is_null() {
      unsafe {
        if !store.is_null() { CertCloseStore(store, 0); }
        if !msg.is_null() { CryptMsgClose(msg); }
      }
      return Err("signer cert not found".to_string());
    }

    let bytes = unsafe {
      std::slice::from_raw_parts((*cert_ctx).pbCertEncoded, (*cert_ctx).cbCertEncoded as usize)
    };
    let out = bytes_to_hex(Sha256::digest(bytes).as_slice());

    unsafe {
      CertFreeCertificateContext(cert_ctx);
      if !store.is_null() { CertCloseStore(store, 0); }
      if !msg.is_null() { CryptMsgClose(msg); }
    }
    Ok(out)
  })();

  trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
  unsafe {
    WinVerifyTrust(
      std::ptr::null_mut(),
      &action as *const GUID as *mut GUID,
      &mut trust_data as *mut WINTRUST_DATA as *mut c_void,
    );
  }

  observed
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

#[derive(serde::Deserialize)]
struct PinningTarget {
  host: String,
  pins: Vec<String>,
}

#[tauri::command]
async fn verify_cert_pinning(targets: Vec<PinningTarget>) -> Result<serde_json::Value, String> {
  let client = reqwest::Client::builder()
    .redirect(Policy::none())
    .timeout(std::time::Duration::from_secs(7))
    .tls_info(true)
    .build()
    .map_err(|_| "pinning probe init failed".to_string())?;

  let mut results: Vec<serde_json::Value> = Vec::new();

  for t in targets {
    let host = t.host;

    if host.is_empty() {
      results.push(serde_json::json!({"host": host, "status": "error"}));
      continue;
    }

    if t.pins.is_empty() {
      results.push(serde_json::json!({"host": host, "status": "skipped"}));
      continue;
    }

    let url = format!("https://{}/", host);
    let resp = match client.get(url).send().await {
      Ok(r) => r,
      Err(_) => {
        results.push(serde_json::json!({"host": host, "status": "error"}));
        continue;
      }
    };

    let tls = match resp.extensions().get::<reqwest::tls::TlsInfo>() {
      Some(t) => t,
      None => {
        results.push(serde_json::json!({"host": host, "status": "error"}));
        continue;
      }
    };

    let leaf_der = match tls.peer_certificate() {
      Some(b) => b,
      None => {
        results.push(serde_json::json!({"host": host, "status": "error"}));
        continue;
      }
    };

    let (_, cert) = match X509Certificate::from_der(leaf_der) {
      Ok(c) => c,
      Err(_) => {
        results.push(serde_json::json!({"host": host, "status": "error"}));
        continue;
      }
    };

    let spki_der = cert.tbs_certificate.subject_pki.raw;
    let observed_pin = encode_b64(Sha256::digest(spki_der).as_slice());
    let matched = t.pins.iter().any(|p| p == &observed_pin);
    results.push(serde_json::json!({
      "host": host,
      "observedPin": observed_pin,
      "status": if matched { "ok" } else { "mismatch" }
    }));
  }

  Ok(serde_json::json!({"results": results}))
}

#[tauri::command]
fn verify_build_integrity() -> Result<serde_json::Value, String> {
  #[cfg(windows)]
  {
    let expected = option_env!("GHOST_EXPECTED_TAURI_SIGNING_CERT_SHA256").unwrap_or("");
    if expected.is_empty() {
      return Ok(serde_json::json!({"status": "error"}));
    }

    let exe_path = std::env::current_exe().map_err(|_| "exe path unavailable".to_string())?;
    let observed = match verify_windows_authenticode_and_get_signer_cert_sha256(&exe_path) {
      Ok(v) => v,
      Err(_) => {
        return Ok(serde_json::json!({
          "status": "unverified",
          "expected": expected
        }))
      }
    };

    let ok = observed.eq_ignore_ascii_case(expected);
    return Ok(serde_json::json!({
      "status": if ok { "verified" } else { "unverified" },
      "observed": observed,
      "expected": expected
    }));
  }

  #[cfg(not(windows))]
  {
    let expected = option_env!("GHOST_EXPECTED_TAURI_EXE_SHA256").unwrap_or("");
    if expected.is_empty() {
      return Ok(serde_json::json!({"status": "skipped"}));
    }

    let exe_path = std::env::current_exe().map_err(|_| "exe path unavailable".to_string())?;
    let mut f = File::open(&exe_path).map_err(|_| "failed to open executable".to_string())?;

    let mut h = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
      let n = f.read(&mut buf).map_err(|_| "failed to read executable".to_string())?;
      if n == 0 {
        break;
      }
      h.update(&buf[..n]);
    }

    let observed = bytes_to_hex(h.finalize().as_slice());
    let ok = observed.eq_ignore_ascii_case(expected);

    Ok(serde_json::json!({
      "status": if ok { "verified" } else { "unverified" },
      "observed": observed,
      "expected": expected
    }))
  }
}

#[tauri::command]
fn secure_panic_wipe() {
  purge_cleanup_plan();
}

#[tauri::command]
fn secure_panic_exit() {
  purge_cleanup_plan();
  std::process::exit(1);
}

#[tauri::command]
fn vault_set_key(session_id: String, key_base64: String) -> Result<(), String> {
  validate_session_id(&session_id)?;

  if key_base64.len() > 128 {
    return Err("key payload too large".to_string());
  }

  let raw = Zeroizing::new(decode_b64_limited(&key_base64, 128, 64)?);
  if raw.len() != 32 {
    return Err("key must be 32 bytes".to_string());
  }

  let mut key = [0u8; 32];
  key.copy_from_slice(raw.as_slice());

  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  vault.set_key(session_id, key)?;
  Ok(())
}

#[tauri::command]
fn vault_encrypt(session_id: String, plaintext_base64: String) -> Result<serde_json::Value, String> {
  validate_session_id(&session_id)?;

  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  vault.with_key(&session_id, |key_bytes| {
    let plaintext = Zeroizing::new(decode_b64_limited(&plaintext_base64, MAX_B64_INPUT_LEN, MAX_VAULT_PLAINTEXT_BYTES)?);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));

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
  })
}

#[tauri::command]
fn vault_encrypt_utf8(session_id: String, plaintext: String) -> Result<serde_json::Value, String> {
  validate_session_id(&session_id)?;

  let vault = KEY_VAULT.get_or_init(KeyVault::new);

  if plaintext.len() > MAX_VAULT_UTF8_BYTES {
    return Err("plaintext too large".to_string());
  }

  vault.with_key(&session_id, |key_bytes| {
    let plaintext = Zeroizing::new(plaintext);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));

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
  })
}

#[tauri::command]
fn vault_decrypt(session_id: String, ciphertext_base64: String, iv_base64: String) -> Result<String, String> {
  validate_session_id(&session_id)?;

  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  if iv_base64.len() > 64 {
    return Err("iv payload too large".to_string());
  }

  vault.with_key(&session_id, |key_bytes| {
    let ciphertext = decode_b64_limited(&ciphertext_base64, MAX_B64_INPUT_LEN, MAX_VAULT_PLAINTEXT_BYTES + 32)?;
    let iv = decode_b64_limited(&iv_base64, 64, 64)?;
    if iv.len() != 12 {
      return Err("iv must be 12 bytes".to_string());
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let nonce = Nonce::from_slice(&iv);

    let plaintext = Zeroizing::new(
      cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "decrypt failed".to_string())?,
    );

    Ok(encode_b64(plaintext.as_ref()))
  })
}

#[tauri::command]
fn vault_decrypt_utf8(session_id: String, ciphertext_base64: String, iv_base64: String) -> Result<String, String> {
  validate_session_id(&session_id)?;

  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  if iv_base64.len() > 64 {
    return Err("iv payload too large".to_string());
  }

  vault.with_key(&session_id, |key_bytes| {
    let ciphertext = decode_b64_limited(&ciphertext_base64, MAX_B64_INPUT_LEN, MAX_VAULT_PLAINTEXT_BYTES + 32)?;
    let iv = decode_b64_limited(&iv_base64, 64, 64)?;
    if iv.len() != 12 {
      return Err("iv must be 12 bytes".to_string());
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let nonce = Nonce::from_slice(&iv);

    let plaintext = Zeroizing::new(
      cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "decrypt failed".to_string())?,
    );

    std::str::from_utf8(plaintext.as_ref())
      .map_err(|_| "invalid utf-8".to_string())
      .map(|s| s.to_string())
  })
}

#[tauri::command]
fn derive_realtime_channel_name(session_id: String, capability_token: String) -> Result<String, String> {
  validate_session_id(&session_id)?;
  if capability_token.is_empty() {
    return Err("empty token".to_string());
  }
  if capability_token.len() > MAX_CAPABILITY_TOKEN_LEN {
    return Err("token too large".to_string());
  }

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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn session_id_validation_accepts_canonical() {
    assert!(validate_session_id("GHOST-ABCD-1234").is_ok());
  }

  #[test]
  fn session_id_validation_rejects_invalid() {
    assert!(validate_session_id("ghost-ABCD-1234").is_err());
    assert!(validate_session_id("GHOST-ABCD-123").is_err());
    assert!(validate_session_id("GHOST-ABCD-12345").is_err());
    assert!(validate_session_id("GHOST-ABcD-1234").is_err());
  }
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
      secure_panic_exit,
      verify_cert_pinning,
      verify_build_integrity,
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
