use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::RngCore;
use tauri::{Manager, Runtime, RunEvent};

static CLEANUP_PLAN: OnceLock<CleanupPlan> = OnceLock::new();
static KEY_VAULT: OnceLock<KeyVault> = OnceLock::new();

struct CleanupPlan {
  paths: Mutex<Vec<PathBuf>>,
}

struct KeyVault {
  keys: Mutex<HashMap<String, [u8; 32]>>,
}

impl KeyVault {
  fn new() -> Self {
    Self {
      keys: Mutex::new(HashMap::new()),
    }
  }

  fn set_key(&self, session_id: String, key: [u8; 32]) {
    let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
    keys.insert(session_id, key);
  }

  fn get_key(&self, session_id: &str) -> Option<[u8; 32]> {
    let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
    keys.get(session_id).copied()
  }

  fn purge(&self) {
    let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
    for (_, mut k) in keys.drain() {
      k.fill(0);
    }
  }
}

impl CleanupPlan {
  fn new() -> Self {
    Self {
      paths: Mutex::new(Vec::new()),
    }
  }

  fn add_path(&self, path: PathBuf) {
    if path.as_os_str().is_empty() {
      return;
    }

    let mut paths = self.paths.lock().unwrap_or_else(|e| e.into_inner());
    if !paths.contains(&path) {
      paths.push(path);
    }
  }

  fn purge_best_effort(&self) {
    let paths = {
      let paths = self.paths.lock().unwrap_or_else(|e| e.into_inner());
      paths.clone()
    };

    for p in paths {
      purge_path_best_effort(&p);
    }
  }
}

fn purge_path_best_effort(path: &Path) {
  let md = std::fs::metadata(path);
  if md.is_err() {
    return;
  }

  let md = md.unwrap();
  if md.is_file() {
    let _ = std::fs::remove_file(path);
    return;
  }

  if md.is_dir() {
    let _ = std::fs::remove_dir_all(path);
  }
}

fn build_cleanup_plan<R: Runtime>(app: &tauri::AppHandle<R>) {
  let plan = CLEANUP_PLAN.get_or_init(CleanupPlan::new);

  if let Ok(p) = app.path().app_cache_dir() {
    plan.add_path(p);
  }
  if let Ok(p) = app.path().app_data_dir() {
    plan.add_path(p);
  }
  if let Ok(p) = app.path().app_config_dir() {
    plan.add_path(p);
  }
  if let Ok(p) = app.path().app_log_dir() {
    plan.add_path(p);
  }

  let mut runtime_dir = std::env::temp_dir();
  runtime_dir.push("ghost-privacy-runtime");
  runtime_dir.push(uuid::Uuid::new_v4().to_string());
  let _ = std::fs::create_dir_all(&runtime_dir);
  plan.add_path(runtime_dir);
}

fn purge_cleanup_plan() {
  if let Some(plan) = CLEANUP_PLAN.get() {
    plan.purge_best_effort();
  }

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

#[tauri::command]
fn secure_panic_wipe() {
  purge_cleanup_plan();
}

#[tauri::command]
fn vault_set_key(session_id: String, key_base64: String) -> Result<(), String> {
  let raw = decode_b64(&key_base64)?;
  if raw.len() != 32 {
    return Err("key must be 32 bytes".to_string());
  }

  let mut key = [0u8; 32];
  key.copy_from_slice(&raw);

  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  vault.set_key(session_id, key);
  Ok(())
}

#[tauri::command]
fn vault_encrypt(session_id: String, plaintext_base64: String) -> Result<serde_json::Value, String> {
  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  let key_bytes = vault.get_key(&session_id).ok_or_else(|| "missing session key".to_string())?;

  let plaintext = decode_b64(&plaintext_base64)?;
  let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

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
fn vault_decrypt(session_id: String, ciphertext_base64: String, iv_base64: String) -> Result<String, String> {
  let vault = KEY_VAULT.get_or_init(KeyVault::new);
  let key_bytes = vault.get_key(&session_id).ok_or_else(|| "missing session key".to_string())?;

  let ciphertext = decode_b64(&ciphertext_base64)?;
  let iv = decode_b64(&iv_base64)?;
  if iv.len() != 12 {
    return Err("iv must be 12 bytes".to_string());
  }

  let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
  let nonce = Nonce::from_slice(&iv);

  let plaintext = cipher
    .decrypt(nonce, ciphertext.as_ref())
    .map_err(|_| "decrypt failed".to_string())?;

  Ok(encode_b64(&plaintext))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  std::panic::set_hook(Box::new(|_| {
    purge_cleanup_plan();
  }));

  tauri::Builder::default()
    .setup(|app| {
      build_cleanup_plan(&app.handle());

      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
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
    .on_run_event(|_app, event| {
      match event {
        RunEvent::ExitRequested { .. } => {
          purge_cleanup_plan();
        }
        RunEvent::Exit => {
          purge_cleanup_plan();
        }
        _ => {}
      }
    })
    .invoke_handler(tauri::generate_handler![
      secure_panic_wipe,
      vault_set_key,
      vault_encrypt,
      vault_decrypt
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
