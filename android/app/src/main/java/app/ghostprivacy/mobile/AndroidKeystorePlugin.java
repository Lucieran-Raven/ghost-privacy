package app.ghostprivacy.mobile;

import android.os.Build;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

@CapacitorPlugin(name = "AndroidKeystore")
public class AndroidKeystorePlugin extends Plugin {
  private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
  private static final String KEY_ALIAS = "ghost_privacy_wrap_key_v1";
  private static final int IV_SIZE = 12;
  private static final int TAG_BITS = 128;

  private SecretKey getOrCreateKey() throws Exception {
    KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
    ks.load(null);

    if (ks.containsAlias(KEY_ALIAS)) {
      SecretKey existing = (SecretKey) ks.getKey(KEY_ALIAS, null);
      if (existing != null) return existing;
    }

    KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);

    KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
      KEY_ALIAS,
      KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setRandomizedEncryptionRequired(true)
      .setUserAuthenticationRequired(false);

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      try {
        b.setIsStrongBoxBacked(true);
      } catch (Exception ignored) {
      }
    }

    try {
      kg.init(b.build());
      return kg.generateKey();
    } catch (Exception e) {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        KeyGenParameterSpec.Builder b2 = new KeyGenParameterSpec.Builder(
          KEY_ALIAS,
          KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
          .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
          .setKeySize(256)
          .setRandomizedEncryptionRequired(true)
          .setUserAuthenticationRequired(false);
        kg.init(b2.build());
        return kg.generateKey();
      }
      throw e;
    }
  }

  @PluginMethod
  public void isAvailable(PluginCall call) {
    JSObject ret = new JSObject();
    ret.put("available", Build.VERSION.SDK_INT >= Build.VERSION_CODES.M);
    call.resolve(ret);
  }

  @PluginMethod
  public void wrap(PluginCall call) {
    String plaintextBase64 = call.getString("plaintextBase64", "");
    if (plaintextBase64 == null || plaintextBase64.length() == 0) {
      call.reject("missing plaintextBase64");
      return;
    }

    byte[] plaintext = null;
    byte[] iv = null;
    try {
      plaintext = android.util.Base64.decode(plaintextBase64, android.util.Base64.DEFAULT);
      iv = new byte[IV_SIZE];
      new SecureRandom().nextBytes(iv);

      SecretKey key = getOrCreateKey();
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
      byte[] ciphertext = cipher.doFinal(plaintext);

      JSObject ret = new JSObject();
      ret.put("ciphertextBase64", android.util.Base64.encodeToString(ciphertext, android.util.Base64.NO_WRAP));
      ret.put("ivBase64", android.util.Base64.encodeToString(iv, android.util.Base64.NO_WRAP));
      call.resolve(ret);

      Arrays.fill(ciphertext, (byte) 0);
    } catch (Exception e) {
      call.reject("wrap failed", e);
    } finally {
      try {
        if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
      } catch (Exception ignored) {
      }
      try {
        if (iv != null) Arrays.fill(iv, (byte) 0);
      } catch (Exception ignored) {
      }
    }
  }

  @PluginMethod
  public void unwrap(PluginCall call) {
    String ciphertextBase64 = call.getString("ciphertextBase64", "");
    String ivBase64 = call.getString("ivBase64", "");

    if (ciphertextBase64 == null || ciphertextBase64.length() == 0) {
      call.reject("missing ciphertextBase64");
      return;
    }
    if (ivBase64 == null || ivBase64.length() == 0) {
      call.reject("missing ivBase64");
      return;
    }

    byte[] ciphertext = null;
    byte[] iv = null;
    try {
      ciphertext = android.util.Base64.decode(ciphertextBase64, android.util.Base64.DEFAULT);
      iv = android.util.Base64.decode(ivBase64, android.util.Base64.DEFAULT);
      if (iv == null || iv.length != IV_SIZE) {
        call.reject("invalid iv");
        return;
      }

      SecretKey key = getOrCreateKey();
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
      byte[] plaintext = cipher.doFinal(ciphertext);

      JSObject ret = new JSObject();
      ret.put("plaintextBase64", android.util.Base64.encodeToString(plaintext, android.util.Base64.NO_WRAP));
      call.resolve(ret);

      Arrays.fill(plaintext, (byte) 0);
    } catch (Exception e) {
      call.reject("unwrap failed", e);
    } finally {
      try {
        if (ciphertext != null) Arrays.fill(ciphertext, (byte) 0);
      } catch (Exception ignored) {
      }
      try {
        if (iv != null) Arrays.fill(iv, (byte) 0);
      } catch (Exception ignored) {
      }
    }
  }

  @PluginMethod
  public void deleteKey(PluginCall call) {
    try {
      KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
      ks.load(null);
      if (ks.containsAlias(KEY_ALIAS)) {
        ks.deleteEntry(KEY_ALIAS);
      }
      call.resolve(new JSObject());
    } catch (Exception e) {
      call.reject("deleteKey failed", e);
    }
  }
}
