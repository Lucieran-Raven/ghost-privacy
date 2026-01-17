package app.ghostprivacy.mobile;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.os.Build;
import java.security.KeyStore;
import java.util.Enumeration;
import javax.crypto.KeyGenerator;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "VersionGuard")
public class VersionGuardPlugin extends Plugin {
  @PluginMethod
  public void getVersionGuardStatus(PluginCall call) {
    JSObject ret = new JSObject();

    try {
      long current = 0L;
      try {
        PackageManager pm = getContext().getPackageManager();
        String pkg = getContext().getPackageName();
        PackageInfo pi = pm.getPackageInfo(pkg, 0);
        if (pi != null) {
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            current = pi.getLongVersionCode();
          } else {
            current = pi.versionCode;
          }
        }
      } catch (Exception e) {
        current = 0L;
      }

      final String prefix = "ghost_privacy_max_version_";
      long maxSeen = 0L;
      String maxAlias = null;

      try {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
          String a = aliases.nextElement();
          if (a == null || !a.startsWith(prefix)) continue;
          String suf = a.substring(prefix.length());
          try {
            long v = Long.parseLong(suf);
            if (v > maxSeen) {
              maxSeen = v;
              maxAlias = a;
            }
          } catch (Exception e) {
          }
        }

        if (current > 0L && current > maxSeen) {
          if (maxAlias != null) {
            try {
              ks.deleteEntry(maxAlias);
            } catch (Exception e) {
            }
          }

          String alias = prefix + Long.toString(current);
          try {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
              alias,
              KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
            )
              .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
              .setUserAuthenticationRequired(false)
              .build();
            kg.init(spec);
            kg.generateKey();
            maxSeen = current;
          } catch (Exception e) {
          }
        }
      } catch (Exception e) {
        maxSeen = 0L;
      }

      ret.put("platform", "android");
      ret.put("currentVersionCode", current);
      ret.put("maxSeenVersionCode", maxSeen);

      if (current <= 0L) {
        ret.put("status", "error");
      } else if (maxSeen > 0L && current < maxSeen) {
        ret.put("status", "downgraded");
      } else {
        ret.put("status", "ok");
      }

      call.resolve(ret);
    } catch (Exception e) {
      ret.put("platform", "android");
      ret.put("status", "error");
      call.resolve(ret);
    }
  }
}
