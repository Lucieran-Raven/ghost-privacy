package app.ghostprivacy.mobile;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ApplicationInfo;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowManager;
import android.webkit.CookieManager;
import android.webkit.ServiceWorkerController;
import android.webkit.ServiceWorkerWebSettings;
import android.webkit.WebSettings;
import android.webkit.WebStorage;
import android.webkit.WebView;
import java.io.File;
import java.security.MessageDigest;
import java.security.KeyStore;
import java.util.Enumeration;
import javax.crypto.KeyGenerator;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    try {
      getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
    } catch (Exception e) {
    }

    enforceVersionMonotonicityBestEffort();
    enforceRuntimeIntegrityBestEffort();
    try {
      registerPlugin(AppSettingsPlugin.class);
      registerPlugin(CertPinningPlugin.class);
      registerPlugin(WebViewCleanupPlugin.class);
      registerPlugin(BuildIntegrityPlugin.class);
      registerPlugin(VersionGuardPlugin.class);
      registerPlugin(AndroidKeystorePlugin.class);
    } catch (Exception e) {
    }
    hardenWebView();
  }

  @Override
  public void onPause() {
    super.onPause();
    clearClipboardBestEffort();
  }

  @Override
  public void onStop() {
    super.onStop();
    clearClipboardBestEffort();
    clearWebViewData();
  }

  @Override
  public void onDestroy() {
    super.onDestroy();
    clearClipboardBestEffort();
    clearWebViewData();
  }

  private void clearClipboardBestEffort() {
    try {
      ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
      if (cm == null) return;
      cm.setPrimaryClip(ClipData.newPlainText("", ""));
    } catch (Exception e) {
    }
  }

  private static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  private static String sha256Hex(byte[] data) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] digest = md.digest(data);
    return bytesToHex(digest);
  }

  private void enforceVersionMonotonicityBestEffort() {
    try {
      long current = 0L;
      try {
        PackageManager pm = getPackageManager();
        String pkg = getPackageName();
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

      if (current <= 0L) {
        return;
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

        if (maxSeen > 0L && current < maxSeen) {
          panicExitBestEffort();
          return;
        }

        if (current > maxSeen) {
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
          } catch (Exception e) {
          }
        }
      } catch (Exception e) {
      }
    } catch (Exception e) {
    }
  }

  private void enforceRuntimeIntegrityBestEffort() {
    try {
      String expected = "";
      try {
        expected = BuildConfig.EXPECTED_SIGNING_CERT_SHA256;
      } catch (Exception e) {
        expected = "";
      }

      if (expected == null || expected.length() == 0) {
        return;
      }

      PackageManager pm = getPackageManager();
      String pkg = getPackageName();

      byte[] certBytes = null;

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
        if (pi.signingInfo != null) {
          if (pi.signingInfo.hasMultipleSigners()) {
            if (pi.signingInfo.getApkContentsSigners() != null && pi.signingInfo.getApkContentsSigners().length > 0) {
              certBytes = pi.signingInfo.getApkContentsSigners()[0].toByteArray();
            }
          } else {
            if (pi.signingInfo.getSigningCertificateHistory() != null && pi.signingInfo.getSigningCertificateHistory().length > 0) {
              certBytes = pi.signingInfo.getSigningCertificateHistory()[0].toByteArray();
            }
          }
        }
      } else {
        PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
        if (pi.signatures != null && pi.signatures.length > 0) {
          certBytes = pi.signatures[0].toByteArray();
        }
      }

      if (certBytes == null || certBytes.length == 0) {
        panicExitBestEffort();
        return;
      }

      String observed = sha256Hex(certBytes);
      boolean ok = observed.equalsIgnoreCase(expected);
      if (!ok) {
        panicExitBestEffort();
      }
    } catch (Exception e) {
      panicExitBestEffort();
    }
  }

  private void panicExitBestEffort() {
    try {
      try {
        finishAndRemoveTask();
      } catch (Exception ignored) {
      }
      try {
        android.os.Process.killProcess(android.os.Process.myPid());
      } catch (Exception ignored) {
      }
      try {
        System.exit(1);
      } catch (Exception ignored) {
      }
    } catch (Exception ignored) {
    }
  }

  private void hardenWebView() {
    try {
      try {
        boolean isDebuggable = false;
        try {
          ApplicationInfo ai = getApplicationInfo();
          isDebuggable = (ai != null) && ((ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
        } catch (Exception e) {
        }

        if (!isDebuggable && Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
          try {
            WebView.setWebContentsDebuggingEnabled(false);
          } catch (Exception e) {
          }
        }
      } catch (Exception e) {
      }

      if (getBridge() == null) {
        return;
      }
      WebView webView = getBridge().getWebView();
      if (webView == null) {
        return;
      }

      WebSettings settings = webView.getSettings();
      settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
      settings.setAllowFileAccess(false);
      settings.setAllowContentAccess(false);
      settings.setSaveFormData(false);
      try {
        settings.setSavePassword(false);
      } catch (Exception e) {
      }
      settings.setJavaScriptCanOpenWindowsAutomatically(false);
      settings.setSupportMultipleWindows(false);
      settings.setSupportZoom(false);
      settings.setBuiltInZoomControls(false);
      settings.setDisplayZoomControls(false);
      settings.setGeolocationEnabled(false);
      settings.setMediaPlaybackRequiresUserGesture(true);

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
      }

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        try {
          settings.setSafeBrowsingEnabled(true);
        } catch (Exception e) {
        }
      }

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
      }

      CookieManager cookies = CookieManager.getInstance();
      cookies.setAcceptCookie(false);
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
        cookies.setAcceptThirdPartyCookies(webView, false);
      }

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
        try {
          ServiceWorkerWebSettings sw = ServiceWorkerController.getInstance().getServiceWorkerWebSettings();
          sw.setCacheMode(WebSettings.LOAD_NO_CACHE);
          sw.setAllowContentAccess(false);
          sw.setAllowFileAccess(false);
        } catch (Exception e) {
        }
      }
    } catch (Exception e) {
    }
  }

  private void deleteRecursively(File f) {
    try {
      if (f == null || !f.exists()) {
        return;
      }

      if (f.isDirectory()) {
        File[] children = f.listFiles();
        if (children != null) {
          for (File c : children) {
            deleteRecursively(c);
          }
        }
      }

      f.delete();
    } catch (Exception e) {
    }
  }

  private void purgeWebViewDiskArtifactsBestEffort() {
    try {
      File cacheDir = getCacheDir();
      deleteRecursively(new File(cacheDir, "WebView"));
      deleteRecursively(new File(cacheDir, "Crash Reports"));
    } catch (Exception e) {
    }

    try {
      File dataDir;
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
        dataDir = getDataDir();
      } else {
        dataDir = new File(getApplicationInfo().dataDir);
      }

      deleteRecursively(new File(dataDir, "app_webview"));

      File prefsDir = new File(dataDir, "shared_prefs");
      deleteRecursively(new File(prefsDir, "WebViewChromiumPrefs.xml"));
      deleteRecursively(new File(prefsDir, "AwOriginVisitLoggerPrefs.xml"));
    } catch (Exception e) {
    }
  }

  public void clearWebViewData() {
    try {
      WebView webView = null;
      try {
        if (getBridge() != null) {
          webView = getBridge().getWebView();
        }
      } catch (Exception e) {
      }

      if (webView != null) {
        try {
          webView.onPause();
          webView.pauseTimers();
        } catch (Exception e) {
        }

        webView.clearCache(true);
        webView.clearHistory();
        webView.clearFormData();
      }

      try {
        WebStorage.getInstance().deleteAllData();
      } catch (Exception e) {
      }

      CookieManager cookies = CookieManager.getInstance();
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
        cookies.removeAllCookies(null);
        cookies.flush();
      } else {
        cookies.removeAllCookie();
      }

      purgeWebViewDiskArtifactsBestEffort();
    } catch (Exception e) {
    }
  }
}
