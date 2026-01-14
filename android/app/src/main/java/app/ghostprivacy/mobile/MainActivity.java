package app.ghostprivacy.mobile;

import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Bundle;
import android.webkit.CookieManager;
import android.webkit.WebSettings;
import android.webkit.WebStorage;
import android.webkit.WebView;
import java.io.File;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    try {
      registerPlugin(AppSettingsPlugin.class);
      registerPlugin(CertPinningPlugin.class);
      registerPlugin(WebViewCleanupPlugin.class);
      registerPlugin(BuildIntegrityPlugin.class);
    } catch (Exception e) {
    }
    hardenWebView();
  }

  @Override
  public void onStop() {
    super.onStop();
    clearWebViewData();
  }

  @Override
  public void onDestroy() {
    super.onDestroy();
    clearWebViewData();
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
      settings.setJavaScriptCanOpenWindowsAutomatically(false);
      settings.setSupportMultipleWindows(false);

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

  private void clearDomStorageBestEffort() {
    try {
      if (getBridge() == null) {
        return;
      }

      getBridge().eval(
        "(async () => {\n" +
          "try { localStorage.clear(); } catch (_) {}\n" +
          "try { sessionStorage.clear(); } catch (_) {}\n" +
          "try {\n" +
            "if (typeof indexedDB !== 'undefined' && indexedDB.databases) {\n" +
              "const dbs = await indexedDB.databases();\n" +
              "for (const db of dbs) { if (db && db.name) indexedDB.deleteDatabase(db.name); }\n" +
            "}\n" +
          "} catch (_) {}\n" +
          "try {\n" +
            "if (typeof caches !== 'undefined' && caches.keys) {\n" +
              "const keys = await caches.keys();\n" +
              "for (const k of keys) { await caches.delete(k); }\n" +
            "}\n" +
          "} catch (_) {}\n" +
          "try {\n" +
            "if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {\n" +
              "const regs = await navigator.serviceWorker.getRegistrations();\n" +
              "for (const r of regs) { await r.unregister(); }\n" +
            "}\n" +
          "} catch (_) {}\n" +
        "})();",
        null
      );
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

        try {
          clearDomStorageBestEffort();
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
