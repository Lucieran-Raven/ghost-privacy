package app.ghostprivacy.mobile;

import android.os.Build;
import android.os.Bundle;
import android.webkit.CookieManager;
import android.webkit.WebSettings;
import android.webkit.WebStorage;
import android.webkit.WebView;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    hardenWebView();
  }

  @Override
  public void onStop() {
    clearWebViewData();
    super.onStop();
  }

  @Override
  public void onDestroy() {
    clearWebViewData();
    super.onDestroy();
  }

  private void hardenWebView() {
    try {
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

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
      }

      CookieManager cookies = CookieManager.getInstance();
      cookies.setAcceptCookie(true);
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
        cookies.setAcceptThirdPartyCookies(webView, false);
      }
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

  private void clearWebViewData() {
    try {
      if (getBridge() == null) {
        return;
      }
      WebView webView = getBridge().getWebView();
      if (webView == null) {
        return;
      }

      clearDomStorageBestEffort();

      webView.clearCache(true);
      webView.clearHistory();
      webView.clearFormData();

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
    } catch (Exception e) {
    }
  }
}
