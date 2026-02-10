package app.ghostprivacy.mobile;

import android.app.Activity;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "WebViewCleanup")
public class WebViewCleanupPlugin extends Plugin {
  @PluginMethod
  public void clearWebViewData(PluginCall call) {
    try {
      final Activity activity = getActivity();
      if (!(activity instanceof MainActivity)) {
        call.reject("MainActivity not available");
        return;
      }

      activity.runOnUiThread(() -> {
        try {
          ((MainActivity) activity).clearWebViewData();
          JSObject ret = new JSObject();
          ret.put("ok", true);
          call.resolve(ret);
        } catch (Exception e) {
          call.reject("Failed to clear WebView data", e);
        }
      });
    } catch (Exception e) {
      call.reject("Failed to clear WebView data", e);
    }
  }
}
