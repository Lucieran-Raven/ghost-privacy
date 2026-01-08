package app.ghostprivacy.mobile;

import android.content.Intent;
import android.net.Uri;
import android.provider.Settings;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "AppSettings")
public class AppSettingsPlugin extends Plugin {
  @PluginMethod
  public void openAppSettings(PluginCall call) {
    try {
      String packageName = getContext().getPackageName();
      Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
      intent.setData(Uri.parse("package:" + packageName));
      intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

      getContext().startActivity(intent);

      JSObject ret = new JSObject();
      ret.put("ok", true);
      call.resolve(ret);
    } catch (Exception e) {
      call.reject("Failed to open app settings", e);
    }
  }
}
