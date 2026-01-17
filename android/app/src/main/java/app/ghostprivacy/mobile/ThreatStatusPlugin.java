package app.ghostprivacy.mobile;

import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Debug;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.File;

@CapacitorPlugin(name = "ThreatStatus")
public class ThreatStatusPlugin extends Plugin {
  private static boolean isEmulatorLikely() {
    try {
      String fingerprint = Build.FINGERPRINT;
      String model = Build.MODEL;
      String manufacturer = Build.MANUFACTURER;
      String brand = Build.BRAND;
      String device = Build.DEVICE;
      String product = Build.PRODUCT;

      if (fingerprint != null) {
        String f = fingerprint.toLowerCase();
        if (f.startsWith("generic") || f.contains("vbox") || f.contains("test-keys")) return true;
      }
      if (model != null) {
        String m = model.toLowerCase();
        if (m.contains("google_sdk") || m.contains("emulator") || m.contains("android sdk built for x86")) return true;
      }
      if (manufacturer != null && manufacturer.toLowerCase().contains("genymotion")) return true;
      if (brand != null && brand.toLowerCase().startsWith("generic")) return true;
      if (device != null && device.toLowerCase().startsWith("generic")) return true;
      if (product != null) {
        String p = product.toLowerCase();
        if (p.contains("sdk") || p.contains("emulator") || p.contains("simulator")) return true;
      }
      return false;
    } catch (Exception e) {
      return false;
    }
  }

  private static boolean isRootLikely() {
    try {
      String tags = Build.TAGS;
      if (tags != null && tags.contains("test-keys")) return true;

      String[] paths = new String[] {
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su"
      };
      for (String p : paths) {
        try {
          if (new File(p).exists()) return true;
        } catch (Exception ignored) {
        }
      }
      return false;
    } catch (Exception e) {
      return false;
    }
  }

  @PluginMethod
  public void getThreatStatus(PluginCall call) {
    JSObject ret = new JSObject();
    try {
      boolean debuggable = false;
      try {
        ApplicationInfo ai = getContext().getApplicationInfo();
        debuggable = (ai != null) && ((ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
      } catch (Exception e) {
        debuggable = false;
      }

      boolean debuggerAttached = false;
      try {
        debuggerAttached = Debug.isDebuggerConnected();
      } catch (Exception e) {
        debuggerAttached = false;
      }

      boolean emulatorLikely = isEmulatorLikely();
      boolean rootLikely = isRootLikely();

      ret.put("platform", "android");
      ret.put("debuggable", debuggable);
      ret.put("debuggerAttached", debuggerAttached);
      ret.put("emulatorLikely", emulatorLikely);
      ret.put("rootLikely", rootLikely);

      String status = (debuggable || emulatorLikely || rootLikely) ? "warn" : "ok";
      ret.put("status", status);

      call.resolve(ret);
    } catch (Exception e) {
      ret.put("platform", "android");
      ret.put("status", "error");
      call.resolve(ret);
    }
  }
}
