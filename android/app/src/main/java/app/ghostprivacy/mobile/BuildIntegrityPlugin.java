package app.ghostprivacy.mobile;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.security.MessageDigest;

@CapacitorPlugin(name = "BuildIntegrity")
public class BuildIntegrityPlugin extends Plugin {
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

  @PluginMethod
  public void verifyBuildIntegrity(PluginCall call) {
    JSObject ret = new JSObject();
    try {
      String expected = "";
      try {
        expected = BuildConfig.EXPECTED_SIGNING_CERT_SHA256;
      } catch (Exception e) {
        expected = "";
      }

      if (expected == null || expected.length() == 0) {
        ret.put("status", "skipped");
        call.resolve(ret);
        return;
      }

      PackageManager pm = getContext().getPackageManager();
      String pkg = getContext().getPackageName();

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
        ret.put("status", "error");
        call.resolve(ret);
        return;
      }

      String observed = sha256Hex(certBytes);
      ret.put("observed", observed);
      ret.put("expected", expected);

      boolean ok = observed.equalsIgnoreCase(expected);
      ret.put("status", ok ? "verified" : "unverified");
      call.resolve(ret);
    } catch (Exception e) {
      ret.put("status", "error");
      call.resolve(ret);
    }
  }

  @PluginMethod
  public void panicExit(PluginCall call) {
    try {
      try {
        if (getActivity() != null) {
          getActivity().finishAndRemoveTask();
        }
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
    } finally {
      call.resolve(new JSObject());
    }
  }
}
