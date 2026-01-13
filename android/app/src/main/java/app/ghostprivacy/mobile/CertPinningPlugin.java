package app.ghostprivacy.mobile;

import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.HttpsURLConnection;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "CertPinning")
public class CertPinningPlugin extends Plugin {
  private String computeSpkiPinBase64(X509Certificate cert) throws Exception {
    byte[] spki = cert.getPublicKey().getEncoded();
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] digest = md.digest(spki);
    return android.util.Base64.encodeToString(digest, android.util.Base64.NO_WRAP);
  }

  @PluginMethod
  public void verifyCertPinning(PluginCall call) {
    JSArray targets = call.getArray("targets");
    if (targets == null) {
      call.reject("missing targets");
      return;
    }

    JSArray results = new JSArray();

    for (int i = 0; i < targets.length(); i++) {
      JSObject t = targets.getJSObject(i);
      if (t == null) continue;

      String host = t.getString("host", "");
      JSArray pins = t.getArray("pins");
      ArrayList<String> pinList = new ArrayList<>();
      if (pins != null) {
        for (int p = 0; p < pins.length(); p++) {
          try {
            String pin = pins.getString(p);
            if (pin != null && pin.length() > 0) pinList.add(pin);
          } catch (Exception e) {
          }
        }
      }

      JSObject r = new JSObject();
      r.put("host", host);

      if (host == null || host.length() == 0) {
        r.put("status", "error");
        results.put(r);
        continue;
      }

      if (pinList.size() == 0) {
        r.put("status", "skipped");
        results.put(r);
        continue;
      }

      HttpsURLConnection conn = null;
      try {
        URL url = new URL("https://" + host + "/");
        conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(7000);
        conn.setReadTimeout(7000);
        conn.setUseCaches(false);
        conn.setRequestMethod("HEAD");

        conn.connect();

        Certificate[] certs = conn.getServerCertificates();
        if (certs == null || certs.length == 0 || !(certs[0] instanceof X509Certificate)) {
          r.put("status", "error");
          results.put(r);
          continue;
        }

        X509Certificate leaf = (X509Certificate) certs[0];
        String observed = computeSpkiPinBase64(leaf);
        r.put("observedPin", observed);

        boolean match = false;
        for (String pin : pinList) {
          if (observed.equals(pin)) {
            match = true;
            break;
          }
        }

        r.put("status", match ? "ok" : "mismatch");
        results.put(r);
      } catch (Exception e) {
        r.put("status", "error");
        results.put(r);
      } finally {
        try {
          if (conn != null) conn.disconnect();
        } catch (Exception e) {
        }
      }
    }

    JSObject ret = new JSObject();
    ret.put("results", results);
    call.resolve(ret);
  }
}
