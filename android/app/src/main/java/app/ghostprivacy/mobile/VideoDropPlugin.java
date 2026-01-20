package app.ghostprivacy.mobile;

import android.content.Intent;
import android.net.Uri;

import androidx.core.content.FileProvider;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.File;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Base64;

@CapacitorPlugin(name = "VideoDrop")
public class VideoDropPlugin extends Plugin {
  private static boolean isSafeId(String id) {
    if (id == null) return false;
    if (id.length() < 1 || id.length() > 128) return false;
    for (int i = 0; i < id.length(); i++) {
      char c = id.charAt(i);
      boolean ok =
        (c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        c == '-' || c == '_' ;
      if (!ok) return false;
    }
    return true;
  }

  private File fileForId(String id) {
    File dir = getContext().getCacheDir();
    return new File(dir, "ghost_video_drop_" + id + ".mp4");
  }

  @PluginMethod
  public void start(PluginCall call) {
    try {
      String id = call.getString("id", "");
      if (!isSafeId(id)) {
        call.reject("invalid id");
        return;
      }

      File f = fileForId(id);
      try {
        if (f.exists()) {
          // Best effort cleanup.
          //noinspection ResultOfMethodCallIgnored
          f.delete();
        }
      } catch (Exception ignored) {
      }

      try (OutputStream out = Files.newOutputStream(
        f.toPath(),
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE
      )) {
        out.flush();
      }

      JSObject ret = new JSObject();
      ret.put("ok", true);
      call.resolve(ret);
    } catch (Exception e) {
      call.reject("start failed", e);
    }
  }

  @PluginMethod
  public void append(PluginCall call) {
    try {
      String id = call.getString("id", "");
      if (!isSafeId(id)) {
        call.reject("invalid id");
        return;
      }
      String chunkBase64 = call.getString("chunkBase64", "");
      if (chunkBase64 == null || chunkBase64.length() == 0) {
        call.reject("empty chunk");
        return;
      }
      if (chunkBase64.length() > 256 * 1024) {
        call.reject("chunk too large");
        return;
      }

      byte[] bytes;
      try {
        bytes = Base64.getDecoder().decode(chunkBase64);
      } catch (Exception e) {
        call.reject("invalid base64", e);
        return;
      }

      File f = fileForId(id);
      try (OutputStream out = Files.newOutputStream(
        f.toPath(),
        StandardOpenOption.CREATE,
        StandardOpenOption.APPEND,
        StandardOpenOption.WRITE
      )) {
        out.write(bytes);
        out.flush();
      }

      // Best-effort zero.
      try {
        for (int i = 0; i < bytes.length; i++) bytes[i] = 0;
      } catch (Exception ignored) {
      }

      JSObject ret = new JSObject();
      ret.put("ok", true);
      call.resolve(ret);
    } catch (Exception e) {
      call.reject("append failed", e);
    }
  }

  @PluginMethod
  public void finishAndOpen(PluginCall call) {
    try {
      String id = call.getString("id", "");
      if (!isSafeId(id)) {
        call.reject("invalid id");
        return;
      }
      String mimeType = call.getString("mimeType", "video/mp4");
      if (mimeType == null || mimeType.length() == 0) {
        mimeType = "video/mp4";
      }

      File f = fileForId(id);
      if (!f.exists()) {
        call.reject("file not found");
        return;
      }

      String authority = getContext().getPackageName() + ".fileprovider";
      Uri uri = FileProvider.getUriForFile(getContext(), authority, f);

      Intent intent = new Intent(Intent.ACTION_VIEW);
      intent.setDataAndType(uri, mimeType);
      intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
      intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

      getContext().startActivity(intent);

      JSObject ret = new JSObject();
      ret.put("ok", true);
      call.resolve(ret);
    } catch (Exception e) {
      call.reject("open failed", e);
    }
  }

  @PluginMethod
  public void purge(PluginCall call) {
    try {
      String id = call.getString("id", "");
      if (!isSafeId(id)) {
        call.reject("invalid id");
        return;
      }

      File f = fileForId(id);
      try {
        if (f.exists()) {
          //noinspection ResultOfMethodCallIgnored
          f.delete();
        }
      } catch (Exception ignored) {
      }

      JSObject ret = new JSObject();
      ret.put("ok", true);
      call.resolve(ret);
    } catch (Exception e) {
      call.reject("purge failed", e);
    }
  }
}
