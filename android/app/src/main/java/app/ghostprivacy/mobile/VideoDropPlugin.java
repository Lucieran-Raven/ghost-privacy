package app.ghostprivacy.mobile;

import android.content.Intent;
import android.content.ContentValues;
import android.os.Build;
import android.net.Uri;
import android.provider.MediaStore;
import android.os.ParcelFileDescriptor;
import android.content.ContentResolver;
import android.os.Environment;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.File;
import java.io.OutputStream;
import java.util.HashMap;
import android.util.Base64;
import java.io.InputStream;

@CapacitorPlugin(name = "VideoDrop")
public class VideoDropPlugin extends Plugin {
  private final HashMap<String, String> fileNames = new HashMap<>();

  private static String sanitizeCacheFileName(String fileName) {
    if (fileName == null) return "file.bin";
    String trimmed = fileName.trim();
    if (trimmed.length() == 0) return "file.bin";

    StringBuilder out = new StringBuilder(Math.min(trimmed.length(), 128));
    for (int i = 0; i < trimmed.length() && out.length() < 128; i++) {
      char c = trimmed.charAt(i);
      boolean ok =
        (c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        c == '-' || c == '_' || c == '.';
      if (ok) out.append(c);
    }

    // Avoid hidden/empty names
    while (out.length() > 0 && out.charAt(0) == '.') out.deleteCharAt(0);
    while (out.length() > 0 && out.charAt(out.length() - 1) == '.') out.deleteCharAt(out.length() - 1);
    if (out.length() == 0) return "file.bin";
    return out.toString();
  }

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
    String fileName = fileNames.get(id);
    String safeName = sanitizeCacheFileName(fileName);
    return new File(dir, "ghost_drop_" + id + "_" + safeName);
  }

  @PluginMethod
  public void start(PluginCall call) {
    try {
      String id = call.getString("id", "");
      if (!isSafeId(id)) {
        call.reject("invalid id");
        return;
      }

      String fileName = call.getString("fileName", "secure_video.mp4");
      if (fileName == null || fileName.trim().length() == 0) {
        fileName = "secure_video.mp4";
      }
      fileNames.put(id, fileName);

      File f = fileForId(id);
      try {
        if (f.exists()) {
          // Best effort cleanup.
          //noinspection ResultOfMethodCallIgnored
          f.delete();
        }
      } catch (Exception ignored) {
      }

      try (ParcelFileDescriptor pfd = ParcelFileDescriptor.open(
        f,
        ParcelFileDescriptor.MODE_CREATE |
          ParcelFileDescriptor.MODE_TRUNCATE |
          ParcelFileDescriptor.MODE_WRITE_ONLY
      ); OutputStream out = new ParcelFileDescriptor.AutoCloseOutputStream(pfd)) {
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
        bytes = Base64.decode(chunkBase64, Base64.DEFAULT);
      } catch (Exception e) {
        call.reject("invalid base64", e);
        return;
      }

      File f = fileForId(id);

      try (ParcelFileDescriptor pfd = ParcelFileDescriptor.open(
        f,
        ParcelFileDescriptor.MODE_CREATE |
          ParcelFileDescriptor.MODE_APPEND |
          ParcelFileDescriptor.MODE_WRITE_ONLY
      ); OutputStream out = new ParcelFileDescriptor.AutoCloseOutputStream(pfd)) {
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

      String fileName = fileNames.get(id);
      if (fileName == null || fileName.trim().length() == 0) {
        fileName = "secure_video.mp4";
      }

      File f = fileForId(id);
      if (!f.exists()) {
        call.reject("file not found");
        return;
      }

      Uri openedUri = null;
      boolean savedToDownloads = false;
      try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
          ContentResolver resolver = getContext().getContentResolver();
          Uri collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI;
          String relBase = Environment.DIRECTORY_DOWNLOADS;
          try {
            if (mimeType != null) {
              String mt = mimeType.toLowerCase();
              if (mt.startsWith("image/")) {
                collection = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
                relBase = Environment.DIRECTORY_PICTURES;
              } else if (mt.startsWith("video/")) {
                collection = MediaStore.Video.Media.EXTERNAL_CONTENT_URI;
                relBase = Environment.DIRECTORY_MOVIES;
              }
            }
          } catch (Exception ignored) {
          }

          ContentValues values = new ContentValues();
          values.put(MediaStore.MediaColumns.DISPLAY_NAME, fileName);
          values.put(MediaStore.MediaColumns.MIME_TYPE, mimeType);
          values.put(MediaStore.MediaColumns.RELATIVE_PATH, relBase + "/GhostPrivacy");
          values.put(MediaStore.MediaColumns.IS_PENDING, 1);

          Uri uri = resolver.insert(collection, values);
          if (uri == null) {
            throw new RuntimeException("insert failed");
          }

          try (OutputStream out = resolver.openOutputStream(uri);
               ParcelFileDescriptor inPfd = ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
               InputStream in = new ParcelFileDescriptor.AutoCloseInputStream(inPfd)) {
            if (out == null) {
              throw new RuntimeException("openOutputStream failed");
            }
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
              out.write(buf, 0, n);
            }
            out.flush();
          }

          try {
            ContentValues done = new ContentValues();
            done.put(MediaStore.MediaColumns.IS_PENDING, 0);
            resolver.update(uri, done, null, null);
          } catch (Exception ignored) {
          }

          openedUri = uri;
          savedToDownloads = true;

          try {
            // Best-effort cleanup of cached source file after persisting to Downloads.
            //noinspection ResultOfMethodCallIgnored
            f.delete();
          } catch (Exception ignored) {
          }
        }
      } catch (Exception e) {
        try {
          if (openedUri != null) {
            // Best effort cleanup if we created a partial MediaStore entry.
            //noinspection ResultOfMethodCallIgnored
            getContext().getContentResolver().delete(openedUri, null, null);
          }
        } catch (Exception ignored) {
        }
        openedUri = null;
        savedToDownloads = false;
      }

      if (openedUri == null) {
        call.reject("save failed");
        return;
      }

      try {
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setDataAndType(openedUri, mimeType);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        getContext().startActivity(intent);
      } catch (Exception ignored) {
      }

      JSObject ret = new JSObject();
      ret.put("ok", true);
      ret.put("uri", openedUri.toString());
      ret.put("savedToDownloads", savedToDownloads);
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

      fileNames.remove(id);

      JSObject ret = new JSObject();
      ret.put("ok", true);
      call.resolve(ret);
    } catch (Exception e) {
      call.reject("purge failed", e);
    }
  }
}
