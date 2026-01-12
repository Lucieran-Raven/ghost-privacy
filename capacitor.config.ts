const serverUrlRaw = process.env.CAPACITOR_SERVER_URL;
const allowHttpDev = process.env.CAPACITOR_ALLOW_HTTP_DEV === '1';

function getSafeServerUrl(input: string | undefined): string | undefined {
  if (!input) return undefined;
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return undefined;
  }

  if (url.protocol === 'https:') {
    return url.toString();
  }

  if (allowHttpDev && url.protocol === 'http:') {
    const host = url.hostname;
    if (host === 'localhost' || host === '127.0.0.1') {
      return url.toString();
    }
  }

  return undefined;
}

const serverUrl = getSafeServerUrl(serverUrlRaw);

const config = {
  appId: 'app.ghostprivacy.mobile',
  appName: 'Ghost Privacy',
  webDir: 'dist',
  ...(serverUrl
    ? {
        server: {
          url: serverUrl,
          cleartext: false
        }
      }
    : {}),
  android: {
    allowMixedContent: false
  }
};

export default config;
