const serverUrl = process.env.CAPACITOR_SERVER_URL;

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
