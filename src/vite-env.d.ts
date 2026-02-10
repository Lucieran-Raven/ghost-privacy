/// <reference types="vite/client" />

interface Window {
  Capacitor?: {
    isNativePlatform?: () => boolean;
  };
}

interface ImportMetaEnv {
  readonly VITE_ENABLE_RESEARCH_FEATURES?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
