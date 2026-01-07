// Public (non-secret) runtime configuration.
// IMPORTANT: Values here are publishable and safe to ship to the browser.

export const PUBLIC_SUPABASE_URL: string =
  import.meta.env.VITE_SUPABASE_URL || "https://muirdvibzicpedfmqdrf.supabase.co";

export const PUBLIC_SUPABASE_PUBLISHABLE_KEY: string =
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY ||
  "sb_publishable_QG9lFeQsP9F-xAllaVncfg_ov4K1OMU";
