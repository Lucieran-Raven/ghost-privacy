// Public (non-secret) runtime configuration.
// IMPORTANT: Values here are publishable and safe to ship to the browser.

export const PUBLIC_SUPABASE_URL: string =
  import.meta.env.VITE_SUPABASE_URL || "https://ppglgiajsaonrpcocdae.supabase.co";

export const PUBLIC_SUPABASE_PUBLISHABLE_KEY: string =
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY ||
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBwZ2xnaWFqc2FvbnJwY29jZGFlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjU4MjkyODcsImV4cCI6MjA4MTQwNTI4N30.g6g4ICTr38nT8dphnSHilJZ-sQuaS8sQ3RVdd0qwph0";
