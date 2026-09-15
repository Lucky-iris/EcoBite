/* ============================================================
   EcoBite — shared Supabase client
   Loaded after the supabase-js CDN script on every page that
   needs accounts (signup.html, signin.html, home.html).
   The publishable key is safe to expose in client code — it's
   the browser-facing key, not the secret one.
   ============================================================ */

const SUPABASE_URL = 'https://njtdiezoglhmlseqvgbg.supabase.co';
const SUPABASE_KEY = 'sb_publishable_DlAiwzBtnAepQS4Zut76VQ_RNHjrWAe';

const sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
