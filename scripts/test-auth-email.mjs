/**
 * Smoke-test Supabase signup + confirmation email delivery.
 * Usage: npm run test:auth-email -- you@example.com
 */
const SUPABASE_URL = 'https://haspklehikocqswmgmtk.supabase.co';
const ANON_KEY = 'sb_publishable_O1qHjWdSJ1hZYraL8mmxYQ_CPRr0Sv6';
const REDIRECT = process.env.AUTH_REDIRECT || 'http://localhost:8000/index.html';

const email = process.argv[2];
if (!email || !email.includes('@')) {
  console.error('Usage: npm run test:auth-email -- your@email.com');
  process.exit(1);
}

const password = 'TestPass-' + Date.now().toString(36);

const res = await fetch(`${SUPABASE_URL}/auth/v1/signup`, {
  method: 'POST',
  headers: {
    apikey: ANON_KEY,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    email,
    password,
    data: { requested_role: 'user' },
    options: { emailRedirectTo: REDIRECT },
  }),
});

const text = await res.text();
let body;
try { body = JSON.parse(text); } catch { body = { raw: text }; }

if (!res.ok) {
  const msg = body?.msg || body?.message || body?.error_description || text;
  console.error(`FAIL (${res.status}): ${msg}`);
  if (/error sending confirmation email/i.test(String(msg))) {
    console.error('\n→ Use Supabase built-in mail: Authentication → SMTP → disable custom SMTP.');
    console.error('  Then check Providers → Email (Confirm ON) and URL Configuration redirect URLs.');
  }
  process.exit(1);
}

console.log('OK: signup accepted — check the inbox for', email);
console.log('   Redirect URL used:', REDIRECT);
if (body?.user && !body?.session) {
  console.log('   (Confirm email is ON — user must click the link before sign-in.)');
} else if (body?.session) {
  console.log('   (Confirm email is OFF — user can sign in immediately.)');
}
