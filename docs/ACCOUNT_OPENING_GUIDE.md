# ImpactLens — Account Opening Guide

Step-by-step instructions to open an account and sign in to **ImpactLens** (local or [production](https://impactlens-assessment.vercel.app)). Includes **pre-seeded test credentials** for demos and grading.

> **Demo passwords only.** These accounts are for PLM ISMS assessment / lab use. Do not reuse these passwords in production systems.

---

## 1. Where to sign in

| Environment | URL |
|-------------|-----|
| **Production (Vercel)** | https://impactlens-assessment.vercel.app |
| **Local dev** | http://localhost:8000 (after `npm start`) |

Both environments use the **same Supabase project** (`haspklehikocqswmgmtk`). Accounts work on localhost and Vercel once created in Auth.

---

## 2. Pre-seeded test accounts (recommended for demos)

Run **`supabase/hotfix_demo_accounts.sql`** once in the [Supabase SQL Editor](https://supabase.com/dashboard/project/haspklehikocqswmgmtk/sql/new). It creates three **auto-approved**, **email-verified** users — no inbox step required.

| Role | Email | Password | What you can do |
|------|-------|----------|-----------------|
| **Admin (CISO)** | `admin@plm.edu.ph` | `IAS_AdminAccount2526@` | Full dashboard, approve assets & users, 12-sheet Excel export, reporting |
| **Info Sec** | `infosec@plm.edu.ph` | `IAS_InfosecAccount2526@` | Draft queue, risk profiling, pending submissions, 9-sheet export, approve Standard Users |
| **Standard User** | `user@plm.edu.ph` | `IAS_UserAccount2526@` | Add Draft assets, CSV import (sheet 1), read-only approved register |

### Quick sign-in (test accounts)

1. Open the app URL (table above).
2. On the **role tiles**, click the role that matches your account (**Standard User**, **Info Sec**, or **Admin (CISO)**).
3. Choose **SIGN IN** (not Register).
4. Enter the **email** and **password** from the table.
5. Click **Authenticate**.

**Important:** Pick the role tile that matches the account. Example: use the **Admin (CISO)** tile when signing in as `admin@plm.edu.ph`.

If you see *Invalid email or password*, re-run `hotfix_demo_accounts.sql` or confirm the user exists under **Supabase → Authentication → Users**.

---

## 3. One-time setup (project maintainer)

Before anyone can sign in, the database must be bootstrapped:

| Step | Script | Purpose |
|------|--------|---------|
| 1 | `supabase/master_setup.sql` | Tables, RLS, triggers, 117-asset seed |
| 2 | `supabase/hotfix_demo_accounts.sql` | Creates the three test accounts above |

Supabase **Auth → URL Configuration** must include:

- `http://localhost:8000/**`
- `https://impactlens-assessment.vercel.app/**`

See **README.md → Quick start** for email provider settings if you register new users (not using the hotfix).

---

## 4. Opening a new account (self-registration)

Use this path for **real** users who are not on the demo hotfix list.

### 4.1 Register

1. Open the app → choose your intended **role tile**.
2. Click **REGISTER**.
3. Enter your **organizational email** (any valid address Supabase can mail).
4. Password **minimum 8 characters**; confirm it matches.
5. Click **Create Account**.

### 4.2 Verify email

1. Check your inbox (and spam) for the Supabase confirmation link.
2. Click the link — you should return to ImpactLens with a message to sign in.
3. If the link fails, add the correct **Redirect URL** in Supabase (section 3 above).

Troubleshooting:

```bash
npm run test:auth-email -- your.email@example.com
```

### 4.3 Wait for role approval

| Requested role | Approved by | Status until approved |
|----------------|-------------|------------------------|
| **Standard User** | Info Sec or Admin | *Pending approval* screen |
| **Info Sec** | Admin (CISO) | *Pending approval* screen |
| **Admin** | — | Only `admin@plm.edu.ph` is auto-promoted on verify; others need manual promotion in Supabase |

After approval, sign in again with **SIGN IN** on the matching role tile.

### 4.4 Approving new users (Info Sec / Admin)

1. Sign in as **Info Sec** or **Admin**.
2. Open **Account Approvals** in the sidebar.
3. **Pending** tab → **Approve** or **Reject** (with reason).

---

## 5. Creating the Admin account without the hotfix

If you prefer not to run the full demo hotfix:

**Option A — Supabase Dashboard**

1. **Authentication → Users → Add user**
2. Email: `admin@plm.edu.ph`
3. Password: choose a strong password (or use `IAS_AdminAccount2526@` for demos)
4. Enable **Auto Confirm User**
5. The `master_setup.sql` trigger assigns **admin** role and **active** status on first profile sync

**Option B — App registration**

1. Register as Admin tile with `admin@plm.edu.ph`
2. Verify email from inbox
3. Trigger auto-promotes this address to **active admin** (built into `master_setup.sql`)

---

## 6. Common issues

| Symptom | Fix |
|---------|-----|
| Invalid email or password (demo users) | Run `supabase/hotfix_demo_accounts.sql` |
| Email not confirmed | Open verification link; or use hotfix accounts (pre-confirmed) |
| Stuck after old session | Click **Reset session** on the login screen |
| Pending approval forever | Info Sec/Admin must approve under **Account Approvals** |
| Empty dashboard / no assets | Run `supabase/master_setup.sql` (asset seed) |
| Wrong menus after login | Sign out; pick the correct **role tile**; sign in again |

---

## 7. Credential reference (copy-paste)

```
Admin (CISO)     admin@plm.edu.ph      IAS_AdminAccount2526@
Info Sec         infosec@plm.edu.ph    IAS_InfosecAccount2526@
Standard User    user@plm.edu.ph       IAS_UserAccount2526@
```

**Requires:** `supabase/hotfix_demo_accounts.sql` executed on the Supabase project.

---

## Related docs

- **README.md** — Install, Supabase bootstrap, deployment
- **docs/USER_GUIDE.md** — Day-to-day assessor workflows
- **docs/DEMO_SCRIPT.md** — Live presentation walkthrough

---

*PLM ISMS — ImpactLens v2.1 — May 2026*
