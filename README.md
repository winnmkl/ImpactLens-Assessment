# ImpactLens — Multi-Role Risk Assessment Platform

A standards-aligned, multi-tenant Information Security Risk Assessment (IAR) platform built for the **Pamantasan ng Lungsod ng Maynila (PLM) ISMS**. Implements the full NIST SP 800-30 Rev. 1 risk-management lifecycle with ISO/IEC 27001:2022, CIS Controls v8, SOC 2 Trust Services Criteria, PCI-DSS v4.0 and RA 10173 (Philippine Data Privacy Act) compliance baked in.

> **v2.0 — major rewrite (May 2026).** The v1 single-user prototype has been replaced by a 3-tier role-based application backed by Supabase Auth, PostgreSQL triggers, mandatory-control floors and a **9-sheet (Info Sec) / 12-sheet (Admin)** ExcelJS audit export (includes MBSS & firewall review sheets). If you are looking for the localStorage prototype, check the v1 tag.

---

## Table of Contents
1. [What's new in v2.0](#whats-new-in-v20)
2. [Architecture](#architecture)
3. [Quick start](#quick-start)
4. [Roles & permissions](#roles--permissions)
5. [Risk-math engine](#risk-math-engine)
6. [Compliance mapping](#compliance-mapping)
7. [Workflow](#workflow)
8. [Reject / Delete with reason capture](#reject--delete-with-reason-capture)
9. [Excel export](#excel-export)
10. [Project structure](#project-structure)
11. [Operations](#operations)
12. [Browser support](#browser-support)
13. [References](#references)

---

## What's new in v2.0

| Area | v1 (prototype) | v2 (current) |
|---|---|---|
| **Auth** | None / single user | Supabase Auth with real email verification + DB trigger for `user_profiles` |
| **Roles** | Single | Standard User / Info Sec / Admin (CISO) — RBAC at UI, API and RLS layers |
| **Workflow** | Direct save | Draft → Pending Approval → Approved (3-tier with reject reasons) |
| **Storage** | localStorage + AlaSQL | Supabase Postgres (5 tables, RLS-enforced) |
| **Risk math** | Probability × Severity matrix only | NIST SP 800-30 inherent escalations + weighted defense-in-depth + synergy bonuses + saturating diminishing returns + mandatory control floors |
| **Compliance** | Implicit | 13 controls explicitly mapped to NIST CSF 2.0, ISO 27001:2022 Annex A, CIS v8, SOC 2 TSC and PCI-DSS v4.0 with concrete clause IDs |
| **Excel export** | 4 sheets, SheetJS | 9–12 sheets (role-aware), ExcelJS, MBSS + firewall sheets, Rejected & Deleted audit |
| **Notifications** | None | Bell-icon inbox, role-scoped, surfaces approve/reject/delete with reasons |
| **Compliance gap UI** | None | Live "Mandatory Control Gaps" panel with framework citations |
| **Reason capture** | `confirm()`/`prompt()` | Branded modal with curated framework-aware presets + free-text essay |

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        Browser (vanilla JS)                    │
│  index.html → assets/scripts/app.js → assets/styles/main.css   │
│  Vendored: assets/vendor/{supabase,exceljs}.min.js             │
└────────────┬───────────────────────────────────────────────────┘
             │ HTTPS + JWT
             ▼
┌────────────────────────────────────────────────────────────────┐
│                     Supabase (haspklehikocqswmgmtk)            │
│   • auth.users  ──trigger──▶ public.user_profiles              │
│   • Assets / AssetControls / SystemLogs / ReportData           │
│   • RLS policies + SECURITY DEFINER current_user_role()        │
│   • il_inherit() helper + risk-math realignment migration      │
└────────────────────────────────────────────────────────────────┘
```

**Frontend stack:** vanilla ES2020 JavaScript (no framework, single `app.js` ~3.2k lines), CSS custom-properties theme (`main.css` ~1.5k lines), ExcelJS for branded multi-sheet workbooks, Supabase JS for auth + REST. Both vendor libraries are served first-party (`assets/vendor/*.min.js`) to bypass strict-tracking-prevention browsers (Edge / Brave) that otherwise block storage access.

**Server:** lightweight `scripts/serve.mjs` (Node 18+) static server with `Cache-Control: no-store` headers and an explicit `?v=YYYYMMDDx` cache marker on every CSS/JS reference.

---

## Quick start

### Prerequisites
- **Node 18+** (LTS recommended).
- A Supabase project (the production one is `haspklehikocqswmgmtk`).
- A modern browser (Chrome, Edge, Firefox, Safari).

### 1. Clone & install
```bash
git clone https://github.com/winnmkl/ImpactLens-Assessment.git
cd ImpactLens-Assessment
npm install
```

### 2. Bootstrap the Supabase database
Open the Supabase SQL Editor for your project and run the scripts in order:

| Step | File | Purpose | Idempotent? |
|---|---|---|---|
| 1 | `supabase/master_setup.sql` | Tables, RLS, triggers, seed of 57 PLM assets, risk-math realignment, `mbss_json` / `firewall_json` columns | yes |
| 2 *(optional)* | `supabase/hotfix_demo_accounts.sql` | Pre-provision `infosec@plm.edu.ph` / `user@plm.edu.ph` (skip the email-verification step) | yes |
| 3 *(optional)* | `supabase/hotfix_mbss_firewall_columns.sql` | Adds `mbss_json` / `firewall_json` if your DB predates May 2026 `master_setup.sql` | yes |
| 4 *(optional)* | `supabase/hotfix_realign_risk_math.sql` | Re-derives risk math + adds `user_profiles.rejection_reason` for legacy databases | yes |

In **Authentication → Providers** make sure Email is enabled and **Confirm email** is ON. The `master_setup.sql` trigger auto-promotes any verified `admin@plm.edu.ph`, `infosec@plm.edu.ph`, or `user@plm.edu.ph` to an active profile.

#### Email verification (Supabase built-in — default)

ImpactLens uses **Supabase Auth’s built-in email**. You do **not** need Resend unless built-in mail fails at scale or you need a custom From-address.

**“Many domains” — what that means**

| Goal | Supabase built-in |
|---|---|
| Users register with **many recipient domains** (`@gmail.com`, `@plm.edu.ph`, `@yahoo.com`, …) | **Yes** — one project sends confirmations to any valid address (within rate limits). |
| **Many sender / From domains** (`noreply@schoolA.edu`, `noreply@schoolB.edu`, …) | **No** — built-in mail uses Supabase’s sender. Multiple From-domains need custom SMTP or separate projects. |

**Setup (Supabase only)**

1. [Authentication → SMTP](https://supabase.com/dashboard/project/haspklehikocqswmgmtk/auth/smtp) — **Enable custom SMTP: OFF** (use built-in mail). If you turned on custom SMTP with bad credentials earlier, turning it **off** fixes many “Error sending confirmation email” cases.

2. [Providers → Email](https://supabase.com/dashboard/project/haspklehikocqswmgmtk/auth/providers) — Email **ON**, **Confirm email** **ON**.

3. [URL Configuration](https://supabase.com/dashboard/project/haspklehikocqswmgmtk/auth/url-configuration) — **Site URL** `http://localhost:8000`; **Redirect URLs** `http://localhost:8000/**` and `http://localhost:8000/index.html`.

4. [Email templates](https://supabase.com/dashboard/project/haspklehikocqswmgmtk/auth/templates) — **Confirm signup** must include `{{ .ConfirmationURL }}`.

5. Test any recipient domain:
   ```bash
   npm run test:auth-email -- user@gmail.com
   npm run test:auth-email -- user@plm.edu.ph
   ```

6. Register in the app → open the inbox link → sign in.

If mail still fails: check Auth rate limits, spam folder, and that the project is not paused. Custom SMTP (Resend, etc.) is optional for production volume or branding.

### 3. Run the dev server
```bash
npm start
# → http://localhost:8000
```

The server automatically falls back to a free port if 8000 is occupied. Hard-refresh (`Ctrl-F5`) any time `?v=YYYYMMDDx` changes.

### 4. Sign in
- **Master Admin (CISO):** create `admin@plm.edu.ph` from Supabase Dashboard with **Auto Confirm User** *or* register through the app and verify the email.
- **Info Sec:** `infosec@plm.edu.ph` (auto-approved by trigger).
- **Standard User:** `user@plm.edu.ph` (auto-approved by trigger).
- **Anyone else:** registers from the app, waits for Info Sec or Admin to approve their requested role.

---

## Roles & permissions

| Capability | Standard User | Info Sec | Admin (CISO) |
|---|---|---|---|
| Add new asset (saves as Draft) | yes | yes | yes |
| Open a Draft for cybersecurity profiling | — | yes | yes |
| Edit Approved asset (re-triggers approval) | — | yes | yes |
| Submit Pending → CISO | — | yes | implicit |
| Approve / Reject Pending | — | — | yes |
| Reject Draft (discard with reason) | — | yes | yes |
| Delete asset (with reason) | — | yes | yes |
| Approve / Reject user accounts | — | yes (Standard User only) | yes (any role) |
| View Dashboard | — | yes | yes |
| View System Logs | — | yes | yes |
| View Risk Register | — | yes | yes |
| Export Excel | — | 9-sheet workbook | 12-sheet workbook |
| Reporting & Sign-offs page | — | — | yes |

UI elements are filtered three ways:

1. **Section-level** — `showSection()` checks an `allowed` map per role.
2. **Body class** — `data-role` attribute drives CSS rules that hide nav items.
3. **RLS** — Postgres rejects any out-of-scope read/write at the database boundary.

---

## Risk-math engine

The engine in `assets/scripts/app.js` (`calculateRiskMath`, `getApplicableMandatorySets`) is grounded in **NIST SP 800-30 Rev. 1** with the controls vocabulary of **ISO/IEC 27001:2022 Annex A**.

### 1. Inherent risk escalations
Triggered by adversarial likelihood / impact factors before any control reduction is applied.

- Internet-Facing + cyber-external threat → `prob = max(prob+1, 3)` (capped 5).
- PII/SPI + (data leak | DPA breach) threat → `sev = 5`.
- CIA score ≥ 8 + cyber/insider threat → `sev ≥ 4`.
- Asset type = FA + cyber threat → `sev = 5` (PCI-DSS CHD breach is total loss).

### 2. Residual reduction
- Each of the 13 controls has a `(p, s)` weight in `CONTROL_WEIGHTS` (e.g. MFA `{p:1.0, s:0.4}`, Backup `{p:0.0, s:1.2}`).
- Only **threat-relevant** controls (per `controlMap`) contribute to the reduction.
- **Synergy bonuses** stack when paired controls are both active: RBAC+MFA, Backup+IRP, EDR+Firewall, Encryption+Segmentation, Vuln+EDR+IRP.
- **Saturating diminishing-returns curve:** `reduction = (score − 1) × (1 − e^(−rawSum / 2))` — prevents "10 controls = score of 1" gaming.

### 3. Mandatory-control floors
After residual is computed, the engine applies a non-negotiable floor when an asset is missing baseline controls:

| Trigger | Required controls | Floor | Citation |
|---|---|---|---|
| Restricted (CIA ≥ 8) | RBAC, MFA, Backup, Encryption, IRP | Moderate | ISO 27001:2022 §A.5.10–A.5.15 + NIST CSF PR.AA + PR.DS |
| Confidential (CIA 6–7) | RBAC, Encryption, IRP | Moderate | ISO 27001:2022 §A.8.2 + NIST CSF PR.DS |
| FA (PCI-DSS scope) | MFA, Encryption, Vuln Mgmt, Segmentation | **High** | PCI-DSS v4.0 Req 3, 4, 8.4, 11.3, 1.4.4 |
| PII / SPI | Procedures, RBAC, Backup, Encryption | Moderate | RA 10173 §20 + ISO 27701 + GDPR Art. 32 |
| Internet-Facing | Firewall/WAF, Vuln Mgmt, IRP | Moderate | CIS v8 §12 + §17 + NIST PR.IR-01, DE.CM-01 |

A live **Mandatory Control Gaps** panel surfaces every unmet baseline with the framework citation.

### 4. Risk-appetite enforcement
The Treatment Type dropdown is locked to deny `Accept` when:
- Residual = High (ISO 27001:2022 §6.1.3 — outside risk appetite),
- FA + residual ≠ Low (PCI-DSS scoped CHD risk),
- CIA ≥ 8 + residual = Moderate (Restricted classification — CISO sign-off territory).

### 5. Compliance-aware control picker
The control checkbox list classifies each control into one of four states based on the chosen threat AND the active baselines:

- **Relevant** — defense-in-depth applicable, lowers P/S.
- **Compliance baseline** (amber ribbon) — required by an active baseline, doesn't reduce P/S for this threat but lifts the floor when checked.
- **Both** (green ribbon) — lowers P/S *and* lifts the floor.
- **Disabled** (struck through) — neither relevant nor required.

This was a deliberate fix in v2 — v1 had restricted the picker only to threat-relevant controls, which made it impossible to satisfy a baseline whose controls fell outside the threat's relevance set.

---

## Compliance mapping

Each of the 13 ImpactLens controls is mapped to concrete framework IDs (see `CONTROL_COMPLIANCE` in `app.js`).

| # | Control | NIST CSF 2.0 | ISO 27001:2022 | CIS v8 | SOC 2 | PCI-DSS v4.0 |
|---|---|---|---|---|---|---|
| 1 | Documented procedures | GV.PO-01/02, ID.GV-01 | A.5.1, A.5.36–37 | 14.1, 14.2 | CC1.1, CC2.2 | 12.1 |
| 2 | Segregation of duties | GV.RR-02, PR.AA-05 | A.5.3, A.5.16 | 6.8 | CC5.1, CC6.3 | 7.2.4 |
| 3 | RBAC | PR.AA-01/05 | A.5.15, A.5.18 | 6.7, 6.8 | CC6.1 | 7.2 |
| 4 | MFA | PR.AA-03 | A.8.5 | 6.3, 6.4, 6.5 | CC6.6, CC6.7 | 8.4 |
| … | *(see `CONTROL_COMPLIANCE` for all 13)* | | | | | |

The Excel export (sheet 6) materialises this mapping per asset, listing only the IDs whose controls are actually active. PCI-DSS columns are populated only for `type = FA` assets.

---

## Workflow

```
┌────────────┐       ┌──────────────┐       ┌──────────────────────────┐       ┌──────────┐
│ Std. User  │ ───▶  │ Draft        │ ───▶  │ Pending Approval         │ ───▶  │ Approved │
│ (form fill)│       │ (Info Sec    │       │ (CISO review/approve/    │       │          │
│            │       │  enriches)   │       │  reject with reason)     │       │          │
└────────────┘       └──────────────┘       └──────────────────────────┘       └──────────┘
                            │                            │
                            │ reject                     │ reject (returns to Draft)
                            ▼                            ▼
                          Deleted                   Draft (with reason notification)
```

Every state transition writes a `SystemLogs` row that drives:

1. The bell-icon notification inbox (parsed reasons, role-scoped messages, click-to-jump).
2. The "Document History" Excel sheet.
3. The "Rejected & Deleted" audit Excel sheet.

---

## Reject / Delete with reason capture

A reusable `promptReason()` modal renders a curated dropdown plus a free-text essay box. Presets are framework-aware per action:

- **Reject Pending submission** — Insufficient controls vs ISO 27001 Annex A; CIA misalignment vs NIST SP 800-60; inherent escalation unjustified; action plan unrealistic; PCI-DSS / RA 10173 / SOC 2 control still missing; duplicate; Other.
- **Reject Draft submission** — Incomplete; not in ISMS scope; duplicate; mis-classified; sensitive data instructions not followed; Other.
- **Delete asset** — Decommissioned; out of scope; duplicate / consolidated; test data; owner request with sign-off; replaced; Other.
- **Reject user account** — Not affiliated with PLM; role inappropriate; already has account; awaiting HR verification; suspected automated registration; Other.

The combined reason (preset + essay) is written to `SystemLogs.details` in the canonical form `Reason: <text> · originator=<email> · prior_status=<status>` and parsed by `parseLogDetails()` everywhere it's displayed.

---

## Excel export

Powered by ExcelJS with a dark-themed brand palette (Pantone-style neon green on charcoal title bars, deep forest green body accents, mid-grey gridlines for legibility on white cells).

| # | Sheet | Info Sec | Admin |
|---|---|---|---|
| 1 | Asset Identification | yes | yes |
| 2 | Sensitivity & Valuation | yes | yes |
| 3 | Risk Assessment | yes | yes |
| 4 | Controls C1–C13 | yes | yes |
| 5 | Residual & Treatment | yes | yes |
| 6 | Compliance Mapping (NIST/ISO/CIS/SOC 2/PCI) | yes | yes |
| 7 | **Rejected & Deleted (audit)** | yes | yes |
| 8 | **MBSS endpoint baseline** (CIS v8 + NIST CSF checklist; `mbss_json`) | yes | yes |
| 9 | **Firewall perimeter review** (CIS v8 §12 + NIST SC/PR; `firewall_json`) | yes | yes |
| 10 | Document History (from SystemLogs) | — | yes |
| 11 | Highlights (KPIs + reason-aware narrative) | — | yes |
| 12 | Sign Off (Prepared / Reviewed / Approved + signature lines) | — | yes |

Column definitions for sheets **8** and **9** are hardcoded in `assets/scripts/app.js` (`MBSS_FIELD_SPEC`, `FIREWALL_FIELD_SPEC`) with explicit CIS / NIST mapping strings on each export row’s legend line.

Risk-rating cells use a fixed colour code (High = red, Moderate = amber, Low = cyan, Very Low = green) so the workbook reads the same way the dashboard does.

---

## Project structure

```
ImpactLens-Assessment/
├── index.html                              # DOM only, cache-busted asset references
├── package.json                            # Node deps, npm scripts
├── README.md                               # this file
├── scripts/
│   ├── serve.mjs                           # static dev server with no-store headers
│   └── patch_index2.mjs                    # one-shot helper for HTML cache markers
├── assets/
│   ├── styles/main.css                     # ~1.5k lines, theme + components
│   ├── scripts/app.js                      # ~3.2k lines, full app logic
│   └── vendor/
│       ├── supabase.min.js                 # vendored to bypass tracking prevention
│       └── exceljs.min.js                  # vendored, same reason
├── supabase/
│   ├── master_setup.sql                    # tables + RLS + triggers + seed + realignment
│   ├── hotfix_demo_accounts.sql            # optional: pre-provision demo accounts
│   ├── hotfix_realign_risk_math.sql        # optional: re-derive seeded math + add column
│   ├── hotfix_action_plans.sql             # optional: diversify seed action-plan dates
│   └── hotfix_user_profiles_rls.sql        # legacy: RLS recursion fix (already in master)
└── docs/
    ├── ARCHITECTURE.md                     # v2 system design (Supabase)
    ├── USER_GUIDE.md                       # End-user guide
    ├── MODULE_ISRA_DESCRIPTION.md          # ISRA module scope
    ├── LIMITATIONS_AND_SCOPE.md            # Out-of-scope + defense talking points
    ├── DOCUMENTATION_BACKGROUND.txt        # Full background (copy-paste)
    ├── asset_import_template.csv           # CSV bulk import sample
    └── PROJECT_SCORING_EVALUATION.txt      # Rubric self-assessment
```

---

## Operations

### Cache busting
Every `<link>`/`<script>` referencing local CSS/JS carries a `?v=YYYYMMDDx` marker. Bump the trailing letter whenever you ship a substantive change so the browser pulls the new bytes immediately. Current marker: **`v=20260517o`**.

### Re-running database scripts
All SQL files use `IF NOT EXISTS`, `CREATE OR REPLACE`, and idempotent `ADD COLUMN IF NOT EXISTS` so they can be re-run any number of times without side effects.

### Bypassing tracking prevention
If a browser blocks `localStorage` for the Supabase SDK (Edge "Tracking Prevention", Brave, etc.), the app uses a `directFetch()` helper that hits the PostgREST API with the explicit access token instead of relying on the SDK's locked session — sign-ins and saves complete in <1s instead of timing out at 15s.

### Resetting a stale session
A **Reset session** button on the login screen clears `localStorage` and reloads. Useful if the SDK state got corrupted between deployments.

---

## CSV bulk import (Info Sec / Admin)

On **Asset Table**, use **CSV Template** → fill in Excel → **Import CSV**. Rows become **Draft** assets (Info Sec completes risk profiling in Draft Queue). **Export CSV** downloads the full register. See `docs/USER_GUIDE.md`.

---

## Browser support

- Chrome / Edge 90+, Firefox 88+, Safari 14+, modern mobile browsers.
- No Internet Explorer support.

---

## References

- **NIST SP 800-30 Rev. 1** — Guide for Conducting Risk Assessments.
- **NIST CSF 2.0** (Feb 2024) — Govern / Identify / Protect / Detect / Respond / Recover.
- **ISO/IEC 27001:2022** + Annex A controls (93 control set).
- **ISO/IEC 27005:2022** — Information security risk management.
- **CIS Controls v8** (May 2021) — 18 controls + 153 safeguards.
- **SOC 2 / TSC 2017** (rev. 2022) — Common Criteria CC1–CC9 + supplemental.
- **PCI-DSS v4.0** (March 2022) — applied to all `type=FA` assets.
- **RA 10173** (PH Data Privacy Act) + IRR + NPC Circulars — applied to all PII/SPI assets.
- **ISO/IEC 27701** + GDPR Art. 32 — Privacy management baseline.

---

**Built for the Pamantasan ng Lungsod ng Maynila Information Security Office.**

*v2.0 — May 2026*
