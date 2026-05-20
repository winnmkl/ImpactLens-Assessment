# ImpactLens Architecture (v2.1)

## System Overview

ImpactLens is a **browser-based Information Security Risk Assessment (ISRA / IAR)** application for the Pamantasan ng Lungsod ng Maynila (PLM) ISMS. Version 2 uses **Supabase** for authentication, PostgreSQL storage, and Row Level Security (RLS). The v1 prototype (localStorage + AlaSQL) is superseded.

### Key principles

- **Standards-aligned risk engine** — NIST SP 800-30 inherent escalations, weighted residual reduction, mandatory control floors
- **Role-based workflow** — Standard User, Info Sec, Admin (CISO)
- **Audit trail** — SystemLogs for every approve, reject, delete, and submit
- **Defense in depth** — UI role checks plus database RLS

---

## Technology stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Markup | HTML5 | Pages, forms, sections |
| Styling | CSS3 + custom properties | Theme, layout, role visibility |
| Logic | Vanilla JavaScript (ES2020) | Single `app.js` application |
| Auth / API | Supabase JS + direct PostgREST fetch | Login, CRUD, session |
| Database | PostgreSQL (Supabase) | Assets, controls, logs, profiles |
| Export | ExcelJS (vendored) | 9-sheet (Info Sec) / 12-sheet (Admin) audit workbooks |
| Import / export | CSV (built-in) | Bulk asset identification rows |
| Dev server | `scripts/serve.mjs` | Static files, port 8000, no-store cache |

Vendor libraries are served from `assets/vendor/` to avoid browser tracking-prevention blocking CDN scripts.

---

## Architecture diagram

```
+---------------------------+
|  Browser                  |
|  index.html               |
|  assets/scripts/app.js    |
|  assets/styles/main.css   |
+-------------+-------------+
              | HTTPS + JWT
              v
+---------------------------+
|  Supabase Project         |
|  - Auth (email/password)  |
|  - public.Assets          |
|  - public.AssetControls   |
|  - public.user_profiles   |
|  - public.SystemLogs      |
|  - public.ReportData      |
|  - RLS policies per role  |
+---------------------------+
```

---

## Database schema (summary)

### Assets

Primary register row: identification, CIA fields, risk (prob, sev, inherit, residual), treatment/action plan, workflow `status`, `created_by`, `reviewed_at`.

Statuses: `Draft`, `Pending Approval`, `Approved`, `Rejected`.

### AssetControls

Many-to-many: `asset_id` + `ctrl_id` (1–13).

### user_profiles

Linked to `auth.users`: `requested_role`, `approved_role`, `account_status` (`pending` | `active` | `rejected`), `rejection_reason`.

### SystemLogs

`user_email`, `user_role`, `action`, `details`, `asset_id`, `created_at` — drives notifications and Excel history sheets.

---

## Application modules

| Module | Section ID | Roles | Description |
|--------|------------|-------|-------------|
| ISRA / IAR | `sec-add`, queues, register | All (scoped) | Core risk assessment and asset lifecycle |
| Dashboard | `sec-dashboard` | Info Sec, Admin | KPIs from **paired `asset_risks_json` roll-up**; live gap hints on register only |
| Risk register | `sec-risk` | Info Sec, Admin | Heatmap + risk table |
| Control metrics | `sec-controls` | Info Sec, Admin | Adoption of 13 controls |
| Action plans | `sec-actions` | Info Sec, Admin | Elevated residual treatments |
| Account approvals | `sec-users` | Info Sec, Admin | User onboarding |
| System logs | `sec-logs` | Info Sec, Admin | Audit trail |
| Reporting | `sec-report` | Admin | Sign-offs + Excel export |
| Risk guidelines | `sec-guidelines` | All | Reference scales |

**Out of scope (documented limitations):** MBSS, firewall rule review, automated vulnerability scan import. Firewall appears as **Control 10 (WAF)** within ISRA only.

See `docs/MODULE_ISRA_DESCRIPTION.md` and `docs/LIMITATIONS_AND_SCOPE.md`.

---

## Risk engine (client-side)

Implemented in `calculateRiskMath()` and `runEnforcementEngine()`:

1. **Inherent** — P/S escalations, 5×5 `INHERIT` matrix lookup
2. **Residual** — `controlMap` threat relevance, `CONTROL_WEIGHTS`, synergies, diminishing returns
3. **Floors** — `getApplicableMandatorySets()` / `MANDATORY_CONTROLS`
4. **Appetite** — Blocks `Accept` when residual or asset class forbids it

**Portfolio vs. form math (v2.1):** Dashboard and register badges use `reportingAssetResidualTier()` (stored paired scenarios). The asset form still runs `computeResidualBundleForScenario()` live, including mandatory floors. Register rows show **↑ control gap floor** when live analysis exceeds the stored tier.

Saved values persist on `Assets` rows and in `asset_risks_json`. `master_setup.sql` syncs roll-up columns from JSON — avoid `hotfix_realign_risk_math.sql` on seeded demo data.

---

## Security model

1. **Supabase Auth** — Email verification, JWT sessions
2. **RLS** — `current_user_role()` restricts reads/writes by role
3. **UI** — `showSection()` allowed map + `body[data-role]` CSS
4. **directFetch()** — PostgREST with explicit bearer token if SDK locks

---

## Data import and export

| Format | Direction | Who | Purpose |
|--------|-----------|-----|---------|
| CSV | Import | Info Sec, Admin | Bulk Draft assets from spreadsheet |
| CSV | Export | Info Sec, Admin | Register backup / interchange |
| Excel | Export | Info Sec (9 tabs), Admin (12) | Formal IAR audit package |

CSV template: `docs/asset_import_template.csv` or download from Asset Table UI.

---

## Project structure

```
ImpactLens-Assessment/
  index.html
  package.json
  assets/scripts/app.js      # Application logic
  assets/styles/main.css
  assets/vendor/             # supabase.min.js, exceljs.min.js
  scripts/serve.mjs
  supabase/master_setup.sql
  docs/
    ARCHITECTURE.md          # This file
    USER_GUIDE.md
    MODULE_ISRA_DESCRIPTION.md
    LIMITATIONS_AND_SCOPE.md
    DOCUMENTATION_BACKGROUND.txt
```

---

## Deployment and operations

### Local
- Run `npm start` → http://localhost:8000
- Execute `supabase/master_setup.sql` in Supabase SQL Editor
- Configure Auth: confirm email, redirect URLs for **localhost and production** (see README)

### Vercel (production)
- **URL:** https://impactlens-assessment.vercel.app
- **Config:** `vercel.json` (static site, no framework build)
- **Deploy:** `npm run deploy:prod` (Vercel CLI, project linked via `.vercel/project.json`)
- **Important:** `.vercelignore` must use `/scripts` (root-only) so `assets/scripts/app.js` is **not** excluded

### Cache busting
Bump `?v=` on CSS/JS in `index.html` after each release. Current: `main.css?v=20260519-dashboard-realistic`, `app.js?v=20260519-metric-colors`.

---

*v2.1 — May 2026 — PLM ISMS*
