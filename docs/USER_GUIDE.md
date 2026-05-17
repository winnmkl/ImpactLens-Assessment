# ImpactLens User Guide

Quick reference for PLM ISMS assessors. Plain language; for full technical detail see `DOCUMENTATION_BACKGROUND.txt` and `ARCHITECTURE.md`.

---

## 1. Getting started

1. Install Node 18+ and run `npm install` then `npm start`.
2. Open http://localhost:8000
3. Ensure Supabase `master_setup.sql` has been run (see README).
4. Register or sign in with a verified email.

**Demo accounts** (if `hotfix_demo_accounts.sql` was run): `user@plm.edu.ph`, `infosec@plm.edu.ph`, `admin@plm.edu.ph`

---

## 2. Roles

| Role | You typically… |
|------|----------------|
| **Standard User** | Submit new assets as **Draft** (identification only) |
| **Info Sec** | Complete risk profiling, submit **Pending Approval**, approve Standard Users |
| **Admin (CISO)** | Approve/reject assets, full dashboard, 10-sheet Excel export |

---

## 3. Asset workflow

```
Standard User          Info Sec                 Admin
     |                    |                      |
     v                    v                      v
  DRAFT  ------------>  risk + controls  ---->  PENDING
                             |                 approve / reject
                             v                      v
                        (reject draft)          APPROVED
```

- **Draft** — Waiting for Info Sec.
- **Pending Approval** — Waiting for CISO.
- **Approved** — Official register; shown on Dashboard.
- **Rejected** — Removed from queue; reason in notifications/logs.

---

## 4. Adding an asset (form)

1. Go to **Add Asset**.
2. Select **Asset Type** (IA, PhA, PA, SA, SV, FA) — ID auto-generates.
3. Fill identification fields (name, group, hostname, environment, etc.).
4. **Standard User:** Save → creates **Draft**.
5. **Info Sec:** Complete CIA (often locked by type), threat, P/S, controls, treatment → Save → **Pending**.
6. **Admin:** Can save directly as **Approved** when appropriate.

Watch the **Mandatory Control Gaps** panel — it lists missing baselines with framework citations.

---

## 5. Bulk CSV import / export (Excel column parity)

On **Asset Table** (Info Sec / Admin):

**CSV is plain text** — it cannot store bold headers, column widths, or cell dropdowns. Use **Excel templates (styled)** when you want those; fill the workbook, then use **File → Save As → CSV (UTF-8)** per sheet (or copy values) before **Import CSV**.

| Button | What it does |
|--------|----------------|
| **Excel templates (styled)** | One `.xlsx`: ImpactLens styling, widths, and pick-lists (Type, Environment, Y/N, CIA, ratings, etc.) — for data entry; export CSV from each sheet to import |
| **CSV template (sheet 1)** | Plain CSV — headers only, sheet `1 — Asset Identification` |
| **All CSV templates** | Eight plain header-only CSVs (sheets 1–6 and **8–9** MBSS & firewall; filenames `ImpactLens_08_*` / `ImpactLens_09_*`) |
| **Import CSV** | Detects sheet from headers — identification, sensitivity, risk, controls, treatment, **MBSS baseline**, or **firewall review** |
| **Export CSV pack** | Eight data files — same columns as Excel sheets **1–7**, **8** (MBSS), **9** (firewall) (Approved + Pending rows only) |
| **Export register (quick)** | One flat CSV of all assets (includes `mbss_json`, `firewall_json` columns) |

**Postgres:** Ensure columns `mbss_json` and `firewall_json` exist (`supabase/master_setup.sql` for new projects, or `supabase/hotfix_mbss_firewall_columns.sql` for existing DBs). Otherwise MBSS/firewall saves and CSV PATCH imports fail.

**Required for new Draft rows (sheet 1 / legacy):** `type`, `name` — types: `IA`, `PhA`, `PA`, `SA`, `SV`, `FA`.

---

## 6. Excel audit export

**Info Sec:** workbook tabs run **1 → 7** (core IAR through rejected audit), then **8** (MBSS baseline) and **9** (firewall review) — **9 sheets total**.  
**Admin:** adds **10** (document history), **11** (highlights), **12** (sign-off).

Use for ISMS documentation and CISO review.

---

## 7. Dashboard (Info Sec / Admin)

**Risk posture** (approved assets only):

- **Share >= Moderate residual** — % still elevated
- **Assets at elevated residual** — count + average inherent tier
- **Register completeness** — % with threat + P + S filled
- **Response progress** — % of elevated risks with action In Progress or Done

---

## 8. Account approvals

**Account Approvals** (nav): Pending / Active / Rejected tabs.

- Info Sec approves **Standard User** requests.
- Admin approves **Info Sec** requests.

---

## 9. Troubleshooting

| Issue | Action |
|-------|--------|
| Stuck on login after sign-in | Hard refresh (Ctrl+F5); use **Reset session** on login screen |
| No confirmation email | Check spam; run `npm run test:auth-email -- your@email.com`; see README SMTP section |
| Save timeout | Edge tracking prevention — app uses `directFetch`; reset session |
| Empty database | Re-run `supabase/master_setup.sql` |

---

## 10. Related documents

- `MODULE_ISRA_DESCRIPTION.md` — What the ISRA module covers
- `LIMITATIONS_AND_SCOPE.md` — Scope boundaries (vs. enterprise GRC, automated rule parsers)
- `README.md` — Install and Supabase setup

---

*ImpactLens v2.0 — PLM ISMS*
