# ImpactLens — Tool overview (logic, standards, and product)

This document describes **what ImpactLens does**, **which standards and methods it follows**, and **how the pieces fit together**. It is meant for stakeholders, assessors, and developers who want one place to orient before diving into **`README.md`** (installation, full risk tables, Excel matrix), **`docs/ARCHITECTURE.md`** (system design), or **`docs/USER_GUIDE.md`** (click-path help).

---

## What the tool is

**ImpactLens** is a browser-based **Information Security / Risk Assessment (ISRA / IAR)** application for **PLM’s ISMS**. It combines:

- An **asset-centric register** (identification through treatment, with explicit workflow states).
- A **client-side risk engine** aligned with **NIST** and common control frameworks.
- **Role-based workflow** (Standard User → Info Sec → Admin / CISO).
- **Auditability**: system log events, notification inbox, and multi-sheet **Excel** exports (plus **CSV** for bulk identification and sheet-wise merges).

The stack is **vanilla HTML/CSS/JavaScript** plus **Supabase** (Postgres + Auth). There is no SPA framework; core logic lives mainly in **`assets/scripts/app.js`**.

---

## Standards and regulatory alignment

ImpactLens is **not a certification** of compliance; it is a **structured assessment and documentation tool** whose rules and mappings cite recognized sources. Primary references used in product logic and copy:

| Area | Primary references (as used in-app / README) |
|------|-----------------------------------------------|
| Risk management process | **NIST SP 800-30 Rev. 1** — inherent risk treatment, likelihood/impact framing, risk register discipline. |
| Management system / controls vocabulary | **ISO/IEC 27001:2022** — Annex A control themes; risk appetite / treatment constraints are echoed in enforcement rules. |
| Security capabilities taxonomy | **NIST Cybersecurity Framework (CSF) 2.0** — control mapping IDs on the 13 ImpactLens controls. |
| Operational safeguards | **CIS Controls v8** — including perimeter (§12) and vulnerability management themes cited for baselines and firewall/MBSS narratives. |
| Service-organization reporting | **SOC 2** Trust Services Criteria — mapped to controls where relevant. |
| Payment-card environments | **PCI-DSS v4.0** — **mandatory floors** and mapping emphasis for **Financial Asset (`FA`)** / cardholder-data-scoping scenarios. |
| Philippine privacy | **Republic Act 10173** (Data Privacy Act) — cited alongside ISO 27701-style language for **PII/SPI** baseline expectations. |

Secondary references appear in UI copy, export legends, and reason-capture presets (e.g. NIST SP 800-60 for CIA alignment notes). **Exact clause tables** for all 13 controls are maintained in code (`CONTROL_COMPLIANCE` in `app.js`) and summarized in **`README.md`** → *Compliance mapping*.

---

## Risk methodology (how the engine thinks)

The engine is implemented in **`calculateRiskMath`**, **`runEnforcementEngine`**, **`getApplicableMandatorySets`**, and related helpers in **`app.js`**. Conceptually:

### 1. Inherent risk (before controls)

- Assets have **probability (1–5)** and **severity (1–5)** for the assessed threat scenario, then an **inherent** Qualitative rating derived from a matrix (implemented consistently with NIST-style P×S thinking).
- **Escalations** adjust P/S upward when factors such as internet exposure, PII/SPI, high CIA scores, financial-asset scope, or certain threat categories are present (see **`README.md`** → *Risk-math engine* → *Inherent risk escalations* for the exact triggers).

### 2. Residual risk (after controls)

- **Thirteen controls** (documented procedures through IRP) have **weights** that reduce P and/or S only when they are **threat-relevant** (`controlMap`).
- **Synergy bonuses** apply when defined pairs are both implemented (e.g. RBAC+MFA, backup+IRP).
- A **saturating curve** applies diminishing returns so residual cannot be “gamed” by stacking many controls (**`README.md`** gives the formula).

### 3. Mandatory-control floors

After residual is computed, the tool may **raise** the residual to a **floor** (e.g. **Moderate** or **High**) if the asset falls in a baseline category (Restricted / Confidential / FA / PII / internet-facing) and is **missing** required controls. Citations in the UI tie floors to **ISO 27001**, **NIST CSF**, **CIS**, **PCI-DSS**, and **RA 10173** as applicable. The **Mandatory Control Gaps** panel lists each unmet requirement.

### 4. Risk appetite / treatment rules

The **treatment type** (e.g. Accept) is **blocked** when doing so would contradict stated appetite rules (e.g. high residual, FA constraints, Restricted-class scenarios) — see **`README.md`** → *Risk-appetite enforcement*.

### 5. Control picker semantics

Each control in the UI can be **relevant** to the threat (drives math), **baseline-required** (lifts floor when satisfied), **both**, or **disabled** — so users can satisfy baselines even when a control is not threat-relevant for P/S reduction (**deliberate v2 behavior** vs. the v1 prototype).

### 6. Dashboard portfolio view (v2.1)

Elevated-risk KPIs and action-plan counts use the **stored paired scenario** roll-up (`asset_risks_json`), giving a realistic portfolio (~18% elevated in the PLM seed). The **live floor engine** applies on the asset form and as an optional **gap hint** on the risk register — not as the dashboard denominator.

---

## The thirteen controls and compliance mapping

ImpactLens collapses many real-world practices into **13 tractable controls** (C1–C13), each mapped to **NIST CSF 2.0**, **ISO 27001:2022 Annex A**, **CIS v8**, **SOC 2**, and **PCI-DSS v4.0** where applicable. The **full ID table** is in **`README.md`**; the **canonical data structure** is **`CONTROL_COMPLIANCE`** in **`app.js`**.

- **Excel / CSV**: Sheet **6** (compliance mapping) materializes active mappings **per asset**. **PCI-related columns** are populated in a **role-appropriate** way for **`FA`** assets.
- **Sheets 8–9** (MBSS-style endpoint baseline and firewall perimeter review) store structured answers in **`mbss_json`** and **`firewall_json`** on the asset row (see schema in **`supabase/master_setup.sql`**).

---

## MBSS-style and firewall artifacts

Beyond the core 13 controls, the product includes **structured checklists** aligned to **CIS v8** and **NIST CSF / SP 800-53**-style language (legends on export):

- **Sheet 8 — MBSS-style endpoint baseline** (endpoint hardening narrative).
- **Sheet 9 — Firewall / perimeter review** (perimeter and rule-review discipline).

These support **documentation and repeatability**; they are **not** automated vulnerability-scan ingestion. **They also connect to the risk model:** when Info Sec / Admin fills **MBSS** and **firewall** fields, the engine applies a small **evidence multiplier** to **P/S reduction** only for **C1–C13 controls that are already checked** and mapped to that evidence (e.g. EDR in MBSS with C9). A panel flags **misalignment** when checkboxes and evidence disagree. Deeper scope boundaries are in **`docs/LIMITATIONS_AND_SCOPE.md`**.

---

## Workflow and audit trail

Asset **status** progresses roughly: **Draft** → **Pending Approval** → **Approved**, with **Rejected** and deletion paths. **Standard Users** typically create **Drafts** (form or **Sheet 1 CSV**); **Info Sec** enriches risk and controls; **Admin** approves or rejects pending items.

Every meaningful transition can generate **`SystemLogs`** entries consumed by:

- The **notification** inbox,
- **Document history** / **Rejected & deleted** style content in **Excel** (Admin gets extended sheets per **`README.md`** matrix).

**Reject / delete / user rejection** flows use a **reason modal** with framework-aware presets; reasons are stored in a **canonical string format** and parsed by **`parseLogDetails`** for display (**`README.md`** → *Reject / Delete with reason capture*).

---

## Roles and the UI (summary)

| Role | Focus |
|------|--------|
| **Standard User** | Submit identification-level data; **asset-oriented dashboard**; **read-only** approved **Asset Table**; **Sheet 1 CSV** import only. |
| **Info Sec** | Draft queue, profiling, pending submissions, user approvals (standard users); full risk UI; **9-sheet** Excel export pattern; full CSV surface. |
| **Admin (CISO)** | Pending approvals, Info Sec account approvals, **12-sheet** Excel export pattern, reporting & sign-offs tab; full CSV surface. |

Enforcement is **layered**: `showSection()` rules, `body[data-role]` CSS, and **RLS** in Postgres (**`master_setup.sql`**).

---

## CSV and Excel (product surface)

- **CSV**: Templates and imports align to **IAR sheet layouts**; users in the Standard role are restricted to **identification** imports; elevated roles can merge additional sheets by **asset id**. Compliance sheet is **export-derived**, not user-imported as a primary source of truth.
- **Excel**: Branded workbooks via **ExcelJS**; sheet list and role split are in **`README.md`** → *Excel export*.

---

## Where to read more

| Need | Document / location |
|------|---------------------|
| Install, seed DB, email auth | **`README.md`** |
| Exact escalation rules, floor table, appetite locks | **`README.md`** → *Risk-math engine* |
| Full control ↔ framework ID table | **`README.md`** → *Compliance mapping* + `CONTROL_COMPLIANCE` in **`app.js`** |
| Module boundaries & limitations | **`docs/LIMITATIONS_AND_SCOPE.md`**, **`docs/MODULE_ISRA_DESCRIPTION.md`** |
| System architecture & tables | **`docs/ARCHITECTURE.md`** |
| Operator steps | **`docs/USER_GUIDE.md`** |

---

## Revision note

This overview is descriptive of the **repository’s intended design**. If **code** or **`README.md`** disagree (e.g. after a refactor), treat the **code** and **SQL** migrations as authoritative and update this file in the same change.
