# ImpactLens — Limitations and Scope Statement

This document records known boundaries of the tool for academic evaluation, defense, and future work. It addresses rubric expectations honestly.

---

## In scope

- **Single primary module:** Information Security Risk Assessment (ISRA / IAR) per PLM template
- Multi-role workflow (User, Info Sec, CISO)
- Standards-aligned risk engine and 13-control framework mapping
- Mandatory compliance gap analysis
- Dashboard analytics, CSV and Excel export, audit logging

---

## Out of scope (not implemented as separate modules)

| Rubric example | ImpactLens approach |
|----------------|---------------------|
| **MBSS** (malware / endpoint baseline separate assessment) | Not a standalone module; partial coverage via Control 9 (EDR) and Control 11 (vulnerability management) within ISRA |
| **Firewall rule review** (rule-by-rule analysis) | Not implemented; **Control 10 (Network Firewall / WAF)** records whether boundary defense exists, not parsing of `.conf` or rule exports |
| Automated scan import | No upload of Nessus/OpenVAS/XML results; assessors enter findings manually |
| Mobile native app | Responsive web only |

---

## File upload — what we provide

| Feature | Status |
|---------|--------|
| Structured web forms | Yes — primary input |
| **CSV import** (bulk identification → Draft assets) | Yes — Info Sec / Admin, Asset Table |
| **CSV export** (register download) | Yes — Info Sec / Admin |
| **Excel export** (full IAR audit pack) | Yes — ExcelJS |
| PDF / image / firewall config upload | No |

**Rationale:** PLM IAR data is structured and audit-sensitive; CSV import balances bulk entry with validated columns without arbitrary file parsers.

---

## Technical limitations

- Risk math runs in the **browser** on edit; database stores results (not re-computed in PostgreSQL on every read except seed/migration scripts)
- **Monolithic** `app.js` — maintainable sections but not split into npm packages
- **Automated tests** — placeholder in `package.json`; manual QA for submission
- **Email delivery** — depends on Supabase Auth configuration (not application code alone)
- `docs/ARCHITECTURE.md` in older clones may have described v1 localStorage — v2 uses Supabase (see current ARCHITECTURE.md)

---

## Documentation map

| Document | Audience |
|----------|----------|
| README.md | Install, Supabase, email setup |
| USER_GUIDE.md | Day-to-day users |
| MODULE_ISRA_DESCRIPTION.md | Evaluators — module boundary |
| DOCUMENTATION_BACKGROUND.txt | Full system background (copy-paste) |
| ARCHITECTURE.md | Developers |
| PROJECT_SCORING_EVALUATION.txt | Self-assessment vs rubric |

---

## Recommended defense statement

> "Our project delivers one assessment module deeply — ISRA/IAR for PLM ISMS — rather than three shallow modules. Firewall and endpoint concerns appear where ISO 27001 expects them: as mapped controls inside the risk assessment, with mandatory floors and gap analysis. Bulk data entry is supported via CSV import; formal audit output via Excel."

---

*ImpactLens v2.0 — May 2026*
