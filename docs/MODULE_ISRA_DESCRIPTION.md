# Module Description: Information Security Risk Assessment (ISRA / IAR)

## Module name

**Information Security Risk Assessment (ISRA)** — aligned with the PLM Information Asset Register (IAR) template.

## Purpose

Digitize the end-to-end lifecycle of registering information assets, assessing inherent and residual risk, mapping security controls to international frameworks, recording risk treatment, and producing audit-ready exports for the PLM ISMS.

## Scope (what this module does)

| Function | Description |
|----------|-------------|
| Asset identification | Type, owner, host, environment, department, description |
| Sensitivity valuation | PII/SPI flags, CIA (C/I/A), classification band |
| Threat assessment | 11 threat categories with templates |
| Inherent risk | Probability x Severity matrix with NIST SP 800-30 escalations |
| Control assessment | 13 organization-level controls, threat-relevant weighting |
| Residual risk | Weighted reduction, synergies, diminishing returns |
| Compliance gaps | Mandatory floors (ISO, NIST, CIS, PCI-DSS, RA 10173) |
| Risk treatment | Mitigate / Transfer / Avoid / Accept with appetite rules |
| Workflow | Draft → Pending Approval → Approved (+ reject/delete reasons) |
| Reporting | Dashboard KPIs, CSV import/export, 9-sheet (Info Sec) / 12-sheet (Admin) Excel workbook |
| Governance | System logs, notifications, account approvals |

## Inputs

- Web forms (primary)
- CSV bulk import for identification fields (Info Sec / Admin)
- Supabase seed data (`master_setup.sql` — 57 PLM sample assets)

## Outputs

- Live risk ratings (inherent, residual) on screen
- Approved asset register
- CSV export of register
- Excel IAR workbook (role-aware sheet count)
- SystemLogs audit trail

## Standards implemented in logic

- NIST SP 800-30 Rev. 1 (escalations, threat-control mapping)
- ISO/IEC 27001:2022 / 27005 (treatment, Annex A mapping)
- NIST CSF 2.0, CIS Controls v8, SOC 2 TSC, PCI-DSS v4.0 (control cross-walk)
- RA 10173, ISO 27701, GDPR Art. 32 (PII/SPI floors)

## Roles per workflow step

| Step | Standard User | Info Sec | Admin |
|------|---------------|----------|-------|
| Create identification | Yes | Yes | Yes |
| Risk profiling + controls | No | Yes | Yes |
| Submit to CISO | No | Yes | Yes |
| Final approval | No | No | Yes |

## Success criteria

An asset is **assessment-complete** when it has threat description, probability, severity, controls evaluated, residual rating, and (if not Accept) an action plan — reflected in Dashboard **register completeness** KPI.

---

*See `LIMITATIONS_AND_SCOPE.md` for explicit out-of-scope items.*
