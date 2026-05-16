-- =================================================================
-- HOTFIX: Diversify Action Plans across ISO/IEC 27005 risk treatments
-- Run in: https://supabase.com/dashboard/project/haspklehikocqswmgmtk/sql/new
--
-- Risk treatment standards used (ISO 27005:2022 / NIST SP 800-39):
--   Mitigate  — reduce risk by applying controls
--   Transfer  — outsource or insure (cloud, third-party, cyber-liability)
--   Avoid     — cease the activity / decommission the asset
--   Accept    — formally acknowledge with senior sign-off
--
-- This script also plants 8 deadlines within the next 14 days so the
-- header KPI "Action Plans Due (14 days)" exercises real data.
-- Idempotent: each UPDATE targets a fixed asset id.
-- =================================================================

BEGIN;

-- ============================================================
-- A. MITIGATE — high-priority items due within 14 days
--    (Today 2026-05-17 → window 2026-05-18..2026-05-31)
-- ============================================================

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Apply DB encryption-at-rest (AES-256) and quarterly access review aligned with ISO/IEC 27001 A.8.24 and NIST SP 800-53 SC-28.',
  "actionOwner"  = 'ICTO Security Lead',
  "actionDate"   = '2026-05-22'
WHERE id = 'IA-001';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Patch SQLi vulnerability surfaced in May pen-test; redeploy mobile API with parameterized queries and SAST gate in CI.',
  "actionOwner"  = 'ICTO App Dev Lead',
  "actionDate"   = '2026-05-20'
WHERE id = 'IA-003';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Deploy MFA for clinical staff and roll out at-rest encryption for EMR records per Data Privacy Act IRR Rule VI.',
  "actionOwner"  = 'Clinic IT Coordinator',
  "actionDate"   = '2026-05-25'
WHERE id = 'IA-006';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'OWASP Top-10 hardening + WAF rule update for student portal; SAST + DAST scan to be run before promotion.',
  "actionOwner"  = 'Web Development Team',
  "actionDate"   = '2026-05-28'
WHERE id = 'SA-003';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'PCI-DSS quarterly external ASV scan + HSM-managed key rotation; submit ROC evidence to acquirer.',
  "actionOwner"  = 'Finance IT',
  "actionDate"   = '2026-05-23'
WHERE id = 'FA-001';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Roll out Privileged Access Management (PAM) for all domain admins; enable session recording and JIT elevation.',
  "actionOwner"  = 'ICTO Director',
  "actionDate"   = '2026-05-26'
WHERE id = 'PA-002';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Implement DLP for donor PII; verify field-level encryption on SPI columns (NIST 800-53 SC-28 / ISO 27002 8.24).',
  "actionOwner"  = 'Scholarship Office Head',
  "actionDate"   = '2026-05-30'
WHERE id = 'IA-002';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Submit signed PCI-DSS SAQ-A and rotate API keys with PayMongo; confirm webhook signature validation in code.',
  "actionOwner"  = 'Finance Systems',
  "actionDate"   = '2026-05-29'
WHERE id = 'SV-006';

-- ============================================================
-- B. MITIGATE — medium-term (Q3 2026)
-- ============================================================

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Quarterly access review for HRIS workflow approvers; integrate audit-log forwarding to SIEM.',
  "actionOwner"  = 'HR Systems Admin',
  "actionDate"   = '2026-06-30'
WHERE id = 'SA-004';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Enforce TLS 1.3 across Intramunotes API; enable App Transport Security on iOS and certificate pinning on Android.',
  "actionOwner"  = 'Mobile Dev Lead',
  "actionDate"   = '2026-07-15'
WHERE id = 'SA-001';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Roll WPA3-Enterprise across Eduroam SSIDs; phase out PEAP/MSCHAPv2 for student logins.',
  "actionOwner"  = 'Network Operations',
  "actionDate"   = '2026-08-01'
WHERE id = 'SV-003';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Quarterly DR drill including UPS battery health check, cooling failover, and backup-restore validation.',
  "actionOwner"  = 'ICTO Infrastructure',
  "actionDate"   = '2026-09-10'
WHERE id = 'PhA-001';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Annual disciplinary file retention review; redact resolved cases per DPA Section 16 and update retention schedule.',
  "actionOwner"  = 'Dean of Student Affairs',
  "actionDate"   = '2026-08-30'
WHERE id = 'IA-009';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Apply CIS Benchmark hardening to VPN concentrator; enforce always-on MFA and device-posture check.',
  "actionOwner"  = 'Network Lead',
  "actionDate"   = '2026-07-20'
WHERE id = 'SV-007';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Onboard admissions portal into central WAF; enable bot-mitigation and ATO protection on application form.',
  "actionOwner"  = 'Admissions IT',
  "actionDate"   = '2026-06-15'
WHERE id = 'SA-009';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Encrypt portfolio records with column-level KMS; quarterly review of authorized signatories by VP-Finance.',
  "actionOwner"  = 'VP Finance',
  "actionDate"   = '2026-07-31'
WHERE id = 'FA-004';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Annual review of governance archive access; restrict to BoR Secretariat under need-to-know.',
  "actionOwner"  = 'Board Secretary',
  "actionDate"   = '2026-09-30'
WHERE id = 'IA-008';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Quarterly procurement document classification + need-to-know access review per ISO 27002 5.10.',
  "actionOwner"  = 'BAC Secretariat',
  "actionDate"   = '2026-08-15'
WHERE id = 'IA-016';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Encrypt international exchange records and align with foreign-data-transfer rules under DPA Section 21.',
  "actionOwner"  = 'International Programs Head',
  "actionDate"   = '2026-08-20'
WHERE id = 'IA-013';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Implement annual audit of CCTV retention; physically secure NVR rack with key-controlled access.',
  "actionOwner"  = 'Chief of Security',
  "actionDate"   = '2026-09-30'
WHERE id = 'PhA-007';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'Pending',
  "actionPlan"   = 'Schedule quarterly CRM access review; deduplicate alumni records per DPA data-quality principle.',
  "actionOwner"  = 'Alumni Affairs Director',
  "actionDate"   = '2026-07-10'
WHERE id = 'IA-005';

-- ============================================================
-- C. TRANSFER — risk shifted to provider, insurer, or contract
-- ============================================================

UPDATE public."Assets" SET
  "actionType"   = 'Transfer',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Risk transferred via AWS Shared Responsibility Model + Customer-Managed KMS; annual SOC 2 Type II review of provider.',
  "actionOwner"  = 'Cloud Administrator',
  "actionDate"   = '2026-09-30'
WHERE id = 'IA-004';

UPDATE public."Assets" SET
  "actionType"   = 'Transfer',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Hosting layer transferred to AWS under Shared Responsibility; verify Region-PH compliance and SOC 2 attestation.',
  "actionOwner"  = 'Cloud Administrator',
  "actionDate"   = '2026-10-15'
WHERE id = 'SV-005';

UPDATE public."Assets" SET
  "actionType"   = 'Transfer',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Microsoft 365 E5 license — risk transferred to Microsoft per OST/DPA. Annual M365 Secure Score review by InfoSec.',
  "actionOwner"  = 'Mail Administrator',
  "actionDate"   = '2026-12-01'
WHERE id = 'SV-002';

UPDATE public."Assets" SET
  "actionType"   = 'Transfer',
  "actionStatus" = 'Done',
  "actionPlan"   = 'Cloudflare Enterprise plan with DDoS guarantee — financial liability transferred per signed MSA, May 2026.',
  "actionOwner"  = 'Infrastructure Lead',
  "actionDate"   = '2026-05-10'
WHERE id = 'SV-004';

UPDATE public."Assets" SET
  "actionType"   = 'Transfer',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Cyber-liability insurance with PhP 50M cap renewed; residual financial impact transferred to underwriter.',
  "actionOwner"  = 'VP Finance',
  "actionDate"   = '2026-06-30'
WHERE id = 'FA-002';

UPDATE public."Assets" SET
  "actionType"   = 'Transfer',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Supabase Cloud — risk transferred under Pro plan SLA; quarterly review of breach-notification clauses and uptime credits.',
  "actionOwner"  = 'Intramunotes DevOps',
  "actionDate"   = '2026-07-10'
WHERE id = 'SV-008';

UPDATE public."Assets" SET
  "actionType"   = 'Transfer',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Disbursement risk transferred to partner bank per signed depository agreement; reconciliation reviewed monthly.',
  "actionOwner"  = 'Scholarship Accountant',
  "actionDate"   = '2026-08-31'
WHERE id = 'FA-003';

-- ============================================================
-- D. AVOID — cease the activity / decommission legacy
-- ============================================================

UPDATE public."Assets" SET
  "actionType"   = 'Avoid',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Legacy COVID health declaration archive — disposal scheduled per retention policy; collection ceased (data minimization, DPA Sec.11).',
  "actionOwner"  = 'Clinic Admin',
  "actionDate"   = '2026-08-31'
WHERE id = 'IA-010';

UPDATE public."Assets" SET
  "actionType"   = 'Avoid',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Decommission self-managed osTicket; replace with vendor-hosted ITSM in Q4 — risk avoided by retiring the asset.',
  "actionOwner"  = 'Service Desk Lead',
  "actionDate"   = '2026-10-31'
WHERE id = 'SV-009';

UPDATE public."Assets" SET
  "actionType"   = 'Avoid',
  "actionStatus" = 'In Progress',
  "actionPlan"   = 'Stop using self-managed Library OPAC; migrate to vendor-hosted catalog. Activity to be ceased Q3 2026.',
  "actionOwner"  = 'Library IT',
  "actionDate"   = '2026-09-15'
WHERE id = 'SA-007';

UPDATE public."Assets" SET
  "actionType"   = 'Avoid',
  "actionStatus" = 'Pending',
  "actionPlan"   = 'Phase out unmanaged wireless mics; replace with university-issued, asset-tagged units only. Discontinue rentals.',
  "actionOwner"  = 'Events Coordinator',
  "actionDate"   = '2026-07-31'
WHERE id = 'PhA-004';

-- ============================================================
-- E. ACCEPT — formal sign-off (mitigation cost > residual exposure)
-- ============================================================

UPDATE public."Assets" SET
  "actionType"   = 'Accept',
  "actionStatus" = 'Done',
  "actionPlan"   = 'Residual risk Low/Very Low; cost of further mitigation outweighs exposure. Formally accepted by CISO sign-off (May 2026).',
  "actionOwner"  = 'CISO',
  "actionDate"   = '2026-05-15'
WHERE id IN ('PhA-003','PhA-006','PhA-009','PhA-011','PhA-013');

UPDATE public."Assets" SET
  "actionType"   = 'Accept',
  "actionStatus" = 'Done',
  "actionPlan"   = 'Low residual risk for non-PII operational asset; accepted by Asset Owner with annual review per ISO 27005 §10.',
  "actionOwner"  = 'Asset Owner',
  "actionDate"   = '2026-05-12'
WHERE id IN ('SA-008','PhA-005','PhA-008');

-- ============================================================
-- F. DONE — historic mitigations now fully closed
-- ============================================================

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'Done',
  "actionPlan"   = 'EDR (CrowdStrike) deployed to 100% of HR workstations; closure validated by InfoSec, April 2026.',
  "actionOwner"  = 'HR IT',
  "actionDate"   = '2026-04-30'
WHERE id = 'IA-007';

UPDATE public."Assets" SET
  "actionType"   = 'Mitigate',
  "actionStatus" = 'Done',
  "actionPlan"   = 'Network segmentation for Finance VLAN completed and validated by independent assessor.',
  "actionOwner"  = 'Network Operations',
  "actionDate"   = '2026-05-05'
WHERE id = 'SA-005';

-- ============================================================
-- G. Spread remaining "default-2026-12-31" mitigations realistically
-- ============================================================

UPDATE public."Assets" SET
  "actionDate" = '2026-09-30',
  "actionPlan" = 'Quarterly review per ISMS schedule; controls verified against ISO/IEC 27001 Annex A.'
WHERE "actionType" = 'Mitigate'
  AND "actionDate" = '2026-12-31'
  AND residual    = 'Moderate';

UPDATE public."Assets" SET
  "actionDate" = '2026-11-30',
  "actionPlan" = 'Annual control review and audit; align with NIST CSF Identify and Protect functions.'
WHERE "actionType" = 'Mitigate'
  AND "actionDate" = '2026-12-31'
  AND residual IN ('Low', 'Very Low');

COMMIT;

-- =================================================================
-- VERIFY — uncomment to inspect the resulting distribution
-- =================================================================
-- SELECT "actionType", "actionStatus", count(*) AS n
-- FROM public."Assets" GROUP BY 1,2 ORDER BY 1,2;
--
-- SELECT id, name, "actionType", "actionStatus", "actionDate", residual
-- FROM public."Assets"
-- WHERE "actionDate" BETWEEN current_date AND current_date + INTERVAL '14 days'
--   AND "actionStatus" <> 'Done'
--   AND "actionType"   <> 'Accept'
-- ORDER BY "actionDate";
