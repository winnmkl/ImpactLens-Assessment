-- Optional: MBSS (endpoint baseline) and Firewall review JSON payloads per asset.
-- Run in Supabase SQL Editor after master_setup.sql (idempotent).

ALTER TABLE public."Assets" ADD COLUMN IF NOT EXISTS mbss_json text;
ALTER TABLE public."Assets" ADD COLUMN IF NOT EXISTS firewall_json text;

COMMENT ON COLUMN public."Assets".mbss_json IS 'JSON: MBSS-style endpoint baseline checklist (EDR, patching, encryption, etc.)';
COMMENT ON COLUMN public."Assets".firewall_json IS 'JSON: Perimeter / firewall rule review notes';

-- Backfill demo / seed data when columns exist but rows are empty (idempotent per column).
-- PhA / PA values MUST match assets/scripts/app.js LOCKED_* JSON (fixed / uneditable in UI).
UPDATE public."Assets" SET mbss_json = CASE type
  WHEN 'PhA' THEN '{"edr_epp":"N","patch_current":"N","disk_encryption":"N","host_firewall":"N","admin_priv_review":"Y","last_review_date":"","notes":"Physical asset — host MBSS baseline not applicable (system fixed)."}'
  WHEN 'PA' THEN '{"edr_epp":"N","patch_current":"N","disk_encryption":"N","host_firewall":"N","admin_priv_review":"Y","last_review_date":"","notes":"Personnel asset — endpoint baseline not applicable (system fixed)."}'
  ELSE '{"edr_epp":"Y","patch_current":"Y","disk_encryption":"Y","host_firewall":"Y","admin_priv_review":"Y","last_review_date":"2026-05-01","notes":"PLM ISMS seed baseline; validate per asset."}'
END::text
WHERE mbss_json IS NULL OR BTRIM(mbss_json) = '' OR BTRIM(mbss_json) = '{}';

UPDATE public."Assets" SET firewall_json = CASE
  WHEN type = 'PhA' THEN '{"scope":"None documented","default_deny":"N","change_control":"Y","logging_soc":"N","rule_review_cadence":"Annual","overly_permissive":"N","notes":"Physical asset — perimeter at facility or campus layer only (system fixed)."}'
  WHEN type = 'PA' THEN '{"scope":"None documented","default_deny":"N","change_control":"Y","logging_soc":"N","rule_review_cadence":"Annual","overly_permissive":"N","notes":"Personnel asset — network perimeter not applicable (system fixed)."}'
  WHEN environment = 'Internet Facing' AND type IN ('SV', 'SA', 'IA', 'FA') THEN '{"scope":"WAF","default_deny":"Y","change_control":"Y","logging_soc":"Y","rule_review_cadence":"Quarterly","overly_permissive":"N","notes":"Internet-facing; edge WAF or equivalent in scope."}'
  ELSE '{"scope":"Network firewall","default_deny":"Y","change_control":"Y","logging_soc":"Y","rule_review_cadence":"Quarterly","overly_permissive":"N","notes":"Internal or hybrid; campus firewall baseline."}'
END::text
WHERE firewall_json IS NULL OR BTRIM(firewall_json) = '' OR BTRIM(firewall_json) = '{}';

-- Optional: force all PhA/PA rows to current UI-locked JSON (run after app deploy; overwrites prior MBSS/firewall text for those types only).
UPDATE public."Assets" SET mbss_json = CASE type
  WHEN 'PhA' THEN '{"edr_epp":"N","patch_current":"N","disk_encryption":"N","host_firewall":"N","admin_priv_review":"Y","last_review_date":"","notes":"Physical asset — host MBSS baseline not applicable (system fixed)."}'
  WHEN 'PA' THEN '{"edr_epp":"N","patch_current":"N","disk_encryption":"N","host_firewall":"N","admin_priv_review":"Y","last_review_date":"","notes":"Personnel asset — endpoint baseline not applicable (system fixed)."}'
  ELSE mbss_json
END::text
WHERE type IN ('PhA', 'PA');

UPDATE public."Assets" SET firewall_json = CASE type
  WHEN 'PhA' THEN '{"scope":"None documented","default_deny":"N","change_control":"Y","logging_soc":"N","rule_review_cadence":"Annual","overly_permissive":"N","notes":"Physical asset — perimeter at facility or campus layer only (system fixed)."}'
  WHEN 'PA' THEN '{"scope":"None documented","default_deny":"N","change_control":"Y","logging_soc":"N","rule_review_cadence":"Annual","overly_permissive":"N","notes":"Personnel asset — network perimeter not applicable (system fixed)."}'
  ELSE firewall_json
END::text
WHERE type IN ('PhA', 'PA');
