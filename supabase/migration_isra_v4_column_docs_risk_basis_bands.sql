-- ISRA v4: ensure ISRA v2–v3 columns exist, then apply extended column documentation.
-- Safe to run in Supabase SQL Editor on any ImpactLens install (idempotent).
-- If you skipped v2/v3 earlier, this block creates the missing columns before COMMENT.

ALTER TABLE public."Assets"
  ADD COLUMN IF NOT EXISTS asset_owners text,
  ADD COLUMN IF NOT EXISTS classification_justification text,
  ADD COLUMN IF NOT EXISTS risk_basis_json text,
  ADD COLUMN IF NOT EXISTS asset_risks_json text,
  ADD COLUMN IF NOT EXISTS cia_questionnaire_json text;

COMMENT ON COLUMN public."Assets".risk_basis_json IS
  'JSON: threat/vuln narratives (threat_statement, vulnerability_statement), occurrence justification, likelihood_qual & impact_qual (1–5), prior_incidents (Y/N), plus threat_choice & vulnerability_choice (1=low/discount inherent P/S anchor, 2=typical, 3=elevated/+1 anchor step vs baseline narratives). Imported side-by-side columns merge into this blob.';

COMMENT ON COLUMN public."Assets".classification_justification IS
  'Info Sec rationale for CIA class and PI flags / regulatory scope.';
COMMENT ON COLUMN public."Assets".cia_questionnaire_json IS
  'JSON: questionnaire answers underpinning CIA posture (see app CISRA flow). Prefer single JSON column in CSV; optional cell in Excel.';
COMMENT ON COLUMN public."Assets".asset_risks_json IS
  'JSON array: multiple risk scenarios per asset (category, risk_basis, qualitative bands, inherent/residual, treatment fields). Imported as full JSON via Risk sheet.';
COMMENT ON COLUMN public."Assets".asset_owners IS
  'Newline-separated or free-text asset owners / responsible parties (mirror Sheet 1 CSV column).';
