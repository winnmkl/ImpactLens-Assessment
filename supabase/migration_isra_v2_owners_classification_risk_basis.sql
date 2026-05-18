-- ISRA v2: assessor-led classification justification, owners, risk basis (ISO 27005 / NIST SP 800-30).
-- Safe to run on existing ImpactLens installs (Supabase SQL Editor).

ALTER TABLE public."Assets"
  ADD COLUMN IF NOT EXISTS asset_owners text,
  ADD COLUMN IF NOT EXISTS classification_justification text,
  ADD COLUMN IF NOT EXISTS risk_basis_json text;

COMMENT ON COLUMN public."Assets".asset_owners IS 'Newline-separated asset owners / responsible parties.';
COMMENT ON COLUMN public."Assets".classification_justification IS 'Info Sec / Admin rationale for CIA, PII flags, and class.';
COMMENT ON COLUMN public."Assets".risk_basis_json IS 'JSON: threat/vuln narratives, qualitative likelihood & impact anchors, occurrence notes, prior incidents.';
