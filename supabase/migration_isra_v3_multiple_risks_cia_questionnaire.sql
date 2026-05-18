-- ISRA v3: multiple risk scenarios per asset + CIA questionnaire (assessor-led)
-- Run in Supabase SQL Editor on existing projects.

ALTER TABLE public."Assets"
  ADD COLUMN IF NOT EXISTS asset_risks_json text,
  ADD COLUMN IF NOT EXISTS cia_questionnaire_json text;

COMMENT ON COLUMN public."Assets".asset_risks_json IS 'JSON array: multiple ISRA scenarios (category, narratives, qualitative anchors, per-scenario inherent/residual, action fields). Legacy single-risk columns remain rolled-up / primary mirror.';
COMMENT ON COLUMN public."Assets".cia_questionnaire_json IS 'JSON: assessed answers mapping to CIA + PI posture (heavy info / integrity harm / outage impact / personal data scope / corporate relevance).';
