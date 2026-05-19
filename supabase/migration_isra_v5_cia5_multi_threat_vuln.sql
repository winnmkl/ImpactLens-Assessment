-- ISRA v5: CIA 1–5 (max-based classification), threats[] / vulnerabilities[] bands 1–5
-- Run in Supabase SQL Editor after pulling latest app code.
-- For a full reseed with aligned demo data, re-run supabase/master_setup.sql (destructive to Assets).

COMMENT ON COLUMN public."Assets"."ciaC" IS 'Confidentiality impact 1–5 (ISO 27005 / NIST SP 800-60).';
COMMENT ON COLUMN public."Assets"."ciaI" IS 'Integrity impact 1–5.';
COMMENT ON COLUMN public."Assets"."ciaA" IS 'Availability impact 1–5.';
COMMENT ON COLUMN public."Assets"."ciaScore" IS 'Stored as max(ciaC, ciaI, ciaA) — drives classification tier, not sum alone.';
COMMENT ON COLUMN public."Assets"."ciaClass" IS 'Public | Internal Use | Confidential | Restricted from max CIA dimension.';
COMMENT ON COLUMN public."Assets".risk_basis_json IS 'JSON: threats[] and vulnerabilities[] ({band 1–5, statement, guide keys}), occurrence justification, likelihood_qual & impact_qual (1–5), prior_incidents (Y/N/U), legacy threat_statement / threat_choice / vulnerability_choice for export parity.';
COMMENT ON COLUMN public."Assets".cia_questionnaire_json IS 'Questionnaire responses 1–5 backing sensitivity / CIA; version 2 schema.';

-- Optional: normalize legacy 1–3 CIA rows still in the database (safe idempotent spread).
UPDATE public."Assets"
SET
  "ciaC" = CASE "ciaC" WHEN 1 THEN 2 WHEN 2 THEN 3 WHEN 3 THEN 5 ELSE LEAST(5, GREATEST(1, "ciaC")) END,
  "ciaI" = CASE "ciaI" WHEN 1 THEN 2 WHEN 2 THEN 3 WHEN 3 THEN 5 ELSE LEAST(5, GREATEST(1, "ciaI")) END,
  "ciaA" = CASE "ciaA" WHEN 1 THEN 2 WHEN 2 THEN 3 WHEN 3 THEN 5 ELSE LEAST(5, GREATEST(1, "ciaA")) END
WHERE "ciaC" IS NOT NULL AND "ciaC" <= 3;

UPDATE public."Assets"
SET
  "ciaScore" = GREATEST(COALESCE("ciaC",3), COALESCE("ciaI",3), COALESCE("ciaA",3)),
  "ciaClass" = CASE
    WHEN GREATEST(COALESCE("ciaC",3), COALESCE("ciaI",3), COALESCE("ciaA",3)) <= 1 THEN 'Public'
    WHEN GREATEST(COALESCE("ciaC",3), COALESCE("ciaI",3), COALESCE("ciaA",3)) <= 2 THEN 'Internal Use'
    WHEN GREATEST(COALESCE("ciaC",3), COALESCE("ciaI",3), COALESCE("ciaA",3)) <= 3 THEN 'Confidential'
    ELSE 'Restricted'
  END
WHERE "ciaC" IS NOT NULL;
