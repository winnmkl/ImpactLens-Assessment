-- Manual fix: align stored inherit / residual with seed (run in Supabase SQL Editor)
-- Use this if the risk register still shows wrong tiers after hotfix_realign_risk_math.sql.
--
-- Why FA petty-cash ledgers showed HIGH residual:
--   The old engine applied PCI-DSS floor (High) to every FA row. Petty-cash / phys_theft
--   ledgers should stay Low / Very Low when controls are in place.
--
-- After running this script: hard-refresh the app (Ctrl+Shift+R).
-- The app now live-recomputes the register; this syncs DB columns for exports/backups.

-- 1) FA discretionary fund ledgers (phys_theft — not PCI cardholder scope)
UPDATE public."Assets"
SET
  prob = 2,
  inherit = CASE WHEN sev >= 4 THEN 'Moderate' ELSE 'Low' END,
  residual = CASE WHEN sev >= 4 THEN 'Low' ELSE 'Very Low' END
WHERE type = 'FA'
  AND name ILIKE '%Discretionary Fund%'
  AND "riskCategory" = 'phys_theft';

UPDATE public."Assets"
SET sev = 2
WHERE type = 'FA'
  AND name ILIKE '%Discretionary Fund%'
  AND "riskCategory" = 'phys_theft'
  AND sev < 4;

-- FA rows with higher severity template keep sev 4 → Moderate / Low after step 1

-- 2) Physical assets — remove erroneous digital-class floors from stored residual
UPDATE public."Assets"
SET
  residual = inherit
WHERE type IN ('PhA', 'PA')
  AND (
    SELECT CASE residual
      WHEN 'Very Low' THEN 0 WHEN 'Low' THEN 1 WHEN 'Moderate' THEN 2 WHEN 'High' THEN 3 ELSE 0 END
    END
  ) > (
    SELECT CASE inherit
      WHEN 'Very Low' THEN 0 WHEN 'Low' THEN 1 WHEN 'Moderate' THEN 2 WHEN 'High' THEN 3 ELSE 0 END
    END
  );

-- 3) Cap any row where residual rank exceeds inherent (except you intentionally set a gap)
UPDATE public."Assets"
SET residual = inherit
WHERE (
  CASE residual WHEN 'High' THEN 3 WHEN 'Moderate' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END
) > (
  CASE inherit WHEN 'High' THEN 3 WHEN 'Moderate' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END
);

-- 5) SA-008: High residual cannot use Accept — restore active mitigation
UPDATE public."Assets"
SET
  "actionType" = 'Mitigate',
  "actionStatus" = 'In Progress',
  "actionPlan" = COALESCE(NULLIF(TRIM("actionPlan"), ''), 'ISMS mitigation in progress.')
WHERE id = 'SA-008'
  AND "actionType" = 'Accept';

-- 6) Restore roll-up columns from paired asset_risks_json (fixes 100% elevated from old Step 2)
WITH worst AS (
  SELECT
    a.id,
    (
      SELECT elem
      FROM jsonb_array_elements(a.asset_risks_json::jsonb) AS elem
      ORDER BY
        CASE elem->>'residual'
          WHEN 'High' THEN 3 WHEN 'Moderate' THEN 2 WHEN 'Low' THEN 1 WHEN 'Very Low' THEN 0 ELSE 0
        END DESC,
        CASE elem->>'inherit'
          WHEN 'High' THEN 3 WHEN 'Moderate' THEN 2 WHEN 'Low' THEN 1 WHEN 'Very Low' THEN 0 ELSE 0
        END DESC
      LIMIT 1
    ) AS sc
  FROM public."Assets" a
  WHERE a.asset_risks_json IS NOT NULL
    AND trim(a.asset_risks_json) <> ''
    AND a.asset_risks_json <> 'null'
)
UPDATE public."Assets" a SET
  prob     = COALESCE((w.sc->>'prob')::int, a.prob),
  sev      = COALESCE((w.sc->>'sev')::int, a.sev),
  inherit  = COALESCE(w.sc->>'inherit', a.inherit),
  residual = COALESCE(w.sc->>'residual', a.residual)
FROM worst w
WHERE a.id = w.id AND w.sc IS NOT NULL;

-- 7) Verify — expect no illogical pairs
SELECT id, name, type, prob, sev, inherit, residual, "riskCategory"
FROM public."Assets"
WHERE (
  CASE residual WHEN 'High' THEN 3 WHEN 'Moderate' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END
) > (
  CASE inherit WHEN 'High' THEN 3 WHEN 'Moderate' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END
)
ORDER BY type, id;

-- 8) Residual distribution snapshot
SELECT residual, COUNT(*) FROM public."Assets" GROUP BY residual ORDER BY 1;
