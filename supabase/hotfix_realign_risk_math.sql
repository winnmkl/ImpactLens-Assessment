-- =====================================================================
-- HOTFIX: Realign every seeded asset to the new cybersecurity-grade engine
--
-- Why this exists:
--   The original seed in master_setup.sql + hotfix_action_plans.sql froze
--   prob/sev/inherent/residual values produced by the OLD risk math (linear
--   reduction, no mandatory floors, only one Accept-block rule). The app
--   now uses an engine grounded in NIST SP 800-30 Rev. 1, ISO 27005,
--   ISO 27001:2022 Annex A, CIS Controls v8, SOC 2 TSC, PCI-DSS v4.0 and
--   RA 10173 (PH Data Privacy Act). This script re-derives every row so
--   the database matches what the live engine would produce on screen.
--
-- Run in: https://supabase.com/dashboard/project/haspklehikocqswmgmtk/sql/new
-- Idempotent: safe to re-run any number of times.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0) Schema migration — track rejection reason for user accounts
--    (matches the new Reject-with-reason flow on the User Management page)
-- ---------------------------------------------------------------------
ALTER TABLE public.user_profiles
  ADD COLUMN IF NOT EXISTS rejection_reason text;

-- ---------------------------------------------------------------------
-- 1) Helper — Inherent rating lookup (mirrors the INHERIT matrix in JS)
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.il_inherit(s int, p int)
RETURNS text
LANGUAGE sql IMMUTABLE AS $func$
  SELECT CASE s::text || '-' || p::text
    WHEN '5-1' THEN 'Moderate' WHEN '5-2' THEN 'Moderate' WHEN '5-3' THEN 'High'
    WHEN '5-4' THEN 'High'     WHEN '5-5' THEN 'High'
    WHEN '4-1' THEN 'Low'      WHEN '4-2' THEN 'Moderate' WHEN '4-3' THEN 'Moderate'
    WHEN '4-4' THEN 'High'     WHEN '4-5' THEN 'High'
    WHEN '3-1' THEN 'Low'      WHEN '3-2' THEN 'Moderate' WHEN '3-3' THEN 'Moderate'
    WHEN '3-4' THEN 'Moderate' WHEN '3-5' THEN 'High'
    WHEN '2-1' THEN 'Low'      WHEN '2-2' THEN 'Low'      WHEN '2-3' THEN 'Moderate'
    WHEN '2-4' THEN 'Moderate' WHEN '2-5' THEN 'Moderate'
    WHEN '1-1' THEN 'Very Low' WHEN '1-2' THEN 'Low'      WHEN '1-3' THEN 'Low'
    WHEN '1-4' THEN 'Low'      WHEN '1-5' THEN 'Moderate'
    ELSE 'Moderate'
  END;
$func$;

-- ---------------------------------------------------------------------
-- 2) STEP 1 — Apply inherent-risk escalations (NIST SP 800-30 Rev.1)
--    a. Internet-Facing + cyber-external  →  prob = max(prob+1, 3) capped 5
--    b. PII/SPI + (data-leak | DPA)        →  sev = 5
--    c. Restricted (CIA ≥ 8) + cyber/insider → sev ≥ 4
--    d. PCI-DSS scoped (FA) + cyber threat →  sev = 5
-- ---------------------------------------------------------------------
UPDATE public."Assets" SET
  prob = LEAST(5, CASE
    WHEN environment = 'Internet Facing' AND "riskCategory" LIKE 'cyber_ext%'
      THEN GREATEST(prob + 1, 3)
    ELSE prob
  END),
  sev = CASE
    WHEN type = 'FA' AND "riskCategory" LIKE 'cyber_%' THEN 5
    WHEN (pii = 'Y' OR spi = 'Y') AND "riskCategory" IN ('cyber_ext_leak','legal_dpa') THEN 5
    WHEN "ciaScore" >= 8
         AND ("riskCategory" LIKE 'cyber_%' OR "riskCategory" = 'hr_insider')
      THEN GREATEST(sev, 4)
    ELSE sev
  END;

-- ---------------------------------------------------------------------
-- 3) STEP 2 — Recompute inherent rating from the new prob/sev
-- ---------------------------------------------------------------------
UPDATE public."Assets" SET
  inherit = public.il_inherit(sev, prob);

-- ---------------------------------------------------------------------
-- 4) STEP 3 — Recompute residual P/S using weighted defense-in-depth +
--    diminishing returns + synergy bonuses + MANDATORY-CONTROL FLOORS.
-- ---------------------------------------------------------------------
DO $real$
DECLARE
  r              RECORD;
  ctrls          int[];
  rel_set        int[];
  cia            int;
  cid            int;
  pRedRaw        numeric;
  sRedRaw        numeric;
  pRed           numeric;
  sRed           numeric;
  capP           numeric;
  capS           numeric;
  resP           int;
  resS           int;
  residual_rating text;
  -- mandatory-control flags
  has_rbac       bool; has_mfa    bool; has_backup bool; has_crypto bool; has_irp bool;
  has_proc       bool; has_vuln   bool; has_seg    bool; has_fw     bool;
  -- triggers for floor matrix
  is_internet    bool; is_pci     bool; has_pii    bool;
  is_restricted  bool; is_confid  bool;
  -- highest applied floor
  floor_rank     int;
  floor_name     text;
  cur_rank       int;
BEGIN
  FOR r IN SELECT * FROM public."Assets" LOOP
    -- linked active controls
    SELECT COALESCE(array_agg(ctrl_id ORDER BY ctrl_id), ARRAY[]::int[])
      INTO ctrls
      FROM public."AssetControls"
     WHERE asset_id = r.id;

    cia := r."ciaC" + r."ciaI" + r."ciaA";

    -- threat → relevant control set (mirrors controlMap in app.js)
    rel_set := CASE r."riskCategory"
      WHEN 'phys_theft'           THEN ARRAY[1,5,7,8]
      WHEN 'phys_destruct'        THEN ARRAY[1,5,6,12,13]
      WHEN 'hr_insider'           THEN ARRAY[1,2,3,4,9,12]
      WHEN 'hr_accidental'        THEN ARRAY[1,3,6,13]
      WHEN 'cyber_ext_ransomware' THEN ARRAY[1,4,6,7,9,10,11,13]
      WHEN 'cyber_ext_leak'       THEN ARRAY[1,3,4,7,9,10,12]
      WHEN 'cyber_ext_ddos'       THEN ARRAY[10,11,12,13]
      WHEN 'cyber_ext_supply'     THEN ARRAY[1,3,4,7,10,11,13]
      WHEN 'cyber_int_unauth'     THEN ARRAY[1,2,3,4,9,13]
      WHEN 'cyber_int_vuln'       THEN ARRAY[1,9,10,11,12]
      WHEN 'legal_dpa'            THEN ARRAY[1,3,7,8,13]
      ELSE ARRAY[1,2,3,4,5,6,7,8,9,10,11,12,13]
    END;

    -- ---------- weighted reduction (CONTROL_WEIGHTS) ----------
    pRedRaw := 0; sRedRaw := 0;
    FOREACH cid IN ARRAY ctrls LOOP
      IF cid = ANY(rel_set) THEN
        pRedRaw := pRedRaw + CASE cid
          WHEN 1  THEN 0.5 WHEN 2  THEN 0.6 WHEN 3  THEN 0.9 WHEN 4  THEN 1.0
          WHEN 5  THEN 0.7 WHEN 6  THEN 0.0 WHEN 7  THEN 0.0 WHEN 8  THEN 0.3
          WHEN 9  THEN 0.6 WHEN 10 THEN 0.9 WHEN 11 THEN 0.9 WHEN 12 THEN 0.7
          WHEN 13 THEN 0.0 ELSE 0
        END;
        sRedRaw := sRedRaw + CASE cid
          WHEN 1  THEN 0.3 WHEN 2  THEN 0.3 WHEN 3  THEN 0.4 WHEN 4  THEN 0.4
          WHEN 5  THEN 0.4 WHEN 6  THEN 1.2 WHEN 7  THEN 1.4 WHEN 8  THEN 0.5
          WHEN 9  THEN 0.7 WHEN 10 THEN 0.4 WHEN 11 THEN 0.3 WHEN 12 THEN 0.5
          WHEN 13 THEN 1.1 ELSE 0
        END;
      END IF;
    END LOOP;

    -- ---------- synergy bonuses (CONTROL_SYNERGIES) ----------
    -- RBAC + MFA  →  +0.5 prob
    IF 3 = ANY(ctrls) AND 4 = ANY(ctrls)
       AND 3 = ANY(rel_set) AND 4 = ANY(rel_set) THEN
      pRedRaw := pRedRaw + 0.5;
    END IF;
    -- Backup + IRP  →  +0.5 sev
    IF 6 = ANY(ctrls) AND 13 = ANY(ctrls)
       AND 6 = ANY(rel_set) AND 13 = ANY(rel_set) THEN
      sRedRaw := sRedRaw + 0.5;
    END IF;
    -- EDR + Firewall  →  +0.4 prob
    IF 9 = ANY(ctrls) AND 10 = ANY(ctrls)
       AND 9 = ANY(rel_set) AND 10 = ANY(rel_set) THEN
      pRedRaw := pRedRaw + 0.4;
    END IF;
    -- Encryption + Segmentation  →  +0.4 sev
    IF 7 = ANY(ctrls) AND 12 = ANY(ctrls)
       AND 7 = ANY(rel_set) AND 12 = ANY(rel_set) THEN
      sRedRaw := sRedRaw + 0.4;
    END IF;
    -- VulnMgmt + EDR + IRP  →  +0.3/+0.3
    IF 11 = ANY(ctrls) AND 9 = ANY(ctrls) AND 13 = ANY(ctrls)
       AND 11 = ANY(rel_set) AND 9 = ANY(rel_set) AND 13 = ANY(rel_set) THEN
      pRedRaw := pRedRaw + 0.3;
      sRedRaw := sRedRaw + 0.3;
    END IF;

    -- ---------- saturating curve  r(x) = (score-1) × (1 - exp(-x/2)) ----------
    capP := GREATEST(0, r.prob - 1);
    capS := GREATEST(0, r.sev  - 1);
    pRed := CASE WHEN pRedRaw <= 0 THEN 0 ELSE LEAST(capP, capP * (1 - exp(-pRedRaw / 2.0))) END;
    sRed := CASE WHEN sRedRaw <= 0 THEN 0 ELSE LEAST(capS, capS * (1 - exp(-sRedRaw / 2.0))) END;
    resP := GREATEST(1, ROUND(r.prob - pRed)::int);
    resS := GREATEST(1, ROUND(r.sev  - sRed)::int);
    residual_rating := public.il_inherit(resS, resP);

    -- ---------- mandatory-control floors ----------
    has_rbac   := 3  = ANY(ctrls);
    has_mfa    := 4  = ANY(ctrls);
    has_backup := 6  = ANY(ctrls);
    has_crypto := 7  = ANY(ctrls);
    has_irp    := 13 = ANY(ctrls);
    has_proc   := 1  = ANY(ctrls);
    has_vuln   := 11 = ANY(ctrls);
    has_seg    := 12 = ANY(ctrls);
    has_fw     := 10 = ANY(ctrls);

    is_internet   := r.environment = 'Internet Facing';
    is_pci        := r.type = 'FA';
    has_pii       := r.pii = 'Y' OR r.spi = 'Y';
    is_restricted := cia >= 8;
    is_confid     := cia BETWEEN 6 AND 7;

    floor_rank := 0;        -- 0=Very Low, 1=Low, 2=Moderate, 3=High
    floor_name := 'Very Low';

    -- Restricted-class baseline (ISO §A.5.10–A.5.15 + NIST PR.AA + PR.DS)
    IF is_restricted AND NOT (has_rbac AND has_mfa AND has_backup AND has_crypto AND has_irp) THEN
      IF floor_rank < 2 THEN floor_rank := 2; floor_name := 'Moderate'; END IF;
    END IF;
    -- Confidential baseline
    IF is_confid AND NOT (has_rbac AND has_crypto AND has_irp) THEN
      IF floor_rank < 2 THEN floor_rank := 2; floor_name := 'Moderate'; END IF;
    END IF;
    -- PCI-DSS baseline (Req 3, 4, 8.4, 11.3, 1.4.4)
    IF is_pci AND NOT (has_mfa AND has_crypto AND has_vuln AND has_seg) THEN
      IF floor_rank < 3 THEN floor_rank := 3; floor_name := 'High'; END IF;
    END IF;
    -- PII / DPA baseline (RA 10173 §20 + GDPR Art. 32)
    IF has_pii AND NOT (has_proc AND has_rbac AND has_backup AND has_crypto) THEN
      IF floor_rank < 2 THEN floor_rank := 2; floor_name := 'Moderate'; END IF;
    END IF;
    -- Internet-Facing baseline (CIS v8 §12 + §17, NIST PR.IR-01)
    IF is_internet AND NOT (has_fw AND has_vuln AND has_irp) THEN
      IF floor_rank < 2 THEN floor_rank := 2; floor_name := 'Moderate'; END IF;
    END IF;

    -- promote residual to the floor when it's lower
    cur_rank := CASE residual_rating
      WHEN 'Very Low' THEN 0 WHEN 'Low' THEN 1
      WHEN 'Moderate' THEN 2 WHEN 'High' THEN 3 ELSE 2
    END;
    IF cur_rank < floor_rank THEN
      residual_rating := floor_name;
      IF floor_name = 'High'     THEN resP := GREATEST(resP, 4); resS := GREATEST(resS, 4); END IF;
      IF floor_name = 'Moderate' THEN resP := GREATEST(resP, 3); resS := GREATEST(resS, 3); END IF;
      IF floor_name = 'Low'      THEN resP := GREATEST(resP, 2); resS := GREATEST(resS, 2); END IF;
    END IF;

    -- ---------- write back ----------
    UPDATE public."Assets"
       SET residual = residual_rating
     WHERE id = r.id;
  END LOOP;
END
$real$;

-- ---------------------------------------------------------------------
-- 5) STEP 4 — Risk-appetite enforcement on actionType.
--    Any 'Accept' that violates the new appetite rules is promoted to
--    'Mitigate' so the existing rows pass the engine's validation.
--      • residual = High            → Accept blocked
--      • PCI-DSS (FA) + residual ≠ Low/Very Low  → Accept blocked
--      • Restricted (CIA ≥ 8) + residual = Moderate → Accept blocked
-- ---------------------------------------------------------------------
UPDATE public."Assets" SET
  "actionType" = 'Mitigate'
WHERE "actionType" = 'Accept'
  AND (
        residual = 'High'
     OR (type = 'FA' AND residual NOT IN ('Low', 'Very Low'))
     OR ("ciaScore" >= 8 AND residual = 'Moderate')
  );

-- ---------------------------------------------------------------------
-- 6) Sanity check (uncomment to view distribution after realignment)
-- ---------------------------------------------------------------------
-- SELECT residual, COUNT(*) FROM public."Assets" GROUP BY residual ORDER BY 1;
-- SELECT inherit, COUNT(*)  FROM public."Assets" GROUP BY inherit  ORDER BY 1;
-- SELECT "actionType", COUNT(*) FROM public."Assets" GROUP BY "actionType";
