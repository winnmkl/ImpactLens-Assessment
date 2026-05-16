/**
 * Build supabase/master_setup.sql from header + seed_plm_assets.sql body.
 * Run: node scripts/build_master_sql.mjs
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const seedPath = path.join(__dirname, '..', 'supabase', 'seed_plm_assets.sql');
const outPath  = path.join(__dirname, '..', 'supabase', 'master_setup.sql');

const seed = fs.readFileSync(seedPath, 'utf8');
// Skip the first 5 lines of seed (its own DELETE preamble) and embed only INSERT.
const seedInsertStart = seed.indexOf('INSERT INTO public."Assets"');
const seedInsertBlock = seed.slice(seedInsertStart).trim();

const ctrlSeeds = [
  ['IA-001',[1,3,4,7,9,10,11,12]], ['IA-002',[1,3,4,7,8]], ['IA-003',[3,4,7,9,10]],
  ['IA-004',[1,3,4,10,13]], ['IA-005',[2,3,4,12]], ['IA-006',[3,4,7,9,10]],
  ['IA-007',[2,3,4,12]], ['IA-008',[2,3,4,12]],
  ['PhA-001',[5,6,13]], ['PhA-002',[5,13]], ['PhA-003',[5,7,8]], ['PhA-004',[5,7,8]],
  ['PhA-005',[5,7,8]], ['PhA-006',[5,7,8]], ['PhA-007',[5,6,13]], ['PhA-008',[5,7,8]],
  ['SA-001',[9,10,11,12]], ['SA-002',[10,12,13]], ['SA-003',[9,10,11,12]],
  ['SA-004',[2,3,4,9]], ['SA-005',[1,3,6]], ['SA-006',[9,10,11,12]],
  ['SV-001',[10,12,13]], ['SV-002',[1,3,4,10,13]], ['SV-003',[2,3,4,9]],
  ['SV-004',[10,12,13]], ['SV-005',[1,3,4,10,13]],
  ['PA-001',[2,3,4,12]], ['PA-002',[2,3,4,9]], ['PA-003',[1,3,6]], ['PA-004',[2,3,4,12]],
  ['FA-001',[2,3,4,9]], ['FA-002',[5,7,8]], ['FA-003',[1,7,8]],
  ['IA-009',[1,7,8]], ['IA-010',[1,7,8]], ['SA-007',[9,10,11,12]],
  ['PhA-009',[5,7,8]], ['SV-006',[1,3,4,10,13]], ['IA-011',[3,4,7,9,10]],
  ['PhA-010',[5,6,13]], ['SA-008',[3,4,7,9,10]], ['IA-012',[1,7,8]],
  ['SV-007',[2,3,4,9]], ['PhA-011',[5,7,8]], ['IA-013',[1,7,8]],
  ['SA-009',[3,4,7,9,10]], ['PhA-012',[5,6,13]], ['FA-004',[2,3,4,9]],
  ['IA-014',[3,4,7,9,10]], ['SV-008',[1,3,4,10,13]], ['PhA-013',[5,7,8]],
  ['SA-010',[3,4,7,9,10]], ['IA-015',[2,3,4,12]], ['PhA-014',[5,6,13]],
  ['SV-009',[9,10,11,12]], ['IA-016',[2,3,4,12]],
];

const ctrlValues = ctrlSeeds.flatMap(([id, ctrls]) =>
  ctrls.map(c => `('${id}', ${c})`)
).join(',\n  ');

const HEADER = `-- ============================================================
-- ImpactLens MASTER SETUP — single-file Supabase bootstrap
-- Project: haspklehikocqswmgmtk
-- Run this ONCE in: Dashboard → SQL Editor → New query → Run
--
-- Creates:
--   • Assets, AssetControls, ReportData, SystemLogs, user_profiles
--   • RLS policies for the 'authenticated' role
--   • Trigger on auth.users that auto-creates user_profiles
--     the moment a user verifies their email (real Supabase email)
--   • Pre-approved master admin profile for admin@plm.edu.ph
--   • 57 PLM-contextualized asset records + control mappings
-- ============================================================

-- Safe re-run: drop dependent objects first
DROP TRIGGER IF EXISTS on_auth_user_created   ON auth.users;
DROP TRIGGER IF EXISTS on_auth_user_confirmed ON auth.users;
DROP FUNCTION IF EXISTS public.handle_user_email_confirmed() CASCADE;

-- ============================================================
-- 1. CORE TABLES
-- ============================================================

CREATE TABLE IF NOT EXISTS public."Assets" (
  id text PRIMARY KEY,
  status text NOT NULL DEFAULT 'Draft',
  type text,
  name text,
  group_name text,
  hostname text,
  server text,
  custodian text,
  description text,
  ip_address text,
  environment text,
  department text,
  pii text DEFAULT 'N',
  spi text DEFAULT 'N',
  corp text DEFAULT 'N',
  "ciaC" integer,
  "ciaI" integer,
  "ciaA" integer,
  "ciaScore" integer,
  "ciaClass" text,
  "riskCategory" text,
  "riskDesc" text,
  prob integer,
  sev integer,
  inherit text,
  residual text,
  "actionType" text,
  "actionStatus" text,
  "actionPlan" text,
  "actionOwner" text,
  "actionDate" text,
  created_by text,
  updated_by text,
  reviewed_at timestamptz
);

CREATE TABLE IF NOT EXISTS public."AssetControls" (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  asset_id text NOT NULL REFERENCES public."Assets"(id) ON DELETE CASCADE,
  ctrl_id integer NOT NULL,
  UNIQUE (asset_id, ctrl_id)
);

CREATE TABLE IF NOT EXISTS public."ReportData" (
  id integer PRIMARY KEY,
  "docDate" text, "docVersion" text, "docAuthor" text, "docApproval" text, "docDesc" text,
  "revHigh" text, "initHigh" text,
  "prepName" text, "prepTitle" text,
  "revName" text, "revTitle" text,
  "appName" text, "appTitle" text
);

CREATE TABLE IF NOT EXISTS public."SystemLogs" (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  user_email text,
  user_role text,
  action text NOT NULL,
  details text,
  asset_id text
);

CREATE TABLE IF NOT EXISTS public.user_profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email text NOT NULL,
  requested_role text NOT NULL DEFAULT 'user'
    CHECK (requested_role IN ('user', 'infosec', 'admin')),
  approved_role text
    CHECK (approved_role IS NULL OR approved_role IN ('user', 'infosec', 'admin')),
  account_status text NOT NULL DEFAULT 'pending'
    CHECK (account_status IN ('pending', 'active', 'rejected')),
  approved_by uuid REFERENCES auth.users(id),
  approved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_assets_status        ON public."Assets" (status);
CREATE INDEX IF NOT EXISTS idx_asset_controls_asset ON public."AssetControls" (asset_id);
CREATE INDEX IF NOT EXISTS idx_system_logs_created  ON public."SystemLogs" (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_profiles_status ON public.user_profiles (account_status);
CREATE INDEX IF NOT EXISTS idx_user_profiles_email  ON public.user_profiles (email);

INSERT INTO public."ReportData"
  (id, "docDate", "docVersion", "docAuthor", "docApproval", "docDesc",
   "revHigh", "initHigh", "prepName", "prepTitle", "revName", "revTitle", "appName", "appTitle")
VALUES (1, '', '', '', '', '', '', '', '', '', '', '', '', '')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 2. AUTO-PROVISION user_profiles ON EMAIL VERIFICATION
-- ============================================================
-- Fires after a real Supabase email confirmation:
--   - INSERT  : user signed up with auto-confirmed email
--   - UPDATE  : email_confirmed_at transitions from NULL to a timestamp
-- The master admin (admin@plm.edu.ph) is pre-approved as 'active'.

CREATE OR REPLACE FUNCTION public.handle_user_email_confirmed()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_role   text;
  v_status text;
BEGIN
  IF NEW.email_confirmed_at IS NULL THEN
    RETURN NEW;
  END IF;

  v_role := COALESCE(NEW.raw_user_meta_data->>'requested_role', 'user');
  IF v_role NOT IN ('user', 'infosec', 'admin') THEN
    v_role := 'user';
  END IF;

  IF lower(NEW.email) = 'admin@plm.edu.ph' THEN
    v_role   := 'admin';
    v_status := 'active';
  ELSE
    v_status := 'pending';
  END IF;

  INSERT INTO public.user_profiles (
    id, email, requested_role, approved_role, account_status, approved_at
  ) VALUES (
    NEW.id,
    NEW.email,
    v_role,
    CASE WHEN v_status = 'active' THEN v_role ELSE NULL END,
    v_status,
    CASE WHEN v_status = 'active' THEN now() ELSE NULL END
  )
  ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    updated_at = now();

  RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  WHEN (NEW.email_confirmed_at IS NOT NULL)
  EXECUTE FUNCTION public.handle_user_email_confirmed();

CREATE TRIGGER on_auth_user_confirmed
  AFTER UPDATE OF email_confirmed_at ON auth.users
  FOR EACH ROW
  WHEN (OLD.email_confirmed_at IS NULL AND NEW.email_confirmed_at IS NOT NULL)
  EXECUTE FUNCTION public.handle_user_email_confirmed();

-- Idempotent backfill for any users already verified before the trigger
INSERT INTO public.user_profiles (id, email, requested_role, approved_role, account_status, approved_at)
SELECT u.id,
       u.email,
       CASE WHEN lower(u.email) = 'admin@plm.edu.ph' THEN 'admin'
            ELSE COALESCE(u.raw_user_meta_data->>'requested_role', 'user') END,
       CASE WHEN lower(u.email) = 'admin@plm.edu.ph' THEN 'admin' ELSE NULL END,
       CASE WHEN lower(u.email) = 'admin@plm.edu.ph' THEN 'active' ELSE 'pending' END,
       CASE WHEN lower(u.email) = 'admin@plm.edu.ph' THEN now() ELSE NULL END
FROM auth.users u
WHERE u.email_confirmed_at IS NOT NULL
ON CONFLICT (id) DO UPDATE SET
  email = EXCLUDED.email,
  updated_at = now();

-- ============================================================
-- 3. ROW LEVEL SECURITY
-- ============================================================

ALTER TABLE public."Assets"        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."AssetControls" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."ReportData"    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."SystemLogs"    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_profiles   ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS impactlens_assets_all   ON public."Assets";
DROP POLICY IF EXISTS impactlens_controls_all ON public."AssetControls";
DROP POLICY IF EXISTS impactlens_report_all   ON public."ReportData";
DROP POLICY IF EXISTS impactlens_logs_all     ON public."SystemLogs";
DROP POLICY IF EXISTS profiles_select         ON public.user_profiles;
DROP POLICY IF EXISTS profiles_self_update    ON public.user_profiles;
DROP POLICY IF EXISTS profiles_approver_update ON public.user_profiles;
DROP POLICY IF EXISTS profiles_self_insert    ON public.user_profiles;

CREATE POLICY impactlens_assets_all   ON public."Assets"        FOR ALL TO authenticated USING (true) WITH CHECK (true);
CREATE POLICY impactlens_controls_all ON public."AssetControls" FOR ALL TO authenticated USING (true) WITH CHECK (true);
CREATE POLICY impactlens_report_all   ON public."ReportData"    FOR ALL TO authenticated USING (true) WITH CHECK (true);
CREATE POLICY impactlens_logs_all     ON public."SystemLogs"    FOR ALL TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY profiles_select ON public.user_profiles
  FOR SELECT TO authenticated
  USING (
    auth.uid() = id
    OR EXISTS (
      SELECT 1 FROM public.user_profiles up
      WHERE up.id = auth.uid()
        AND up.account_status = 'active'
        AND up.approved_role IN ('infosec', 'admin')
    )
  );

CREATE POLICY profiles_self_insert ON public.user_profiles
  FOR INSERT TO authenticated
  WITH CHECK (auth.uid() = id);

CREATE POLICY profiles_self_update ON public.user_profiles
  FOR UPDATE TO authenticated
  USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);

CREATE POLICY profiles_approver_update ON public.user_profiles
  FOR UPDATE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.user_profiles up
      WHERE up.id = auth.uid()
        AND up.account_status = 'active'
        AND (
          up.approved_role = 'admin'
          OR (up.approved_role = 'infosec' AND user_profiles.requested_role = 'user')
        )
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.user_profiles up
      WHERE up.id = auth.uid()
        AND up.account_status = 'active'
        AND up.approved_role IN ('infosec', 'admin')
    )
  );

GRANT USAGE ON SCHEMA public TO authenticated;
GRANT ALL ON public."Assets", public."AssetControls", public."ReportData",
            public."SystemLogs", public.user_profiles TO authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated;

-- ============================================================
-- 4. PLM ASSET SEED — 57 contextualized records + control mapping
-- ============================================================

DELETE FROM public."AssetControls";
DELETE FROM public."Assets";

`;

const FOOTER = `

INSERT INTO public."AssetControls" (asset_id, ctrl_id) VALUES
  ${ctrlValues}
ON CONFLICT DO NOTHING;

-- Done. Next:
--   1) Authentication → Providers → Email is enabled (default).
--   2) Authentication → Sign Up: leave "Confirm email" ON for real verification.
--   3) Register admin@plm.edu.ph from the app or the Auth dashboard.
--      The trigger above auto-promotes that email to active 'admin'.
`;

fs.writeFileSync(outPath, HEADER + seedInsertBlock + FOOTER);
console.log('Wrote', outPath);
