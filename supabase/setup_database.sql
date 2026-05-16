-- ImpactLens — full database bootstrap (run once in Supabase SQL Editor)
-- Project: https://supabase.com/dashboard/project/haspklehikocqswmgmtk/sql/new
-- After this runs: create Auth users, then sign in — the app will auto-seed sample assets if tables are empty.

-- ---------------------------------------------------------------------------
-- 1. TABLES
-- ---------------------------------------------------------------------------

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
  "docDate" text,
  "docVersion" text,
  "docAuthor" text,
  "docApproval" text,
  "docDesc" text,
  "revHigh" text,
  "initHigh" text,
  "prepName" text,
  "prepTitle" text,
  "revName" text,
  "revTitle" text,
  "appName" text,
  "appTitle" text
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

CREATE INDEX IF NOT EXISTS idx_assets_status ON public."Assets" (status);
CREATE INDEX IF NOT EXISTS idx_asset_controls_asset ON public."AssetControls" (asset_id);
CREATE INDEX IF NOT EXISTS idx_system_logs_created ON public."SystemLogs" (created_at DESC);

-- Empty report row (app expects id = 1)
INSERT INTO public."ReportData" (id, "docDate", "docVersion", "docAuthor", "docApproval", "docDesc", "revHigh", "initHigh", "prepName", "prepTitle", "revName", "revTitle", "appName", "appTitle")
VALUES (1, '', '', '', '', '', '', '', '', '', '', '', '', '')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. ROW LEVEL SECURITY (logged-in users can read/write)
-- ---------------------------------------------------------------------------

ALTER TABLE public."Assets" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."AssetControls" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."ReportData" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."SystemLogs" ENABLE ROW LEVEL SECURITY;

-- Drop old policies if re-running this script
DROP POLICY IF EXISTS "impactlens_assets_all" ON public."Assets";
DROP POLICY IF EXISTS "impactlens_controls_all" ON public."AssetControls";
DROP POLICY IF EXISTS "impactlens_report_all" ON public."ReportData";
DROP POLICY IF EXISTS "impactlens_logs_all" ON public."SystemLogs";

CREATE POLICY "impactlens_assets_all" ON public."Assets"
  FOR ALL TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "impactlens_controls_all" ON public."AssetControls"
  FOR ALL TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "impactlens_report_all" ON public."ReportData"
  FOR ALL TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "impactlens_logs_all" ON public."SystemLogs"
  FOR ALL TO authenticated USING (true) WITH CHECK (true);

-- ---------------------------------------------------------------------------
-- 3. GRANTS
-- ---------------------------------------------------------------------------

GRANT USAGE ON SCHEMA public TO authenticated;
GRANT ALL ON public."Assets" TO authenticated;
GRANT ALL ON public."AssetControls" TO authenticated;
GRANT ALL ON public."ReportData" TO authenticated;
GRANT ALL ON public."SystemLogs" TO authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated;

-- Done. Next: run enterprise_setup.sql, create admin@plm.edu.ph in Auth, then seed_plm_assets.sql.
