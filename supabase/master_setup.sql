-- ============================================================
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
  rejection_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Backfill column for existing installs (idempotent)
ALTER TABLE public.user_profiles
  ADD COLUMN IF NOT EXISTS rejection_reason text;

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
    v_role   := 'admin';   v_status := 'active';
  ELSIF lower(NEW.email) = 'infosec@plm.edu.ph' THEN
    v_role   := 'infosec'; v_status := 'active';
  ELSIF lower(NEW.email) = 'user@plm.edu.ph' THEN
    v_role   := 'user';    v_status := 'active';
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
       CASE
         WHEN lower(u.email) = 'admin@plm.edu.ph'   THEN 'admin'
         WHEN lower(u.email) = 'infosec@plm.edu.ph' THEN 'infosec'
         WHEN lower(u.email) = 'user@plm.edu.ph'    THEN 'user'
         ELSE COALESCE(u.raw_user_meta_data->>'requested_role', 'user')
       END,
       CASE
         WHEN lower(u.email) = 'admin@plm.edu.ph'   THEN 'admin'
         WHEN lower(u.email) = 'infosec@plm.edu.ph' THEN 'infosec'
         WHEN lower(u.email) = 'user@plm.edu.ph'    THEN 'user'
         ELSE NULL
       END,
       CASE
         WHEN lower(u.email) IN ('admin@plm.edu.ph','infosec@plm.edu.ph','user@plm.edu.ph') THEN 'active'
         ELSE 'pending'
       END,
       CASE
         WHEN lower(u.email) IN ('admin@plm.edu.ph','infosec@plm.edu.ph','user@plm.edu.ph') THEN now()
         ELSE NULL
       END
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

-- SECURITY DEFINER helper avoids RLS infinite recursion on user_profiles
CREATE OR REPLACE FUNCTION public.current_user_role()
RETURNS text
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = public
AS $$
  SELECT approved_role
  FROM public.user_profiles
  WHERE id = auth.uid() AND account_status = 'active'
  LIMIT 1
$$;

GRANT EXECUTE ON FUNCTION public.current_user_role() TO authenticated;

CREATE POLICY profiles_select ON public.user_profiles
  FOR SELECT TO authenticated
  USING (
    auth.uid() = id
    OR public.current_user_role() IN ('infosec', 'admin')
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
    public.current_user_role() = 'admin'
    OR (public.current_user_role() = 'infosec' AND requested_role = 'user')
  )
  WITH CHECK (
    public.current_user_role() IN ('infosec', 'admin')
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

INSERT INTO public."Assets" (
  id, status, type, name, group_name, hostname, server, custodian, description,
  ip_address, environment, department, pii, spi, corp, "ciaC", "ciaI", "ciaA", "ciaScore", "ciaClass",
  "riskCategory", "riskDesc", prob, sev, inherit, residual,
  "actionType", "actionStatus", "actionPlan", "actionOwner", "actionDate"
) VALUES
('IA-001', 'Approved', 'IA', 'PLM Central Registration System (CRS) Database', 'Registrar', 'CRS-DB-PROD', 'CRS Primary PostgreSQL', 'University Registrar', 'Student records, grades, enrollment — primary SIS datastore.', '10.20.1.10', 'Internal', 'Office of the Registrar', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'cyber_ext_leak', 'Student records, grades, enrollment — primary SIS datastore.', 3, 5, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-002', 'Approved', 'IA', 'Yoshii Scholarship Foundation Beneficiary Records', 'Scholarship Office', 'SCHOL-DB-01', 'Scholarship DB Server', 'Scholarship Office Head', 'Financial aid and donor-linked student PII/SPI.', '10.20.2.15', 'Internal', 'Scholarship & Financial Aid', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'legal_dpa', 'Financial aid and donor-linked student PII/SPI.', 3, 5, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-003', 'Approved', 'IA', 'Intramunotes Mobile App User Database', 'ICTO', 'INTRA-DB-01', 'Intramunotes API Backend', 'ICTO App Dev Lead', 'Campus community notes, posts, and student identifiers.', '10.20.8.50', 'Internet Facing', 'ICTO / Student Affairs', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'cyber_ext_leak', 'Campus community notes, posts, and student identifiers.', 4, 4, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-004', 'Approved', 'IA', 'Haribon AWS Cloud Research Dataset', 'Research', 'HARIBON-S3-01', 'AWS EC2 / S3 Research', 'Research Data Steward', 'Biodiversity research files hosted on AWS for Haribon partnership.', 'Cloud', 'Internet Facing', 'Research & Extension', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'cyber_ext_supply', 'Biodiversity research files hosted on AWS for Haribon partnership.', 2, 4, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-005', 'Approved', 'IA', 'PLM Alumni Relations CRM Database', 'Alumni Affairs', 'ALUM-CRM-01', 'Alumni CRM Server', 'Alumni Affairs Director', 'Alumni contact history and employment tracking.', '10.20.3.20', 'Hybrid', 'Alumni Affairs', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'hr_insider', 'Alumni contact history and employment tracking.', 3, 4, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-006', 'Approved', 'IA', 'University Clinic EMR Records', 'Medical Services', 'CLINIC-EMR-01', 'Clinic EMR DB', 'Chief Clinic Physician', 'Electronic medical records and patient history.', '10.50.1.10', 'Internal', 'University Clinic', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'cyber_ext_leak', 'Electronic medical records and patient history.', 3, 5, 'High', 'High', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-007', 'Approved', 'IA', 'HR Payroll Master File', 'Human Resources', 'HR-PAY-01', 'Payroll DB', 'HR Director', 'Faculty and staff salary, SSS, PhilHealth data.', '10.30.1.10', 'Internal', 'Human Resources', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'hr_insider', 'Faculty and staff salary, SSS, PhilHealth data.', 2, 5, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-008', 'Approved', 'IA', 'Board of Regents Confidential Minutes Archive', 'Administration', 'BOR-ARCH-01', 'Exec File Server', 'Board Secretary', 'Restricted governance documents and resolutions.', '10.10.1.5', 'Internal', 'Office of the President', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'hr_insider', 'Restricted governance documents and resolutions.', 2, 5, 'Moderate', 'High', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-001', 'Approved', 'PhA', 'Gusaling Corazon Aquino Main Server Room', 'ICTO', 'GCA-SRVR-01', 'GCA Data Center Rack A', 'ICTO Infrastructure', 'Primary on-prem server room in GCA building.', '10.99.10.1', 'Internal', 'ICTO', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_destruct', 'Primary on-prem server room in GCA building.', 2, 5, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-002', 'Approved', 'PhA', 'Gusaling Corazon Aquino Network Core Switch Stack', 'ICTO', 'GCA-CORE-SW', 'GCA Network Closet', 'Network Operations', 'Core switching for GCA academic buildings.', '10.99.10.2', 'Internal', 'ICTO', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_destruct', 'Core switching for GCA academic buildings.', 3, 4, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-003', 'Approved', 'PhA', 'Tanghalang Bayan AV Control Rack', 'Cultural Affairs', 'TB-AV-RACK', 'TB Stage Tech Booth', 'Theater Technical Director', 'Audio-visual control systems for university events.', '10.40.5.10', 'Internal', 'Cultural Affairs', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_theft', 'Audio-visual control systems for university events.', 3, 3, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-004', 'Approved', 'PhA', 'Tanghalang Bayan Wireless Microphone Inventory', 'Cultural Affairs', 'TB-WIRELESS', 'TB Storage', 'Events Coordinator', 'Wireless mics and receivers for performances.', 'N/A', 'Internal', 'Cultural Affairs', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_theft', 'Wireless mics and receivers for performances.', 3, 2, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-005', 'Approved', 'PhA', 'Main Library RFID Gate System', 'Library', 'LIB-RFID-01', 'Library Entrance', 'Library Systems Admin', 'RFID anti-theft gates and sensors.', '10.20.5.1', 'Internal', 'University Library', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_theft', 'RFID anti-theft gates and sensors.', 2, 3, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-006', 'Approved', 'PhA', 'CET Fabrication Lab 3D Printers', 'CET', 'CET-3DP-01', 'CET Fab Lab', 'CET Lab Technician', 'Additive manufacturing equipment for engineering prototypes.', 'DHCP', 'Internal', 'College of Engineering', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_theft', 'Additive manufacturing equipment for engineering prototypes.', 3, 2, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-007', 'Approved', 'PhA', 'Campus CCTV NVR Cluster', 'Security', 'SEC-NVR-01', 'Security Office', 'Chief of Security', '30-day retention video surveillance storage.', '10.99.1.50', 'Internal', 'Campus Security', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_destruct', '30-day retention video surveillance storage.', 3, 4, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-008', 'Approved', 'PhA', 'Finance Vault & Safe Deposit Unit', 'Finance', 'FIN-VAULT', 'Cashier Building', 'Head Cashier', 'Physical safe for daily university collections.', 'N/A', 'Internal', 'Finance', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_theft', 'Physical safe for daily university collections.', 2, 4, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SA-001', 'Approved', 'SA', 'Intramunotes Android/iOS Application', 'ICTO', 'INTRA-APP', 'Intramunotes Build Pipeline', 'Mobile Dev Lead', 'Official PLM student community mobile app.', 'Cloud', 'Internet Facing', 'ICTO', 'N', 'N', 'Y', 2, 3, 3, 8, 'Restricted', 'cyber_int_vuln', 'Official PLM student community mobile app.', 4, 4, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SA-002', 'Approved', 'SA', 'PLM Learning Management System (Moodle)', 'Academic', 'LMS-APP-01', 'LMS Application Server', 'Academic IT', 'Online modules, quizzes, and grade sync.', '10.20.10.5', 'Hybrid', 'Academic Affairs', 'N', 'N', 'Y', 2, 3, 3, 8, 'Restricted', 'cyber_ext_ddos', 'Online modules, quizzes, and grade sync.', 3, 3, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SA-003', 'Approved', 'SA', 'CRS Web Portal Application', 'Registrar', 'CRS-WEB-01', 'CRS App Tier', 'Registrar IT Liaison', 'Student-facing enrollment and grades portal.', '10.20.1.20', 'Internet Facing', 'Registrar', 'N', 'N', 'Y', 2, 3, 3, 8, 'Restricted', 'cyber_int_vuln', 'Student-facing enrollment and grades portal.', 4, 5, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SA-004', 'Approved', 'SA', 'University HRIS Platform', 'HR', 'HRIS-APP', 'HR Application Server', 'HR Systems Admin', 'Leave, attendance, and personnel workflows.', '10.30.1.20', 'Internal', 'Human Resources', 'N', 'N', 'Y', 2, 3, 3, 8, 'Restricted', 'cyber_int_unauth', 'Leave, attendance, and personnel workflows.', 3, 4, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SA-005', 'Approved', 'SA', 'Finance Budget Planning System', 'Finance', 'FIN-BPS', 'Finance App Server', 'Finance Systems', 'Annual budgeting and allotment tracking.', '10.40.1.10', 'Internal', 'Finance', 'N', 'N', 'Y', 2, 3, 3, 8, 'Restricted', 'hr_accidental', 'Annual budgeting and allotment tracking.', 2, 4, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SA-006', 'Approved', 'SA', 'Research Grant Management System', 'Research', 'RGMS-APP', 'Research App Server', 'Research Office', 'Grant proposals and compliance reporting.', '10.60.1.10', 'Internal', 'Research & Extension', 'N', 'N', 'Y', 2, 3, 3, 8, 'Restricted', 'cyber_int_vuln', 'Grant proposals and compliance reporting.', 3, 3, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SV-001', 'Approved', 'SV', 'PLM Official Website (www.plm.edu.ph)', 'ICTO', 'WEB-PROD-01', 'Public Web Farm', 'Web Development Team', 'Primary public-facing university portal.', '203.177.X.X', 'Internet Facing', 'ICTO', 'N', 'N', 'Y', 2, 2, 3, 7, 'Confidential', 'cyber_ext_ddos', 'Primary public-facing university portal.', 4, 3, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SV-002', 'Approved', 'SV', 'Microsoft 365 Student Email Tenant', 'ICTO', 'O365-MAIL', 'Cloud Tenant', 'Mail Administrator', 'Student email and Teams collaboration.', 'Cloud', 'Internet Facing', 'ICTO', 'N', 'N', 'Y', 2, 2, 3, 7, 'Confidential', 'cyber_ext_supply', 'Student email and Teams collaboration.', 2, 4, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SV-003', 'Approved', 'SV', 'Campus Wi-Fi Authentication (Eduroam)', 'ICTO', 'WIFI-RADIUS', 'RADIUS Cluster', 'Network Operations', 'Wireless access for students and faculty.', '10.99.2.1', 'Hybrid', 'ICTO', 'N', 'N', 'Y', 2, 2, 3, 7, 'Confidential', 'cyber_int_unauth', 'Wireless access for students and faculty.', 3, 3, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SV-004', 'Approved', 'SV', 'Cloudflare DDoS Protection Service', 'ICTO', 'CF-EDGE', 'Edge Proxy', 'Infrastructure Lead', 'CDN and DDoS mitigation for public services.', 'Cloud', 'Internet Facing', 'ICTO', 'N', 'N', 'Y', 2, 2, 3, 7, 'Confidential', 'cyber_ext_ddos', 'CDN and DDoS mitigation for public services.', 3, 3, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SV-005', 'Approved', 'SV', 'AWS Haribon Research Hosting', 'Research', 'AWS-HARIBON', 'AWS Account', 'Cloud Administrator', 'Haribon partnership workloads on AWS.', 'Cloud', 'Internet Facing', 'Research', 'N', 'N', 'Y', 2, 2, 3, 7, 'Confidential', 'cyber_ext_supply', 'Haribon partnership workloads on AWS.', 2, 4, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PA-001', 'Approved', 'PA', 'University President Executive Office', 'Administration', 'EXEC-OFFICE', 'Executive Suite', 'Executive Secretary', 'Top management and board liaison personnel.', 'N/A', 'Hybrid', 'Office of the President', 'Y', 'N', 'Y', 3, 2, 2, 7, 'Confidential', 'hr_insider', 'Top management and board liaison personnel.', 3, 5, 'High', 'High', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PA-002', 'Approved', 'PA', 'ICTO Systems Administration Team', 'ICTO', 'ICTO-ADMINS', 'ICTO Operations', 'ICTO Director', 'Privileged administrators with domain-wide access.', 'N/A', 'Internal', 'ICTO', 'Y', 'N', 'Y', 3, 2, 2, 7, 'Confidential', 'cyber_int_unauth', 'Privileged administrators with domain-wide access.', 3, 5, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PA-003', 'Approved', 'PA', 'Registrar Frontline Staff', 'Registrar', 'REG-STAFF', 'Registrar Counters', 'Registrar Head', 'Staff processing transcripts and enrollment.', 'N/A', 'Internal', 'Registrar', 'Y', 'N', 'Y', 3, 2, 2, 7, 'Confidential', 'hr_accidental', 'Staff processing transcripts and enrollment.', 3, 4, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PA-004', 'Approved', 'PA', 'Scholarship Verification Officers', 'Scholarship', 'SCHOL-STAFF', 'Scholarship Office', 'Scholarship Coordinator', 'Officers validating Yoshii and institutional grants.', 'N/A', 'Internal', 'Scholarship Office', 'Y', 'N', 'Y', 3, 2, 2, 7, 'Confidential', 'hr_insider', 'Officers validating Yoshii and institutional grants.', 2, 4, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('FA-001', 'Approved', 'FA', 'University Main Operating Bank Account Portal', 'Finance', 'BANK-GW-01', 'Banking Gateway', 'Finance IT', 'Online banking for tuition and operations.', '10.40.1.5', 'Internet Facing', 'Finance', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'cyber_int_unauth', 'Online banking for tuition and operations.', 3, 5, 'High', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('FA-002', 'Approved', 'FA', 'Cashier Daily Collection Ledger', 'Finance', 'CASH-LEDGER', 'Cashier System', 'Head Cashier', 'Daily cash intake and deposit records.', '10.40.2.1', 'Internal', 'Finance', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'phys_theft', 'Daily cash intake and deposit records.', 3, 4, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('FA-003', 'Approved', 'FA', 'Yoshii Scholarship Disbursement Account', 'Scholarship', 'YOSHII-ACCT', 'Scholarship Finance', 'Scholarship Accountant', 'Dedicated fund flows for Yoshii beneficiaries.', '10.40.3.1', 'Internal', 'Scholarship Office', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'legal_dpa', 'Dedicated fund flows for Yoshii beneficiaries.', 2, 5, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-009', 'Approved', 'IA', 'Student Disciplinary Case Files', 'Student Affairs', 'DSA-CASES', 'DSA Records', 'Dean of Student Affairs', 'Conduct cases and sanctions documentation.', '10.20.9.10', 'Internal', 'Student Affairs', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'legal_dpa', 'Conduct cases and sanctions documentation.', 2, 4, 'Moderate', 'High', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-010', 'Approved', 'IA', 'COVID-19 Health Declaration Archives', 'Medical Services', 'CLINIC-COVID', 'Clinic Records', 'Clinic Admin', 'Historical health screening submissions.', '10.50.1.20', 'Internal', 'University Clinic', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'legal_dpa', 'Historical health screening submissions.', 2, 3, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SA-007', 'Approved', 'SA', 'Library Online Catalog (OPAC)', 'Library', 'LIB-OPAC', 'Library App', 'Library IT', 'Bibliographic and patron loan data.', '10.20.5.15', 'Hybrid', 'Library', 'N', 'N', 'Y', 2, 3, 3, 8, 'Restricted', 'cyber_int_vuln', 'Bibliographic and patron loan data.', 3, 3, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-009', 'Approved', 'PhA', 'College of Law Moot Court Recording System', 'Law', 'LAW-MOOT-AV', 'Law Building AV', 'Law IT Coordinator', 'Recording infrastructure for legal training.', '10.20.7.5', 'Internal', 'College of Law', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_theft', 'Recording infrastructure for legal training.', 2, 2, 'Low', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SV-006', 'Approved', 'SV', 'PayMongo Tuition Payment Gateway', 'Finance', 'PAY-GW', 'Payment Service', 'Finance Systems', 'Online tuition payment integration.', 'Cloud', 'Internet Facing', 'Finance', 'N', 'N', 'Y', 2, 2, 3, 7, 'Confidential', 'cyber_ext_supply', 'Online tuition payment integration.', 3, 5, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-011', 'Approved', 'IA', 'Faculty Research Publication Repository', 'Research', 'REPO-DSPACE', 'DSpace Server', 'Research Librarian', 'Thesis and faculty research archive.', '10.60.2.10', 'Hybrid', 'Library / Research', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'cyber_ext_leak', 'Thesis and faculty research archive.', 2, 3, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-010', 'Approved', 'PhA', 'Gusaling Corazon Aquino UPS Battery Banks', 'ICTO', 'GCA-UPS', 'GCA Server Room', 'Facilities Electrician', 'Power backup for GCA data center.', 'N/A', 'Internal', 'Facilities', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_destruct', 'Power backup for GCA data center.', 2, 4, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SA-008', 'Approved', 'SA', 'Campus ID Card Printing Software', 'Security', 'ID-PRINT', 'ID Office Workstation', 'ID Office Supervisor', 'ID card encoding and photo capture.', '10.99.3.10', 'Internal', 'Campus Security', 'N', 'N', 'Y', 2, 3, 3, 8, 'Restricted', 'cyber_ext_leak', 'ID card encoding and photo capture.', 2, 3, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-012', 'Approved', 'IA', 'Athletics Medical Clearance Forms DB', 'Athletics', 'ATH-MED-01', 'Athletics Records', 'Athletics Director', 'Student athlete health clearances.', '10.20.11.5', 'Internal', 'Athletics', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'legal_dpa', 'Student athlete health clearances.', 2, 3, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SV-007', 'Approved', 'SV', 'PLM VPN Remote Access Service', 'ICTO', 'VPN-GW', 'VPN Concentrator', 'Network Lead', 'Remote admin and faculty access.', '10.99.0.1', 'Internet Facing', 'ICTO', 'N', 'N', 'Y', 2, 2, 3, 7, 'Confidential', 'cyber_int_unauth', 'Remote admin and faculty access.', 3, 4, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-011', 'Approved', 'PhA', 'Tanghalang Bayan Stage Lighting Console', 'Cultural Affairs', 'TB-LIGHT', 'Stage Control', 'Stage Manager', 'DMX lighting control for productions.', 'N/A', 'Internal', 'Cultural Affairs', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_theft', 'DMX lighting control for productions.', 2, 2, 'Low', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-013', 'Approved', 'IA', 'International Programs Exchange Records', 'International', 'INTL-REC', 'Intl Office DB', 'International Programs Head', 'Foreign exchange student documentation.', '10.20.12.10', 'Internal', 'International Affairs', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'legal_dpa', 'Foreign exchange student documentation.', 3, 4, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SA-009', 'Approved', 'SA', 'Admission Online Application Portal', 'Admissions', 'ADM-PORTAL', 'Admissions Web', 'Admissions IT', 'Freshman and transferee application pipeline.', '10.20.1.50', 'Internet Facing', 'Admissions', 'N', 'N', 'Y', 2, 3, 3, 8, 'Restricted', 'cyber_ext_leak', 'Freshman and transferee application pipeline.', 4, 4, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-012', 'Approved', 'PhA', 'Science Lab Gas Line Manifold (Intramuros)', 'Sciences', 'SCI-GAS', 'Science Bldg Basement', 'Lab Safety Officer', 'Laboratory gas distribution physical infrastructure.', 'N/A', 'Internal', 'College of Sciences', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_destruct', 'Laboratory gas distribution physical infrastructure.', 1, 5, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('FA-004', 'Approved', 'FA', 'Endowment Investment Portfolio Records', 'Finance', 'ENDOW-PORT', 'Finance Records', 'VP Finance', 'Long-term university investments.', '10.40.4.1', 'Internal', 'Finance', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'cyber_int_unauth', 'Long-term university investments.', 2, 5, 'Moderate', 'High', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-014', 'Approved', 'IA', 'Dormitory Housing Assignment System Data', 'Student Affairs', 'DORM-DB', 'Housing DB', 'Housing Coordinator', 'On-campus housing assignments and billing.', '10.20.9.20', 'Internal', 'Student Affairs', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'cyber_ext_leak', 'On-campus housing assignments and billing.', 3, 3, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SV-008', 'Approved', 'SV', 'Supabase Backend for Intramunotes (BaaS)', 'ICTO', 'INTRA-SUPA', 'Supabase Project', 'Intramunotes DevOps', 'Managed backend for Intramunotes prototype/production.', 'Cloud', 'Internet Facing', 'ICTO', 'N', 'N', 'Y', 2, 2, 3, 7, 'Confidential', 'cyber_ext_supply', 'Managed backend for Intramunotes prototype/production.', 3, 4, 'High', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-013', 'Approved', 'PhA', 'Haribon Field Equipment GPS Trackers', 'Research', 'HARIBON-GPS', 'Field Kit', 'Field Research Lead', 'GPS units for biodiversity field work.', 'N/A', 'Hybrid', 'Research', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_theft', 'GPS units for biodiversity field work.', 3, 2, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SA-010', 'Approved', 'SA', 'Board Room Video Conferencing System', 'Administration', 'BOR-VC', 'Board Room', 'Executive Assistant', 'VC system for regents meetings.', '10.10.1.10', 'Internal', 'Office of the President', 'N', 'N', 'Y', 2, 3, 3, 8, 'Restricted', 'cyber_ext_leak', 'VC system for regents meetings.', 2, 3, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-015', 'Approved', 'IA', 'Faculty Evaluation (SET) Results Warehouse', 'Academic', 'SET-WAREHOUSE', 'Academic DB', 'Academic Planning', 'Aggregated teaching evaluation scores.', '10.20.10.20', 'Internal', 'Academic Affairs', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'hr_insider', 'Aggregated teaching evaluation scores.', 2, 3, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('PhA-014', 'Approved', 'PhA', 'PLM Intramuros Generator Sets', 'Facilities', 'GEN-INTRAM', 'Power House', 'Facilities Manager', 'Emergency generators for main campus.', 'N/A', 'Internal', 'Facilities Management', 'N', 'N', 'N', 1, 1, 2, 4, 'Internal Use', 'phys_destruct', 'Emergency generators for main campus.', 2, 5, 'Moderate', 'Moderate', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('SV-009', 'Approved', 'SV', 'ICTO Service Desk Ticketing (osTicket)', 'ICTO', 'SD-TICKET', 'Helpdesk Server', 'Service Desk Lead', 'IT support ticket tracking.', '10.99.5.10', 'Internal', 'ICTO', 'N', 'N', 'Y', 2, 2, 3, 7, 'Confidential', 'cyber_int_vuln', 'IT support ticket tracking.', 3, 2, 'Moderate', 'Low', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31'),
('IA-016', 'Approved', 'IA', 'Procurement Bid Document Repository', 'Procurement', 'PROC-BIDS', 'Procurement Share', 'BAC Secretariat', 'Sensitive bid proposals and awards.', '10.40.6.10', 'Internal', 'Procurement', 'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 'hr_insider', 'Sensitive bid proposals and awards.', 2, 4, 'Moderate', 'High', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31');

INSERT INTO public."AssetControls" (asset_id, ctrl_id) VALUES
  ('IA-001', 1),
  ('IA-001', 3),
  ('IA-001', 4),
  ('IA-001', 7),
  ('IA-001', 9),
  ('IA-001', 10),
  ('IA-001', 11),
  ('IA-001', 12),
  ('IA-002', 1),
  ('IA-002', 3),
  ('IA-002', 4),
  ('IA-002', 7),
  ('IA-002', 8),
  ('IA-003', 3),
  ('IA-003', 4),
  ('IA-003', 7),
  ('IA-003', 9),
  ('IA-003', 10),
  ('IA-004', 1),
  ('IA-004', 3),
  ('IA-004', 4),
  ('IA-004', 10),
  ('IA-004', 13),
  ('IA-005', 2),
  ('IA-005', 3),
  ('IA-005', 4),
  ('IA-005', 12),
  ('IA-006', 3),
  ('IA-006', 4),
  ('IA-006', 7),
  ('IA-006', 9),
  ('IA-006', 10),
  ('IA-007', 2),
  ('IA-007', 3),
  ('IA-007', 4),
  ('IA-007', 12),
  ('IA-008', 2),
  ('IA-008', 3),
  ('IA-008', 4),
  ('IA-008', 12),
  ('PhA-001', 5),
  ('PhA-001', 6),
  ('PhA-001', 13),
  ('PhA-002', 5),
  ('PhA-002', 13),
  ('PhA-003', 5),
  ('PhA-003', 7),
  ('PhA-003', 8),
  ('PhA-004', 5),
  ('PhA-004', 7),
  ('PhA-004', 8),
  ('PhA-005', 5),
  ('PhA-005', 7),
  ('PhA-005', 8),
  ('PhA-006', 5),
  ('PhA-006', 7),
  ('PhA-006', 8),
  ('PhA-007', 5),
  ('PhA-007', 6),
  ('PhA-007', 13),
  ('PhA-008', 5),
  ('PhA-008', 7),
  ('PhA-008', 8),
  ('SA-001', 9),
  ('SA-001', 10),
  ('SA-001', 11),
  ('SA-001', 12),
  ('SA-002', 10),
  ('SA-002', 12),
  ('SA-002', 13),
  ('SA-003', 9),
  ('SA-003', 10),
  ('SA-003', 11),
  ('SA-003', 12),
  ('SA-004', 2),
  ('SA-004', 3),
  ('SA-004', 4),
  ('SA-004', 9),
  ('SA-005', 1),
  ('SA-005', 3),
  ('SA-005', 6),
  ('SA-006', 9),
  ('SA-006', 10),
  ('SA-006', 11),
  ('SA-006', 12),
  ('SV-001', 10),
  ('SV-001', 12),
  ('SV-001', 13),
  ('SV-002', 1),
  ('SV-002', 3),
  ('SV-002', 4),
  ('SV-002', 10),
  ('SV-002', 13),
  ('SV-003', 2),
  ('SV-003', 3),
  ('SV-003', 4),
  ('SV-003', 9),
  ('SV-004', 10),
  ('SV-004', 12),
  ('SV-004', 13),
  ('SV-005', 1),
  ('SV-005', 3),
  ('SV-005', 4),
  ('SV-005', 10),
  ('SV-005', 13),
  ('PA-001', 2),
  ('PA-001', 3),
  ('PA-001', 4),
  ('PA-001', 12),
  ('PA-002', 2),
  ('PA-002', 3),
  ('PA-002', 4),
  ('PA-002', 9),
  ('PA-003', 1),
  ('PA-003', 3),
  ('PA-003', 6),
  ('PA-004', 2),
  ('PA-004', 3),
  ('PA-004', 4),
  ('PA-004', 12),
  ('FA-001', 2),
  ('FA-001', 3),
  ('FA-001', 4),
  ('FA-001', 9),
  ('FA-002', 5),
  ('FA-002', 7),
  ('FA-002', 8),
  ('FA-003', 1),
  ('FA-003', 7),
  ('FA-003', 8),
  ('IA-009', 1),
  ('IA-009', 7),
  ('IA-009', 8),
  ('IA-010', 1),
  ('IA-010', 7),
  ('IA-010', 8),
  ('SA-007', 9),
  ('SA-007', 10),
  ('SA-007', 11),
  ('SA-007', 12),
  ('PhA-009', 5),
  ('PhA-009', 7),
  ('PhA-009', 8),
  ('SV-006', 1),
  ('SV-006', 3),
  ('SV-006', 4),
  ('SV-006', 10),
  ('SV-006', 13),
  ('IA-011', 3),
  ('IA-011', 4),
  ('IA-011', 7),
  ('IA-011', 9),
  ('IA-011', 10),
  ('PhA-010', 5),
  ('PhA-010', 6),
  ('PhA-010', 13),
  ('SA-008', 3),
  ('SA-008', 4),
  ('SA-008', 7),
  ('SA-008', 9),
  ('SA-008', 10),
  ('IA-012', 1),
  ('IA-012', 7),
  ('IA-012', 8),
  ('SV-007', 2),
  ('SV-007', 3),
  ('SV-007', 4),
  ('SV-007', 9),
  ('PhA-011', 5),
  ('PhA-011', 7),
  ('PhA-011', 8),
  ('IA-013', 1),
  ('IA-013', 7),
  ('IA-013', 8),
  ('SA-009', 3),
  ('SA-009', 4),
  ('SA-009', 7),
  ('SA-009', 9),
  ('SA-009', 10),
  ('PhA-012', 5),
  ('PhA-012', 6),
  ('PhA-012', 13),
  ('FA-004', 2),
  ('FA-004', 3),
  ('FA-004', 4),
  ('FA-004', 9),
  ('IA-014', 3),
  ('IA-014', 4),
  ('IA-014', 7),
  ('IA-014', 9),
  ('IA-014', 10),
  ('SV-008', 1),
  ('SV-008', 3),
  ('SV-008', 4),
  ('SV-008', 10),
  ('SV-008', 13),
  ('PhA-013', 5),
  ('PhA-013', 7),
  ('PhA-013', 8),
  ('SA-010', 3),
  ('SA-010', 4),
  ('SA-010', 7),
  ('SA-010', 9),
  ('SA-010', 10),
  ('IA-015', 2),
  ('IA-015', 3),
  ('IA-015', 4),
  ('IA-015', 12),
  ('PhA-014', 5),
  ('PhA-014', 6),
  ('PhA-014', 13),
  ('SV-009', 9),
  ('SV-009', 10),
  ('SV-009', 11),
  ('SV-009', 12),
  ('IA-016', 2),
  ('IA-016', 3),
  ('IA-016', 4),
  ('IA-016', 12)
ON CONFLICT DO NOTHING;

-- ============================================================
-- 5. ACTION-PLAN DIVERSIFICATION — ISO/IEC 27005:2022 risk treatments
--    Mitigate (apply controls) · Transfer (cloud / insurance) ·
--    Avoid (decommission) · Accept (formal sign-off).
--    Plants 8 deadlines within 14 days for the dashboard KPI demo.
-- ============================================================

-- A. Mitigate — high priority, due within 14 days of seed
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Apply DB encryption-at-rest (AES-256) and quarterly access review aligned with ISO/IEC 27001 A.8.24 and NIST SP 800-53 SC-28.',
  "actionOwner"='ICTO Security Lead',     "actionDate"=(current_date +  5)::text WHERE id='IA-001';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Patch SQLi vulnerability surfaced in pen-test; redeploy mobile API with parameterized queries and SAST gate in CI.',
  "actionOwner"='ICTO App Dev Lead',      "actionDate"=(current_date +  3)::text WHERE id='IA-003';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Deploy MFA for clinical staff and roll out at-rest encryption for EMR per Data Privacy Act IRR Rule VI.',
  "actionOwner"='Clinic IT Coordinator',  "actionDate"=(current_date +  8)::text WHERE id='IA-006';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='OWASP Top-10 hardening + WAF rule update for student portal; SAST + DAST scan to be run before promotion.',
  "actionOwner"='Web Development Team',   "actionDate"=(current_date + 11)::text WHERE id='SA-003';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='PCI-DSS quarterly external ASV scan + HSM-managed key rotation; submit ROC evidence to acquirer.',
  "actionOwner"='Finance IT',             "actionDate"=(current_date +  6)::text WHERE id='FA-001';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Roll out PAM for all domain admins; enable session recording and JIT elevation.',
  "actionOwner"='ICTO Director',          "actionDate"=(current_date +  9)::text WHERE id='PA-002';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Implement DLP for donor PII; verify field-level encryption on SPI columns (NIST 800-53 SC-28 / ISO 27002 8.24).',
  "actionOwner"='Scholarship Office Head',"actionDate"=(current_date + 13)::text WHERE id='IA-002';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Submit signed PCI-DSS SAQ-A and rotate API keys with PayMongo; confirm webhook signature validation in code.',
  "actionOwner"='Finance Systems',        "actionDate"=(current_date + 12)::text WHERE id='SV-006';

-- B. Mitigate — Q3 2026
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Quarterly access review for HRIS workflow approvers; integrate audit-log forwarding to SIEM.',
  "actionOwner"='HR Systems Admin',         "actionDate"='2026-06-30' WHERE id='SA-004';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Enforce TLS 1.3 across Intramunotes API; enable App Transport Security on iOS and certificate pinning on Android.',
  "actionOwner"='Mobile Dev Lead',          "actionDate"='2026-07-15' WHERE id='SA-001';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Roll WPA3-Enterprise across Eduroam SSIDs; phase out PEAP/MSCHAPv2 for student logins.',
  "actionOwner"='Network Operations',       "actionDate"='2026-08-01' WHERE id='SV-003';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Quarterly DR drill: UPS battery health, cooling failover, and backup-restore validation.',
  "actionOwner"='ICTO Infrastructure',      "actionDate"='2026-09-10' WHERE id='PhA-001';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Annual disciplinary file retention review; redact resolved cases per DPA Section 16.',
  "actionOwner"='Dean of Student Affairs',  "actionDate"='2026-08-30' WHERE id='IA-009';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Apply CIS Benchmark hardening to VPN concentrator; enforce always-on MFA and device-posture check.',
  "actionOwner"='Network Lead',             "actionDate"='2026-07-20' WHERE id='SV-007';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Onboard admissions portal into central WAF; enable bot-mitigation and ATO protection on application form.',
  "actionOwner"='Admissions IT',            "actionDate"='2026-06-15' WHERE id='SA-009';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Encrypt portfolio records with column-level KMS; quarterly review of authorized signatories by VP-Finance.',
  "actionOwner"='VP Finance',               "actionDate"='2026-07-31' WHERE id='FA-004';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Annual review of governance archive access; restrict to BoR Secretariat under need-to-know.',
  "actionOwner"='Board Secretary',          "actionDate"='2026-09-30' WHERE id='IA-008';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Quarterly procurement document classification + need-to-know access review per ISO 27002 5.10.',
  "actionOwner"='BAC Secretariat',          "actionDate"='2026-08-15' WHERE id='IA-016';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Encrypt international exchange records and align with foreign-data-transfer rules under DPA Section 21.',
  "actionOwner"='International Programs Head',"actionDate"='2026-08-20' WHERE id='IA-013';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='In Progress',
  "actionPlan"='Annual audit of CCTV retention; physically secure NVR rack with key-controlled access.',
  "actionOwner"='Chief of Security',        "actionDate"='2026-09-30' WHERE id='PhA-007';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='Pending',
  "actionPlan"='Schedule quarterly CRM access review; deduplicate alumni records per DPA data-quality principle.',
  "actionOwner"='Alumni Affairs Director',  "actionDate"='2026-07-10' WHERE id='IA-005';

-- C. Transfer — risk shifted to provider, insurer, or contract
UPDATE public."Assets" SET "actionType"='Transfer', "actionStatus"='In Progress',
  "actionPlan"='Risk transferred via AWS Shared Responsibility Model + Customer-Managed KMS; annual SOC 2 Type II review.',
  "actionOwner"='Cloud Administrator',      "actionDate"='2026-09-30' WHERE id='IA-004';
UPDATE public."Assets" SET "actionType"='Transfer', "actionStatus"='In Progress',
  "actionPlan"='Hosting layer transferred to AWS under Shared Responsibility; verify SOC 2 attestation.',
  "actionOwner"='Cloud Administrator',      "actionDate"='2026-10-15' WHERE id='SV-005';
UPDATE public."Assets" SET "actionType"='Transfer', "actionStatus"='In Progress',
  "actionPlan"='Microsoft 365 E5 license — risk transferred to Microsoft per OST/DPA. Annual Secure Score review.',
  "actionOwner"='Mail Administrator',       "actionDate"='2026-12-01' WHERE id='SV-002';
UPDATE public."Assets" SET "actionType"='Transfer', "actionStatus"='Done',
  "actionPlan"='Cloudflare Enterprise plan with DDoS guarantee — financial liability transferred per signed MSA.',
  "actionOwner"='Infrastructure Lead',      "actionDate"='2026-05-10' WHERE id='SV-004';
UPDATE public."Assets" SET "actionType"='Transfer', "actionStatus"='In Progress',
  "actionPlan"='Cyber-liability insurance with PhP 50M cap renewed; residual financial impact transferred to underwriter.',
  "actionOwner"='VP Finance',               "actionDate"='2026-06-30' WHERE id='FA-002';
UPDATE public."Assets" SET "actionType"='Transfer', "actionStatus"='In Progress',
  "actionPlan"='Supabase Cloud — risk transferred under Pro plan SLA; quarterly review of breach-notification clauses.',
  "actionOwner"='Intramunotes DevOps',      "actionDate"='2026-07-10' WHERE id='SV-008';
UPDATE public."Assets" SET "actionType"='Transfer', "actionStatus"='In Progress',
  "actionPlan"='Disbursement risk transferred to partner bank per signed depository agreement; monthly reconciliation.',
  "actionOwner"='Scholarship Accountant',   "actionDate"='2026-08-31' WHERE id='FA-003';

-- D. Avoid — cease the activity / decommission legacy
UPDATE public."Assets" SET "actionType"='Avoid', "actionStatus"='In Progress',
  "actionPlan"='Legacy COVID health declaration archive — disposal scheduled; collection ceased (DPA data minimization).',
  "actionOwner"='Clinic Admin',             "actionDate"='2026-08-31' WHERE id='IA-010';
UPDATE public."Assets" SET "actionType"='Avoid', "actionStatus"='In Progress',
  "actionPlan"='Decommission self-managed osTicket; replace with vendor-hosted ITSM in Q4 — risk avoided.',
  "actionOwner"='Service Desk Lead',        "actionDate"='2026-10-31' WHERE id='SV-009';
UPDATE public."Assets" SET "actionType"='Avoid', "actionStatus"='In Progress',
  "actionPlan"='Stop using self-managed Library OPAC; migrate to vendor-hosted catalog. Activity ceased Q3 2026.',
  "actionOwner"='Library IT',               "actionDate"='2026-09-15' WHERE id='SA-007';
UPDATE public."Assets" SET "actionType"='Avoid', "actionStatus"='Pending',
  "actionPlan"='Phase out unmanaged wireless mics; replace with university-issued, asset-tagged units only.',
  "actionOwner"='Events Coordinator',       "actionDate"='2026-07-31' WHERE id='PhA-004';

-- E. Accept — formal sign-off (mitigation cost > residual exposure)
UPDATE public."Assets" SET "actionType"='Accept', "actionStatus"='Done',
  "actionPlan"='Residual risk Low/Very Low; cost of further mitigation outweighs exposure. Formally accepted by CISO sign-off.',
  "actionOwner"='CISO',                     "actionDate"='2026-05-15'
  WHERE id IN ('PhA-003','PhA-006','PhA-009','PhA-011','PhA-013');
UPDATE public."Assets" SET "actionType"='Accept', "actionStatus"='Done',
  "actionPlan"='Low residual risk for non-PII operational asset; accepted by Asset Owner with annual review per ISO 27005 §10.',
  "actionOwner"='Asset Owner',              "actionDate"='2026-05-12'
  WHERE id IN ('SA-008','PhA-005','PhA-008');

-- F. Done — historic mitigations now closed
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='Done',
  "actionPlan"='EDR (CrowdStrike) deployed to 100% of HR workstations; closure validated by InfoSec.',
  "actionOwner"='HR IT',                    "actionDate"='2026-04-30' WHERE id='IA-007';
UPDATE public."Assets" SET "actionType"='Mitigate', "actionStatus"='Done',
  "actionPlan"='Network segmentation for Finance VLAN completed and validated by independent assessor.',
  "actionOwner"='Network Operations',       "actionDate"='2026-05-05' WHERE id='SA-005';

-- G. Spread remaining default-2026-12-31 mitigations realistically
UPDATE public."Assets" SET "actionDate"='2026-09-30',
  "actionPlan"='Quarterly review per ISMS schedule; controls verified against ISO/IEC 27001 Annex A.'
WHERE "actionType"='Mitigate' AND "actionDate"='2026-12-31' AND residual='Moderate';

UPDATE public."Assets" SET "actionDate"='2026-11-30',
  "actionPlan"='Annual control review and audit; align with NIST CSF Identify and Protect functions.'
WHERE "actionType"='Mitigate' AND "actionDate"='2026-12-31' AND residual IN ('Low','Very Low');

-- =====================================================================
-- 5. RISK-MATH REALIGNMENT
--    Re-derives prob / sev / inherit / residual / actionType for every
--    seeded asset using the cybersecurity-grade engine (NIST SP 800-30,
--    ISO 27005/27001:2022, CIS v8, SOC 2 TSC, PCI-DSS v4.0, RA 10173).
--    Mirrors CONTROL_WEIGHTS / CONTROL_SYNERGIES / MANDATORY_CONTROLS in
--    assets/scripts/app.js. Idempotent — safe to re-run.
-- =====================================================================

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

-- Step 1: Inherent escalations
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
UPDATE public."Assets" SET inherit = public.il_inherit(sev, prob);

-- Step 2: Residual recompute with weighted DiD + synergies + mandatory floors
DO $real$
DECLARE
  r RECORD; ctrls int[]; rel_set int[]; cia int; cid int;
  pRedRaw numeric; sRedRaw numeric; pRed numeric; sRed numeric;
  capP numeric; capS numeric; resP int; resS int;
  residual_rating text;
  has_rbac bool; has_mfa bool; has_backup bool; has_crypto bool; has_irp bool;
  has_proc bool; has_vuln bool; has_seg bool; has_fw bool;
  is_internet bool; is_pci bool; has_pii bool; is_restricted bool; is_confid bool;
  floor_rank int; floor_name text; cur_rank int;
BEGIN
  FOR r IN SELECT * FROM public."Assets" LOOP
    SELECT COALESCE(array_agg(ctrl_id ORDER BY ctrl_id), ARRAY[]::int[]) INTO ctrls
      FROM public."AssetControls" WHERE asset_id = r.id;
    cia := r."ciaC" + r."ciaI" + r."ciaA";
    rel_set := CASE r."riskCategory"
      WHEN 'phys_theft' THEN ARRAY[1,5,7,8]
      WHEN 'phys_destruct' THEN ARRAY[1,5,6,12,13]
      WHEN 'hr_insider' THEN ARRAY[1,2,3,4,9,12]
      WHEN 'hr_accidental' THEN ARRAY[1,3,6,13]
      WHEN 'cyber_ext_ransomware' THEN ARRAY[1,4,6,7,9,10,11,13]
      WHEN 'cyber_ext_leak' THEN ARRAY[1,3,4,7,9,10,12]
      WHEN 'cyber_ext_ddos' THEN ARRAY[10,11,12,13]
      WHEN 'cyber_ext_supply' THEN ARRAY[1,3,4,7,10,11,13]
      WHEN 'cyber_int_unauth' THEN ARRAY[1,2,3,4,9,13]
      WHEN 'cyber_int_vuln' THEN ARRAY[1,9,10,11,12]
      WHEN 'legal_dpa' THEN ARRAY[1,3,7,8,13]
      ELSE ARRAY[1,2,3,4,5,6,7,8,9,10,11,12,13]
    END;
    pRedRaw := 0; sRedRaw := 0;
    FOREACH cid IN ARRAY ctrls LOOP
      IF cid = ANY(rel_set) THEN
        pRedRaw := pRedRaw + CASE cid
          WHEN 1 THEN 0.5 WHEN 2 THEN 0.6 WHEN 3 THEN 0.9 WHEN 4 THEN 1.0
          WHEN 5 THEN 0.7 WHEN 6 THEN 0.0 WHEN 7 THEN 0.0 WHEN 8 THEN 0.3
          WHEN 9 THEN 0.6 WHEN 10 THEN 0.9 WHEN 11 THEN 0.9 WHEN 12 THEN 0.7
          WHEN 13 THEN 0.0 ELSE 0 END;
        sRedRaw := sRedRaw + CASE cid
          WHEN 1 THEN 0.3 WHEN 2 THEN 0.3 WHEN 3 THEN 0.4 WHEN 4 THEN 0.4
          WHEN 5 THEN 0.4 WHEN 6 THEN 1.2 WHEN 7 THEN 1.4 WHEN 8 THEN 0.5
          WHEN 9 THEN 0.7 WHEN 10 THEN 0.4 WHEN 11 THEN 0.3 WHEN 12 THEN 0.5
          WHEN 13 THEN 1.1 ELSE 0 END;
      END IF;
    END LOOP;
    IF 3=ANY(ctrls) AND 4=ANY(ctrls) AND 3=ANY(rel_set) AND 4=ANY(rel_set) THEN pRedRaw := pRedRaw + 0.5; END IF;
    IF 6=ANY(ctrls) AND 13=ANY(ctrls) AND 6=ANY(rel_set) AND 13=ANY(rel_set) THEN sRedRaw := sRedRaw + 0.5; END IF;
    IF 9=ANY(ctrls) AND 10=ANY(ctrls) AND 9=ANY(rel_set) AND 10=ANY(rel_set) THEN pRedRaw := pRedRaw + 0.4; END IF;
    IF 7=ANY(ctrls) AND 12=ANY(ctrls) AND 7=ANY(rel_set) AND 12=ANY(rel_set) THEN sRedRaw := sRedRaw + 0.4; END IF;
    IF 11=ANY(ctrls) AND 9=ANY(ctrls) AND 13=ANY(ctrls)
       AND 11=ANY(rel_set) AND 9=ANY(rel_set) AND 13=ANY(rel_set) THEN
      pRedRaw := pRedRaw + 0.3; sRedRaw := sRedRaw + 0.3;
    END IF;
    capP := GREATEST(0, r.prob - 1); capS := GREATEST(0, r.sev - 1);
    pRed := CASE WHEN pRedRaw <= 0 THEN 0 ELSE LEAST(capP, capP * (1 - exp(-pRedRaw / 2.0))) END;
    sRed := CASE WHEN sRedRaw <= 0 THEN 0 ELSE LEAST(capS, capS * (1 - exp(-sRedRaw / 2.0))) END;
    resP := GREATEST(1, ROUND(r.prob - pRed)::int);
    resS := GREATEST(1, ROUND(r.sev  - sRed)::int);
    residual_rating := public.il_inherit(resS, resP);
    has_rbac:=3=ANY(ctrls); has_mfa:=4=ANY(ctrls); has_backup:=6=ANY(ctrls);
    has_crypto:=7=ANY(ctrls); has_irp:=13=ANY(ctrls); has_proc:=1=ANY(ctrls);
    has_vuln:=11=ANY(ctrls); has_seg:=12=ANY(ctrls); has_fw:=10=ANY(ctrls);
    is_internet:=r.environment='Internet Facing'; is_pci:=r.type='FA';
    has_pii:=r.pii='Y' OR r.spi='Y'; is_restricted:=cia>=8; is_confid:=cia BETWEEN 6 AND 7;
    floor_rank := 0; floor_name := 'Very Low';
    IF is_restricted AND NOT (has_rbac AND has_mfa AND has_backup AND has_crypto AND has_irp) THEN
      IF floor_rank < 2 THEN floor_rank := 2; floor_name := 'Moderate'; END IF;
    END IF;
    IF is_confid AND NOT (has_rbac AND has_crypto AND has_irp) THEN
      IF floor_rank < 2 THEN floor_rank := 2; floor_name := 'Moderate'; END IF;
    END IF;
    IF is_pci AND NOT (has_mfa AND has_crypto AND has_vuln AND has_seg) THEN
      IF floor_rank < 3 THEN floor_rank := 3; floor_name := 'High'; END IF;
    END IF;
    IF has_pii AND NOT (has_proc AND has_rbac AND has_backup AND has_crypto) THEN
      IF floor_rank < 2 THEN floor_rank := 2; floor_name := 'Moderate'; END IF;
    END IF;
    IF is_internet AND NOT (has_fw AND has_vuln AND has_irp) THEN
      IF floor_rank < 2 THEN floor_rank := 2; floor_name := 'Moderate'; END IF;
    END IF;
    cur_rank := CASE residual_rating WHEN 'Very Low' THEN 0 WHEN 'Low' THEN 1
      WHEN 'Moderate' THEN 2 WHEN 'High' THEN 3 ELSE 2 END;
    IF cur_rank < floor_rank THEN
      residual_rating := floor_name;
      IF floor_name='High'     THEN resP:=GREATEST(resP,4); resS:=GREATEST(resS,4); END IF;
      IF floor_name='Moderate' THEN resP:=GREATEST(resP,3); resS:=GREATEST(resS,3); END IF;
    END IF;
    UPDATE public."Assets" SET residual = residual_rating WHERE id = r.id;
  END LOOP;
END
$real$;

-- Step 3: Risk-appetite enforcement on actionType
UPDATE public."Assets" SET "actionType" = 'Mitigate'
WHERE "actionType" = 'Accept'
  AND ( residual = 'High'
     OR (type = 'FA' AND residual NOT IN ('Low', 'Very Low'))
     OR ("ciaScore" >= 8 AND residual = 'Moderate') );

-- Done. Next:
--   1) Authentication → Providers → Email is enabled (default).
--   2) Authentication → Sign Up: leave "Confirm email" ON for real verification.
--   3) Register admin@plm.edu.ph from the app or the Auth dashboard.
--      The trigger above auto-promotes admin@, infosec@, user@ (all @plm.edu.ph)
--      to active accounts upon email verification.
--   4) Optional: run supabase/hotfix_demo_accounts.sql to seed pre-created
--      infosec@plm.edu.ph and user@plm.edu.ph accounts (no email step).
