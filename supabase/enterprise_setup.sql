-- ImpactLens Enterprise — user profiles, approvals, RLS
-- Run AFTER setup_database.sql in Supabase SQL Editor
-- Project: https://supabase.com/dashboard/project/haspklehikocqswmgmtk/sql/new

-- ---------------------------------------------------------------------------
-- 1. USER PROFILES (roles & account approvals)
-- ---------------------------------------------------------------------------

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

CREATE INDEX IF NOT EXISTS idx_user_profiles_status ON public.user_profiles (account_status);
CREATE INDEX IF NOT EXISTS idx_user_profiles_email ON public.user_profiles (email);

-- Auto-create profile on Auth signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.user_profiles (id, email, requested_role, account_status)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'requested_role', 'user'),
    'pending'
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ---------------------------------------------------------------------------
-- 2. RLS — profiles
-- ---------------------------------------------------------------------------

ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "profiles_select_own" ON public.user_profiles;
DROP POLICY IF EXISTS "profiles_update_own" ON public.user_profiles;
DROP POLICY IF EXISTS "profiles_insert_own" ON public.user_profiles;
DROP POLICY IF EXISTS "profiles_approver_update" ON public.user_profiles;

CREATE POLICY "profiles_select_own" ON public.user_profiles
  FOR SELECT TO authenticated
  USING (auth.uid() = id OR EXISTS (
    SELECT 1 FROM public.user_profiles up
    WHERE up.id = auth.uid()
      AND up.account_status = 'active'
      AND up.approved_role IN ('infosec', 'admin')
  ));

CREATE POLICY "profiles_insert_own" ON public.user_profiles
  FOR INSERT TO authenticated
  WITH CHECK (auth.uid() = id);

CREATE POLICY "profiles_update_own" ON public.user_profiles
  FOR UPDATE TO authenticated
  USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);

CREATE POLICY "profiles_approver_update" ON public.user_profiles
  FOR UPDATE TO authenticated
  USING (EXISTS (
    SELECT 1 FROM public.user_profiles up
    WHERE up.id = auth.uid()
      AND up.account_status = 'active'
      AND (
        (up.approved_role = 'admin')
        OR (up.approved_role = 'infosec' AND user_profiles.requested_role = 'user')
      )
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM public.user_profiles up
    WHERE up.id = auth.uid()
      AND up.account_status = 'active'
      AND up.approved_role IN ('infosec', 'admin')
  ));

GRANT SELECT, INSERT, UPDATE ON public.user_profiles TO authenticated;

-- ---------------------------------------------------------------------------
-- 3. MASTER ADMIN PROFILE SEED
-- ---------------------------------------------------------------------------
-- Step A: In Supabase Dashboard → Authentication → Users → Add user:
--   Email: admin@plm.edu.ph  |  Password: (your secure password)  |  Auto Confirm: ON
-- Step B: Run the block below (links profile to that Auth user)

INSERT INTO public.user_profiles (id, email, requested_role, approved_role, account_status, approved_at)
SELECT
  u.id,
  u.email,
  'admin',
  'admin',
  'active',
  now()
FROM auth.users u
WHERE lower(u.email) = 'admin@plm.edu.ph'
ON CONFLICT (id) DO UPDATE SET
  email = EXCLUDED.email,
  requested_role = 'admin',
  approved_role = 'admin',
  account_status = 'active',
  approved_at = now(),
  updated_at = now();

-- ---------------------------------------------------------------------------
-- 4. OPTIONAL: PLM asset seed (57 assets)
-- Run: supabase/seed_plm_assets.sql after this file
-- ---------------------------------------------------------------------------
