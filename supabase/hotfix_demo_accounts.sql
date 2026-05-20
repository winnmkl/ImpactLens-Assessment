-- =================================================================
-- HOTFIX: Seed Admin + Info Sec + Standard User demo accounts (auto-approved)
-- Run in: https://supabase.com/dashboard/project/haspklehikocqswmgmtk/sql/new
-- Idempotent: safe to re-run; cleans any prior partial entries first.
-- =================================================================

-- 1) Extend the auto-confirm trigger to recognize the demo accounts ----
CREATE OR REPLACE FUNCTION public.handle_user_email_confirmed()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $func$
DECLARE
  v_role   text;
  v_status text;
  v_email  text;
BEGIN
  IF NEW.email_confirmed_at IS NULL THEN
    RETURN NEW;
  END IF;

  v_email := lower(NEW.email);
  v_role  := COALESCE(NEW.raw_user_meta_data->>'requested_role', 'user');
  IF v_role NOT IN ('user', 'infosec', 'admin') THEN
    v_role := 'user';
  END IF;

  IF v_email = 'admin@plm.edu.ph' THEN
    v_role := 'admin';   v_status := 'active';
  ELSIF v_email = 'infosec@plm.edu.ph' THEN
    v_role := 'infosec'; v_status := 'active';
  ELSIF v_email = 'user@plm.edu.ph' THEN
    v_role := 'user';    v_status := 'active';
  ELSE
    v_status := 'pending';
  END IF;

  INSERT INTO public.user_profiles (
    id, email, requested_role, approved_role, account_status, approved_at
  ) VALUES (
    NEW.id, NEW.email, v_role,
    CASE WHEN v_status = 'active' THEN v_role ELSE NULL END,
    v_status,
    CASE WHEN v_status = 'active' THEN now() ELSE NULL END
  )
  ON CONFLICT (id) DO UPDATE SET
    email          = EXCLUDED.email,
    approved_role  = COALESCE(EXCLUDED.approved_role, user_profiles.approved_role),
    account_status = CASE WHEN EXCLUDED.account_status = 'active'
                          THEN 'active' ELSE user_profiles.account_status END,
    approved_at    = COALESCE(user_profiles.approved_at, EXCLUDED.approved_at),
    updated_at     = now();

  RETURN NEW;
END;
$func$;

-- 2) Create the three demo users (deterministic IDs, bcrypt passwords) ---
DO $body$
DECLARE
  v_admin   uuid := '0000aaaa-0000-4000-a000-000000000003';
  v_infosec uuid := '0000aaaa-0000-4000-a000-000000000001';
  v_user    uuid := '0000aaaa-0000-4000-a000-000000000002';
BEGIN
  -- Cleanup any prior partial state
  DELETE FROM auth.identities    WHERE user_id IN (v_admin, v_infosec, v_user);
  DELETE FROM public.user_profiles WHERE id      IN (v_admin, v_infosec, v_user);
  DELETE FROM auth.users         WHERE id        IN (v_admin, v_infosec, v_user);
  DELETE FROM auth.users         WHERE lower(email) IN ('admin@plm.edu.ph','infosec@plm.edu.ph','user@plm.edu.ph');

  -- Insert auth.users (email_confirmed_at=now() makes them sign-in ready)
  INSERT INTO auth.users (
    instance_id, id, aud, role, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
    created_at, updated_at,
    confirmation_token, recovery_token, email_change_token_new, email_change
  ) VALUES
  (
    '00000000-0000-0000-0000-000000000000',
    v_admin, 'authenticated', 'authenticated',
    'admin@plm.edu.ph',
    crypt('IAS_AdminAccount2526@', gen_salt('bf')),
    now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    '{"requested_role":"admin"}'::jsonb,
    now(), now(), '', '', '', ''
  ),
  (
    '00000000-0000-0000-0000-000000000000',
    v_infosec, 'authenticated', 'authenticated',
    'infosec@plm.edu.ph',
    crypt('IAS_InfosecAccount2526@', gen_salt('bf')),
    now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    '{"requested_role":"infosec"}'::jsonb,
    now(), now(), '', '', '', ''
  ),
  (
    '00000000-0000-0000-0000-000000000000',
    v_user, 'authenticated', 'authenticated',
    'user@plm.edu.ph',
    crypt('IAS_UserAccount2526@', gen_salt('bf')),
    now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    '{"requested_role":"user"}'::jsonb,
    now(), now(), '', '', '', ''
  );

  -- Identities row is required for password sign-in in modern Supabase
  INSERT INTO auth.identities (
    provider_id, user_id, identity_data, provider,
    last_sign_in_at, created_at, updated_at
  ) VALUES
  (
    v_admin::text, v_admin,
    jsonb_build_object('sub', v_admin::text, 'email', 'admin@plm.edu.ph', 'email_verified', true),
    'email', now(), now(), now()
  ),
  (
    v_infosec::text, v_infosec,
    jsonb_build_object('sub', v_infosec::text, 'email', 'infosec@plm.edu.ph', 'email_verified', true),
    'email', now(), now(), now()
  ),
  (
    v_user::text, v_user,
    jsonb_build_object('sub', v_user::text, 'email', 'user@plm.edu.ph', 'email_verified', true),
    'email', now(), now(), now()
  );

  -- Force-active profiles (trigger fires too; ON CONFLICT keeps us aligned)
  INSERT INTO public.user_profiles (id, email, requested_role, approved_role, account_status, approved_at)
  VALUES
    (v_admin,   'admin@plm.edu.ph',   'admin',   'admin',   'active', now()),
    (v_infosec, 'infosec@plm.edu.ph', 'infosec', 'infosec', 'active', now()),
    (v_user,    'user@plm.edu.ph',    'user',    'user',    'active', now())
  ON CONFLICT (id) DO UPDATE SET
    approved_role  = EXCLUDED.approved_role,
    account_status = 'active',
    approved_at    = COALESCE(user_profiles.approved_at, EXCLUDED.approved_at),
    updated_at     = now();
END
$body$;

-- 3) Sanity check (uncomment to view results):
-- SELECT email, requested_role, approved_role, account_status FROM public.user_profiles
-- WHERE email IN ('admin@plm.edu.ph','infosec@plm.edu.ph','user@plm.edu.ph');
