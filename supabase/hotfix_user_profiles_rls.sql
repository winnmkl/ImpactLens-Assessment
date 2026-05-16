-- Hotfix: removes the recursive user_profiles policies and replaces them
-- with a SECURITY DEFINER helper. Safe to run multiple times.
-- Apply via: Supabase Dashboard → SQL Editor → New query → Run

DROP POLICY IF EXISTS profiles_select          ON public.user_profiles;
DROP POLICY IF EXISTS profiles_self_update     ON public.user_profiles;
DROP POLICY IF EXISTS profiles_approver_update ON public.user_profiles;
DROP POLICY IF EXISTS profiles_self_insert     ON public.user_profiles;

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

-- Sanity check (optional): show a row count from your own profile
-- SELECT count(*) FROM public.user_profiles WHERE id = auth.uid();
