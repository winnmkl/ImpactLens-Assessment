-- Log USER_REQUEST when a verified signup creates a pending user_profiles row.
-- Run after master_setup.sql so approvers get notifications in System Logs.

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
    v_role := 'admin'; v_status := 'active';
  ELSIF lower(NEW.email) = 'infosec@plm.edu.ph' THEN
    v_role := 'infosec'; v_status := 'active';
  ELSIF lower(NEW.email) = 'user@plm.edu.ph' THEN
    v_role := 'user'; v_status := 'active';
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
    email = EXCLUDED.email,
    updated_at = now();

  IF v_status = 'pending' THEN
    INSERT INTO public."SystemLogs" (user_email, user_role, action, details)
    VALUES (
      NEW.email,
      v_role,
      'USER_REQUEST',
      'target=' || NEW.email || ' · requested_role=' || v_role || ' · account_status=pending'
    );
  END IF;

  RETURN NEW;
END;
$$;
