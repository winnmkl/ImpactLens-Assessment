-- =================================================================
-- HOTFIX: Manually confirm a user's email when Supabase cannot send mail
-- Run in: https://supabase.com/dashboard/project/haspklehikocqswmgmtk/sql/new
-- Replace the email below, then Run.
-- =================================================================

DO $body$
DECLARE
  v_email text := 'winfred3190@gmail.com';  -- ← change if needed
BEGIN
  UPDATE auth.users
  SET
    email_confirmed_at = COALESCE(email_confirmed_at, now()),
    confirmed_at       = COALESCE(confirmed_at, now()),
    updated_at         = now()
  WHERE lower(email) = lower(v_email);

  IF NOT FOUND THEN
    RAISE EXCEPTION 'No auth.users row for %', v_email;
  END IF;
END;
$body$;

-- user_profiles row is created/updated by handle_user_email_confirmed trigger on confirm.
-- Verify:
-- SELECT email, email_confirmed_at FROM auth.users WHERE lower(email) = 'winfred3190@gmail.com';
-- SELECT email, account_status, requested_role FROM public.user_profiles WHERE lower(email) = 'winfred3190@gmail.com';
