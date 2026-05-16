-- ImpactLens Phase 2: workflow status + audit logs
-- Run in Supabase SQL Editor (project: haspklehikocqswmgmtk)

ALTER TABLE public."Assets"
  ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'Draft';

ALTER TABLE public."Assets"
  ADD COLUMN IF NOT EXISTS created_by text;

ALTER TABLE public."Assets"
  ADD COLUMN IF NOT EXISTS updated_by text;

ALTER TABLE public."Assets"
  ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;

UPDATE public."Assets"
SET status = 'Approved'
WHERE status IS NULL OR status = 'Draft';

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
CREATE INDEX IF NOT EXISTS idx_system_logs_created ON public."SystemLogs" (created_at DESC);
