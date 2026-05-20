# ImpactLens — Vercel deployment

Static site (vanilla HTML/CSS/JS). Site files live in **`public/`** (committed to git). Supabase client loads from CDN in `public/index.html`.

## Production URLs

| Project | URL | Notes |
|---------|-----|--------|
| **Primary** | https://impactlens-assessment.vercel.app | Project `impactlens-assessment` |
| GitHub import | `impact-lens-assessment-mcr7` | Same repo, same `public/` output |

Both projects use **`outputDirectory: public`** in `vercel.json`. The folder is in git — no build copy step required.

---

## Local dev

```bash
npm start
```

Serves **`public/`** at http://localhost:8000

Edit files under `public/index.html` and `public/assets/`.

---

## GitHub → Vercel

1. [Vercel Dashboard](https://vercel.com/winnmkls-projects) → your project → **Settings → Git** → branch **`main`**.
2. **Settings → General → Build & Development Settings:**
   - **Framework Preset:** Other
   - **Root Directory:** `./`
   - **Build Command:** leave empty (uses `vercel.json`) or `exit 0`
   - **Output Directory:** leave empty (uses `vercel.json`) or **`public`**
   - **Install Command:** leave empty or `exit 0`
3. **Redeploy** latest `main`.

### *No Output Directory named "public" found*

Usually an old deploy before `public/` was committed, or **Root Directory** points at a subfolder. Ensure repo root contains `public/index.html` and `public/assets/`.

| Check | Action |
|-------|--------|
| Framework = Next.js | Set to **Other** |
| Output Directory | **`public`** or empty (vercel.json sets it) |
| Root Directory | **`./`** repo root, not `public` |

---

## `vercel.json`

- `"outputDirectory": "public"` — Vercel serves `public/` as site root
- `"buildCommand": "exit 0"` — no npm build; static files are already in `public/`
- Cache headers for `/assets/*` and `/index.html`

---

## Supabase redirect URLs

- `http://localhost:8000/**`
- `https://impactlens-assessment.vercel.app/**`

---

## `.vercelignore`

Uses `/scripts` and `/docs` (root only) so **`public/assets/scripts/app.js` is included**.

---

*PLM ISMS — ImpactLens v2.1*
