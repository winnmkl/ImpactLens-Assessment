# ImpactLens — Vercel deployment

Static site (vanilla HTML/CSS/JS). No build step. Supabase client loads from CDN in `index.html`.

## Production URLs

| Project | URL | Notes |
|---------|-----|--------|
| **Primary (recommended)** | https://impactlens-assessment.vercel.app | CLI-linked project `impactlens-assessment` |
| GitHub auto-import | `impact-lens-assessment-mcr7` | Same repo — uses `public/` output from `vercel-build.mjs` |

Use **one** Vercel project for production if possible. Both projects can deploy from the same repo when `vercel.json` is present.

---

## Deploy from CLI (reliable)

```bash
npm run deploy:prod
```

Requires [Vercel CLI](https://vercel.com/docs/cli) logged in and `.vercel/project.json` linked to your target project.

---

## GitHub → Vercel (CI)

### Connect a project (primary or mcr7)

1. [Vercel Dashboard](https://vercel.com/winnmkls-projects) → open the project (e.g. **`impactlens-assessment`** or **`impact-lens-assessment-mcr7`**).
2. **Settings → Git** → Connect **winnmkl/ImpactLens-Assessment** → branch **`main`** → Production.
3. **Settings → General → Build & Development Settings:**
   - **Framework Preset:** Other
   - **Root Directory:** `./` (repo root)
   - **Build Command:** leave empty (uses `vercel.json`) or `node vercel-build.mjs`
   - **Output Directory:** leave empty (uses `vercel.json`) or **`public`**
   - **Install Command:** leave empty (uses `vercel.json`) or `exit 0`
4. Redeploy from **Deployments → Redeploy**.

### If you see: *No Output Directory named "public" found*

The dashboard had **Output Directory = `public`** but the old config did not create that folder. The repo now runs `vercel-build.mjs`, which copies `index.html` and `assets/` into `public/` before deploy. Pull latest `main` and redeploy.

| Check | Action |
|-------|--------|
| Framework = Next.js | Set to **Other**; `vercel.json` has `"framework": null` |
| Output Directory = `public` | OK — matches `vercel.json` after this fix |
| Output Directory empty | OK — `vercel.json` sets `"outputDirectory": "public"` |
| Build fails on `vercel-build.mjs` | Ensure **Root Directory** is repo root, not a subfolder |
| Two Vercel projects for same repo | Both can work; prefer one production URL |

---

## `vercel.json` (repo)

- `"framework": null` — static site, no Next.js
- `"buildCommand": "node vercel-build.mjs"` — copies root static files into `public/`
- `"outputDirectory": "public"` — satisfies mcr7 and standard static deploy
- `"installCommand": "exit 0"` — no npm install required for deploy
- Cache headers for `/assets/*` and `index.html`

---

## Supabase redirect URLs

Add both for auth email links:

- `http://localhost:8000/**`
- `https://impactlens-assessment.vercel.app/**`

---

## `.vercelignore`

Uses `/scripts` and `/docs` (root only) so **`assets/scripts/app.js` is included**. Do not use bare `scripts` — that would exclude the app bundle.

---

*PLM ISMS — ImpactLens v2.1*
