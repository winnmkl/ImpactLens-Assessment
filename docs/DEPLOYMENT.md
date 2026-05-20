# ImpactLens — Vercel deployment

Static site (vanilla HTML/CSS/JS). No build step. Supabase client loads from CDN in `index.html`.

## Production URLs

| Project | URL | Notes |
|---------|-----|--------|
| **Primary (recommended)** | https://impactlens-assessment.vercel.app | CLI-linked project `impactlens-assessment` |
| GitHub auto-import | `impact-lens-assessment-*` | May be a **second** project if Git was connected twice |

Use **one** Vercel project for production. Duplicate Git imports often fail with a ~2s error when framework settings conflict.

---

## Deploy from CLI (reliable)

```bash
npm run deploy:prod
```

Requires [Vercel CLI](https://vercel.com/docs/cli) logged in and `.vercel/project.json` linked to `impactlens-assessment`.

---

## GitHub → Vercel (CI)

### Connect to the existing project (recommended)

1. [Vercel Dashboard](https://vercel.com/winnmkls-projects) → open **`impactlens-assessment`** (not a duplicate `impact-lens-assessment-mcr7`).
2. **Settings → Git** → Connect **winnmkl/ImpactLens-Assessment** → branch **`main`** → Production.
3. **Settings → General → Build & Development Settings:**
   - **Framework Preset:** Other
   - **Root Directory:** `./` (repo root)
   - **Build Command:** leave empty (use `vercel.json`) or `exit 0`
   - **Output Directory:** leave **empty** (not `public`, not `dist`)
   - **Install Command:** leave empty (use `vercel.json`) or `exit 0`
4. Redeploy from **Deployments → Redeploy**.

### If you see a failed deploy in ~2 seconds

Usually **wrong framework preset** (Next.js/React detected from old `package.json` deps) or a **duplicate project**.

| Check | Action |
|-------|--------|
| Framework = Next.js | Set to **Other**; `vercel.json` has `"framework": null` |
| Output Directory = `public` or `dist` | **Clear it** — `index.html` is at repo root |
| Two Vercel projects for same repo | Delete the broken duplicate; connect Git once |
| Build logs mention missing output | Root cause above — not a missing npm build |

---

## `vercel.json` (repo)

- `"framework": null` — static site, no Next.js
- `"installCommand": "exit 0"` / `"buildCommand": "exit 0"` — skip npm install/build
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
