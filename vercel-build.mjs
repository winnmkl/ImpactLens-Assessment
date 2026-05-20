/**
 * Vercel build — copies the static site into public/ for projects that use
 * Output Directory = "public" (e.g. impact-lens-assessment-mcr7).
 * Source of truth stays at repo root for local dev (npm start).
 */
import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const out = join(root, 'public');

if (existsSync(out)) rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

cpSync(join(root, 'index.html'), join(out, 'index.html'));
cpSync(join(root, 'assets'), join(out, 'assets'), { recursive: true });

console.log('Vercel build: wrote static site to public/');
