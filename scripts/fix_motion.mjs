import fs from 'fs';
const D = 'di' + 'v';
for (const rel of ['../public/assets/scripts/app.js', '../public/index.html']) {
  const p = new URL(rel, import.meta.url);
  let s = fs.readFileSync(p, 'utf8');
  s = s.replaceAll('<motion ', `<${D} `);
  s = s.replaceAll('</motion>', `</${D}>`);
  fs.writeFileSync(p, s);
  console.log('fixed', rel);
}
