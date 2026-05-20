import fs from 'fs';
const p = new URL('../public/index.html', import.meta.url);
const d = 'di' + 'v';
let s = fs.readFileSync(p, 'utf8');
s = s.replace(
  `INSERT <span>RECORD</span></${d}></${d}><p class="page-desc">Workflow:`,
  `INSERT <span>RECORD</span></${d}><p class="page-desc">Workflow:`
);
fs.writeFileSync(p, s);
console.log('done');
