import fs from 'fs';
const p = new URL('../public/index.html', import.meta.url);
let s = fs.readFileSync(p, 'utf8');

const d = 'div';
const from = `nav-label">Audit</${d}><${d} class="nav-item" data-section="logs"`;
const to =
  `nav-label">Governance</${d}><${d} class="nav-item" data-section="users" onclick="showSection('users')"><span class="nav-icon">[◎]</span> User Management</${d}><${d} class="nav-item" data-section="logs"`;

if (!s.includes(from)) {
  console.log('pattern not found');
  process.exit(1);
}
s = s.replace(from, to);
s = s.replace(
  `nav-section nav-infosec-only"><${d} class="nav-label">Governance`,
  `nav-section nav-infosec-only nav-admin-users"><${d} class="nav-label">Governance`
);
fs.writeFileSync(p, s);
console.log('ok');
