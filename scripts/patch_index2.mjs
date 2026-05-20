import fs from 'fs';
const p = new URL('../public/index.html', import.meta.url);
let s = fs.readFileSync(p, 'utf8');
const D = 'di' + 'v';

const usersSection = `
    <${D} id="sec-users" class="section">
      <${D} class="page-header"><${D}><${D} class="page-title">USER <span>MANAGEMENT</span></${D}><${D} class="page-desc">// Approve Standard User and Info Sec accounts</${D}></${D}></${D}>
      <${D} class="table-wrap"><table><thead><tr><th>Email</th><th>Requested Role</th><th>Status</th><th>Actions</th></tr></thead><tbody id="users-body"></tbody></table></${D}>
    </${D}>
`;

if (!s.includes('sec-users')) {
  s = s.replace(`    <${D} id="sec-logs" class="section">`, usersSection + `    <${D} id="sec-logs" class="section">`);
}

s = s.replace(
  '<button class="btn btn-success" onclick="exportDataXLSX()">▤ Export Excel</button>',
  `<button class="btn btn-success nav-export-only hidden" onclick="exportDataXLSX()">▤ Export Excel</button>`
);

const complianceCard = `
        <${D} id="compliance-mapping-panel" class="compliance-panel hidden">
          <label style="margin-top:16px;display:block;color:var(--accent2);">Framework Compliance Mapping</label>
          <${D} id="compliance-tags" class="compliance-tags"></${D}>
          <p class="compliance-hint">Mapped from implemented controls — NIST CSF, ISO/IEC 27001/27002, CIS, SOC 2, PCI-DSS (FA assets).</p>
        </${D}>
`;

if (!s.includes('compliance-mapping-panel')) {
  s = s.replace(
    `<${D} class="selected-tags" id="selected-controls-tags"></${D}>`,
    `<${D} class="selected-tags" id="selected-controls-tags"></${D}>` + complianceCard
  );
}

if (!s.includes('id="r-inherit"')) {
  s = s.replace(
    `<${D} style="display:flex; gap:16px; margin-bottom:16px; align-items:center;">
           <span style="font-family:var(--mono); color:var(--text3); text-transform:uppercase; font-size:10px;">Calculated Residual Risk:</span>`,
    `<${D} style="display:flex; gap:16px; margin-bottom:16px; align-items:center; flex-wrap:wrap;">
           <span style="font-family:var(--mono); color:var(--text3); text-transform:uppercase; font-size:10px;">System Derived Inherent Risk:</span>
           <span class="badge badge-mo" id="r-inherit" style="font-size:14px; padding:6px 12px;">Moderate</span>
           <span class="metric-enforced">Enforced Metric</span>
        </${D}>
        <${D} style="display:flex; gap:16px; margin-bottom:16px; align-items:center; flex-wrap:wrap;">
           <span style="font-family:var(--mono); color:var(--text3); text-transform:uppercase; font-size:10px;">System Derived Residual Risk:</span>
           <span class="metric-enforced">Enforced Metric</span>`
  );
}

s = s.replace(
  'Inherent Probability (1-5) 🔒',
  'Inherent Probability (1-5) — System Derived'
);
s = s.replace(
  'Inherent Severity (1-5) 🔒',
  'Inherent Severity (1-5) — System Derived'
);
s = s.replace(
  'Residual Probability (Post-Controls) 🔒',
  'Residual Probability — System Derived'
);
s = s.replace(
  'Residual Severity (Post-Controls) 🔒',
  'Residual Severity — System Derived'
);

fs.writeFileSync(p, s);
console.log('patch2 done');
