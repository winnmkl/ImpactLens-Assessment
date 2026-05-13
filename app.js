/* ==========================================
   IMPACTLENS - MAIN APPLICATION
   Comprehensive risk assessment system
   ========================================== */

// ==========================================
// 1. SQL DATABASE INITIALIZATION (AlaSQL)
// ==========================================
alasql(`CREATE TABLE IF NOT EXISTS Assets (
    id STRING PRIMARY KEY, type STRING, name STRING, group_name STRING, 
    hostname STRING, server STRING, custodian STRING, description STRING, 
    ip_address STRING, environment STRING, department STRING, 
    pii STRING, spi STRING, corp STRING, 
    ciaC INT, ciaI INT, ciaA INT, ciaScore INT, ciaClass STRING, 
    riskDesc STRING, prob INT, sev INT, inherit STRING, 
    effectiveness STRING, residual STRING,
    actionPlan STRING, actionOwner STRING, actionDate STRING
)`);

alasql(`CREATE TABLE IF NOT EXISTS AssetControls (
    asset_id STRING, ctrl_id INT
)`);

alasql(`CREATE TABLE IF NOT EXISTS ReportData (
    id INT PRIMARY KEY, docDate STRING, docVersion STRING, docAuthor STRING, docApproval STRING, docDesc STRING,
    revHigh STRING, initHigh STRING,
    prepName STRING, prepTitle STRING, revName STRING, revTitle STRING, appName STRING, appTitle STRING
)`);

// Load persistence from LocalStorage
const storedAssets = JSON.parse(localStorage.getItem('impactlens_assets')) || [];
const storedControls = JSON.parse(localStorage.getItem('impactlens_controls')) || [];
const storedReport = JSON.parse(localStorage.getItem('impactlens_report')) || [];

// Check if this is the user's very first time opening the app
const isInitialized = localStorage.getItem('impactlens_initialized');

if (isInitialized) {
    // If they have been here before, strictly load their saved data
    alasql.tables.Assets.data = storedAssets;
    alasql.tables.AssetControls.data = storedControls;
} else {
    // FIRST TIME ONLY: Seed Sample Data (Updated with Hostname, Server, IP, Environment, Department)
    alasql(`INSERT INTO Assets VALUES 
        ('IA-001', 'IA', 'University Clinic Medical Records', 'Clinic', 
         'CLINIC-DB-01', 'Clinic Primary DB', 'Clinic Records Admin', 
         'Physical and digital health records of students and faculty.', 
         '10.50.1.10', 'Internal', 'Medical Services',
         'Y', 'Y', 'N', 3, 3, 2, 8, 'Restricted', 
         'Accidental data leak of sensitive health information via unsecured sharing or misplacement.', 
         3, 5, 'High', 'partially', 'High', 
         'Enforce strict physical access to the clinic records room and implement DLP tools for digital health data.', 
         'Head Physician', '2026-10-15'),

        ('PhA-002', 'PhA', 'CET Engineering Lab Computers', 'CET', 
         'CET-LAB-XX', 'Lab Workstations', 'CET Lab Technician', 
         'High-performance desktops used for CAD and simulations.', 
         'DHCP', 'Internal', 'Engineering',
         'N', 'N', 'N', 1, 2, 2, 5, 'Internal Use', 
         'Theft of physical hardware components during off-hours.', 
         3, 3, 'Moderate', 'partially', 'Moderate', 
         'Install physical cable locks on all lab PCs and upgrade lab CCTV coverage.', 
         'Security Office', '2026-11-01'),

        ('SA-003', 'SA', 'PLM Library Management System', 'Library', 
         'LIB-APP-01', 'Library App Server', 'ITC Database Administrator', 
         'System managing book inventory and borrowing records.', 
         '10.20.5.15', 'Hybrid', 'Library Services',
         'Y', 'N', 'N', 2, 2, 3, 7, 'Confidential', 
         'Unpatched software vulnerabilities leading to system disruption.', 
         4, 3, 'High', 'substantially', 'Moderate', 
         'Establish a monthly patch management routine for the library server OS.', 
         'ITC SecOps', '2026-09-30'),

        ('PA-004', 'PA', 'University President & Board', 'Admin', 
         'EXEC-LPT-XX', 'Exec Endpoints', 'Office of the University Sec', 
         'Top-level executive management with highest signing authority.', 
         'DHCP', 'Hybrid', 'Administration',
         'Y', 'N', 'Y', 3, 3, 3, 9, 'Restricted', 
         'Targeted spear-phishing (Whaling) attempting to authorize fraudulent wire transfers.', 
         3, 5, 'High', 'ineffective', 'High', 
         'Mandate executive anti-phishing training and enforce out-of-band verbal verification for transfers.', 
         'CISO', '2026-08-15'),

        ('SV-005', 'SV', 'PLM Official Website', 'ITC', 
         'WEB-PROD-01', 'Public Web Server', 'ITC Web Development Team', 
         'Primary public-facing portal for university info.', 
         '203.177.X.X', 'Internet Facing', 'ITC',
         'N', 'N', 'Y', 1, 2, 3, 6, 'Confidential', 
         'DDoS attack during admissions season rendering the site inaccessible.', 
         4, 3, 'High', 'substantially', 'Moderate', 
         'Route website traffic through a cloud-based DDoS mitigation and CDN service.', 
         'ITC Infra', '2026-12-01'),

        ('FA-006', 'FA', 'University Cashier Main Vault', 'Finance', 
         'N/A', 'N/A', 'Head Cashier / Security', 
         'Physical safe holding daily tuition fee collections.', 
         'N/A', 'Internal', 'Finance',
         'N', 'N', 'Y', 3, 3, 3, 9, 'Restricted', 
         'Theft or armed robbery targeting physical cash collections.', 
         2, 4, 'Moderate', 'fully', 'Low', 
         '', '', ''),

        ('IA-007', 'IA', 'PLM Alumni Database', 'Alumni Office', 
         'ALUM-DB-01', 'Alumni Records DB', 'ITC Enterprise Systems Team', 
         'Contact info and employment history of former students.', 
         '10.50.2.20', 'Internal', 'Alumni Affairs',
         'Y', 'N', 'N', 3, 2, 2, 7, 'Confidential', 
         'Unauthorized extraction of the database by an insider.', 
         3, 4, 'High', 'partially', 'High', 
         'Enforce strict RBAC limiting export capabilities and monitor query logs.', 
         'ITC SecOps', '2026-10-30'),

        ('PhA-008', 'PhA', 'Campus Security CCTV NVR', 'Security', 
         'SEC-NVR-01', 'Video Storage Array', 'ITC Infrastructure Team', 
         'Network Video Recorder storing 30 days of security footage.', 
         '10.99.1.50', 'Internal', 'Campus Security',
         'Y', 'N', 'N', 3, 3, 3, 9, 'Restricted', 
         'Hardware failure due to overheating in the security office closet.', 
         3, 4, 'High', 'substantially', 'Moderate', 
         'Relocate the NVR to the main climate-controlled server room with RAID 5.', 
         'Chief of Security', '2026-09-15'),

        ('SA-009', 'SA', 'HR Payroll & Benefits System', 'HR', 
         'HR-APP-01', 'Payroll Application', 'ITC Database Administrator', 
         'System calculating faculty salaries and tax deductions.', 
         '10.30.1.10', 'Internal', 'Human Resources',
         'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 
         'Disgruntled employee modifying salary bands (Insider Threat).', 
         2, 5, 'Moderate', 'partially', 'Moderate', 
         'Implement strict segregation of duties (maker-checker rule) for payroll changes.', 
         'HR Director', '2026-11-15'),

        ('FA-010', 'FA', 'University Digital Banking Portal', 'Finance', 
         'BANK-GW-01', 'Banking Gateway', 'Finance IT Support', 
         'Online access to operational bank accounts for payments.', 
         '10.40.1.5', 'Internet Facing', 'Finance',
         'N', 'N', 'Y', 3, 3, 3, 9, 'Restricted', 
         'Unauthorized access to admin accounts via credential stuffing.', 
         3, 5, 'High', 'substantially', 'Moderate', 
         'Require physical hardware security keys for banking portal access.', 
         'VP for Finance', '2026-12-15')
    `);
    
    alasql(`INSERT INTO AssetControls VALUES 
        ('IA-001', 1), ('IA-001', 3), ('IA-001', 7),
        ('PhA-002', 5),
        ('SA-003', 1), ('SA-003', 6),
        ('PA-004', 1),
        ('SV-005', 1), ('SV-005', 6),
        ('FA-006', 1), ('FA-006', 2), ('FA-006', 3), ('FA-006', 5),
        ('IA-007', 1), ('IA-007', 3), ('IA-007', 6),
        ('PhA-008', 1), ('PhA-008', 3), ('PhA-008', 5),
        ('SA-009', 1), ('SA-009', 2), ('SA-009', 3), ('SA-009', 4),
        ('FA-010', 1), ('FA-010', 2), ('FA-010', 3), ('FA-010', 7)
    `);
    
    localStorage.setItem('impactlens_initialized', 'true');
}

if(storedReport.length > 0) {
    alasql.tables.ReportData.data = storedReport;
    loadReportDataToUI();
} else {
    alasql("INSERT INTO ReportData VALUES (1, '', '', '', '', '', '', '', '', '', '', '', '', '')");
}

persistDB();

function persistDB() {
    localStorage.setItem('impactlens_assets', JSON.stringify(alasql('SELECT * FROM Assets')));
    localStorage.setItem('impactlens_controls', JSON.stringify(alasql('SELECT * FROM AssetControls')));
    localStorage.setItem('impactlens_report', JSON.stringify(alasql('SELECT * FROM ReportData')));
}

// ==========================================
// 2. CONSTANTS & LOOKUPS
// ==========================================
let editingId = null;

const INHERIT = { 
  '5-1':'Moderate','5-2':'Moderate','5-3':'High','5-4':'High','5-5':'High', 
  '4-1':'Low','4-2':'Moderate','4-3':'Moderate','4-4':'High','4-5':'High', 
  '3-1':'Low','3-2':'Moderate','3-3':'Moderate','3-4':'Moderate','3-5':'High', 
  '2-1':'Low','2-2':'Low','2-3':'Moderate','2-4':'Moderate','2-5':'Moderate', 
  '1-1':'Very Low','1-2':'Low','1-3':'Low','1-4':'Low','1-5':'Moderate' 
};

const RESIDUAL = { 
  ineffective: {Very_Low:'Low',Low:'Moderate',Moderate:'High',High:'High'}, 
  partially: {Very_Low:'Low',Low:'Moderate',Moderate:'Moderate',High:'High'}, 
  substantially: {Very_Low:'Low',Low:'Low',Moderate:'Moderate',High:'Moderate'}, 
  fully: {Very_Low:'Very Low',Low:'Low',Moderate:'Low',High:'Low'} 
};

const CIA_CLASS = {
  3:'Public',4:'Internal Use',5:'Internal Use',6:'Confidential',
  7:'Confidential',8:'Restricted',9:'Restricted'
};

const CTRL_NAMES = [
  'Documented operating procedures',
  'Segregation of duties',
  'Access restriction',
  'Removal of access (off-boarding)',
  'Physical entry controls',
  'Information backup',
  'Encryption',
  'Asset disposal procedures'
];

const RISK_TEMPLATES = {
    "phys_theft": { desc: "Theft of storage devices or printed documents", prob: "3", sev: "4", action: "Enforce physical access controls, clean desk policy, and full disk encryption (FDE)." },
    "phys_destruct": { desc: "Destruction of facilities or systems (Fire, Flood, Earthquake)", prob: "2", sev: "5", action: "Implement disaster recovery (DR) site, environmental sensors, and off-site backups." },
    "hr_insider": { desc: "Disgruntled employee or insider threat", prob: "3", sev: "4", action: "Implement strict RBAC, continuous monitoring, and structured offboarding procedures." },
    "hr_accidental": { desc: "Accidental data deletion or modification", prob: "4", sev: "3", action: "Enable regular automated backups, version control, and user training." },
    "cyber_ext_ransomware": { desc: "Ransomware / Malware attacks", prob: "4", sev: "5", action: "Deploy EDR, ensure immutable offline backups, and conduct regular phishing simulations." },
    "cyber_ext_leak": { desc: "Data Leak / Breach or PII Exposure", prob: "3", sev: "5", action: "Implement Data Loss Prevention (DLP) tools, enforce data classification, and network segmentation." },
    "cyber_ext_ddos": { desc: "DDoS attacks (Distributed Denial of Service)", prob: "3", sev: "3", action: "Subscribe to cloud-based DDoS mitigation and configure edge firewalls." },
    "cyber_ext_supply": { desc: "Third Party / Supply Chain compromise", prob: "2", sev: "4", action: "Conduct strict vendor risk assessments and require SLA security clauses." },
    "cyber_int_unauth": { desc: "Unauthorized Access to Admin accounts", prob: "3", sev: "5", action: "Mandate MFA for all privileged accounts and audit admin access logs." },
    "cyber_int_vuln": { desc: "Unpatched System vulnerabilities / Misconfiguration", prob: "4", sev: "4", action: "Establish aggressive patch management, run quarterly vulnerability scans, and secure configurations." },
    "legal_dpa": { desc: "Non-compliance to Data Privacy Act (DPA)", prob: "3", sev: "5", action: "Appoint DPO, conduct regular Privacy Impact Assessments (PIA), and update privacy notices." }
};

// ==========================================
// 3. NAVIGATION & UTILS
// ==========================================
function showSection(name) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('sec-' + name).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n => {
    if (n.getAttribute('onclick') && n.getAttribute('onclick').includes("'" + name + "'")) n.classList.add('active');
  });
  
  if (name === 'register') renderRegister();
  if (name === 'dashboard') renderDashboard();
  if (name === 'controls') renderControls();
  if (name === 'actions') renderActions();
  if (name === 'report') loadReportDataToUI();
  if (name === 'risk') { renderRiskRegister(); updateMatrixHeatmap(); }
}

function notify(msg, isErr=false) {
  const el = document.getElementById('notification');
  if(!el) return;
  el.textContent = (isErr ? '⚠ ' : '✓ ') + msg; 
  el.className = 'notification' + (isErr ? ' error' : '') + ' show';
  setTimeout(() => el.classList.remove('show'), 3000);
}

function g(id) { 
  const el = document.getElementById(id); 
  return el ? el.value : ''; 
}

// ==========================================
// 4. FORM LOGIC & MATH
// ==========================================
function genId() {
  const t = document.getElementById('f-type').value;
  if (!t) return '';
  const count = alasql(`SELECT COUNT(*) as c FROM Assets WHERE type = '${t}' AND id != '${editingId}'`)[0].c + 1;
  return t + '-' + String(count).padStart(3, '0');
}

function onTypeChange() { 
  if (!editingId) document.getElementById('f-id').value = genId(); 
}

function applyRiskTemplate() {
    const key = document.getElementById('f-risk-category').value;
    if (RISK_TEMPLATES[key]) {
        document.getElementById('f-risk-desc').value = RISK_TEMPLATES[key].desc;
        document.getElementById('f-prob').value = RISK_TEMPLATES[key].prob;
        document.getElementById('f-sev').value = RISK_TEMPLATES[key].sev;
        document.getElementById('f-action-plan').value = RISK_TEMPLATES[key].action;
        updateRisk();
        notify("Risk template applied.");
    } else {
        document.getElementById('f-risk-desc').value = "";
        document.getElementById('f-prob').value = "3";
        document.getElementById('f-sev').value = "3";
        document.getElementById('f-action-plan').value = "";
        updateRisk();
        notify("Switched to manual entry.");
    }
}

function updateCIA() {
  const s = (+g('f-c')) + (+g('f-i')) + (+g('f-a'));
  const scoreEl = document.getElementById('cia-score');
  const classEl = document.getElementById('cia-class');
  if(scoreEl) scoreEl.textContent = s;
  if(classEl) classEl.textContent = CIA_CLASS[s] || 'N/A';
  updateResidual();
}

function getInherit() {
  const p = g('f-prob'), s = g('f-sev');
  return { p, s, rating: INHERIT[s + '-' + p] || 'Moderate', score: p * s };
}

function updateRisk() {
  const { score, rating } = getInherit();
  const sEl = document.getElementById('r-score');
  const rEl = document.getElementById('r-inherit');
  if(sEl) sEl.textContent = score;
  if(rEl) { rEl.textContent = rating; rEl.style.color = riskColor(rating); }
  updateResidual();
}

function updateResidual() {
  const { rating } = getInherit();
  const eff = g('f-effectiveness');
  const residual = (RESIDUAL[eff] || {})[rating.replace(' ', '_')] || 'Low';
  
  const el = document.getElementById('r-residual');
  if(el) { el.textContent = residual; el.style.color = riskColor(residual); }
  
  const ap = document.getElementById('action-plan-section');
  if(ap) ap.style.display = (residual === 'High' || residual === 'Moderate') ? 'block' : 'none';
}

function riskColor(r) { 
  return { 
    'Very Low': 'var(--success)', 
    'Low': 'var(--accent2)', 
    'Moderate': 'var(--warn)', 
    'High': 'var(--danger)', 
    'Critical': 'var(--purple)' 
  }[r] || 'var(--text)'; 
}

function riskBadge(r) { 
  const cls = { 
    'Very Low': 'badge-vl', 
    'Low': 'badge-lo', 
    'Moderate': 'badge-mo', 
    'High': 'badge-hi', 
    'Critical': 'badge-cr' 
  }[r] || 'badge-lo'; 
  return `<span class="badge ${cls}">${r||'—'}</span>`; 
}

function classBadge(c) { 
  const cls = { 
    'Public': 'badge-pub', 
    'Internal Use': 'badge-int', 
    'Confidential': 'badge-con', 
    'Restricted': 'badge-res' 
  }[c] || 'badge-type'; 
  return `<span class="badge ${cls}">${c||'—'}</span>`; 
}

// ==========================================
// 5. SQL CRUD OPERATIONS
// ==========================================
function saveAssetToDB() {
  const type = g('f-type');
  const name = g('f-name').trim();
  if (!type) return notify('Error: Select an asset type', true);
  if (!name) return notify('Error: Enter an asset name', true);
  
  const id = editingId || genId();
  const { p, s, rating: inherit } = getInherit();
  const eff = g('f-effectiveness');
  const residual = (RESIDUAL[eff] || {})[inherit.replace(' ', '_')] || 'Low';
  const c = +g('f-c'), ii = +g('f-i'), a = +g('f-a');

  alasql(`DELETE FROM Assets WHERE id = '${id}'`);
  alasql(`DELETE FROM AssetControls WHERE asset_id = '${id}'`);

  alasql(`INSERT INTO Assets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, [
      id, type, name, g('f-group'), 
      g('f-hostname'), g('f-server'), g('f-custodian'), g('f-desc'), 
      g('f-ip'), g('f-environment'), g('f-department'),
      g('f-pii'), g('f-spi'), g('f-corp'),
      c, ii, a, c+ii+a, CIA_CLASS[c+ii+a], g('f-risk-desc'), p, s, inherit, 
      eff, residual, g('f-action-plan'), g('f-action-owner'), g('f-action-date')
  ]);

  const selectedControls = Array.from(document.getElementById('f-controls').selectedOptions);
  selectedControls.forEach(opt => {
    alasql("INSERT INTO AssetControls VALUES (?,?)", [id, parseInt(opt.value)]);
  });

  persistDB();
  editingId = null;
  clearForm();
  notify(`Asset ${id} saved successfully!`);
  showSection('register');
  renderDashboard();
}

function editAsset(id) {
  try {
      const a = alasql(`SELECT * FROM Assets WHERE id = '${id}'`)[0];
      
      if (!a) {
          notify("Error: Asset not found in database.", true);
          return;
      }

      editingId = id;

      const titleEl = document.getElementById('form-title');
      if(titleEl) titleEl.innerHTML = 'UPDATE <span>RECORD</span>';

      document.getElementById('f-type').value = a.type || '';
      document.getElementById('f-id').value = a.id || '';
      document.getElementById('f-name').value = a.name || '';
      document.getElementById('f-group').value = a.group_name || '';
      document.getElementById('f-hostname').value = a.hostname || '';
      document.getElementById('f-server').value = a.server || '';
      document.getElementById('f-custodian').value = a.custodian || '';
      document.getElementById('f-desc').value = a.description || '';
      
      document.getElementById('f-ip').value = a.ip_address || '';
      document.getElementById('f-environment').value = a.environment || 'Internal';
      document.getElementById('f-department').value = a.department || '';
      
      document.getElementById('f-pii').value = a.pii || 'N';
      document.getElementById('f-spi').value = a.spi || 'N';
      document.getElementById('f-corp').value = a.corp || 'N';
      document.getElementById('f-c').value = a.ciaC || '2';
      document.getElementById('f-i').value = a.ciaI || '2';
      document.getElementById('f-a').value = a.ciaA || '2';

      if (document.getElementById('f-risk-category')) document.getElementById('f-risk-category').value = ""; 
      document.getElementById('f-risk-desc').value = a.riskDesc || '';
      document.getElementById('f-prob').value = a.prob || '3';
      document.getElementById('f-sev').value = a.sev || '3';

      document.getElementById('f-effectiveness').value = a.effectiveness || 'substantially';
      document.getElementById('f-action-plan').value = a.actionPlan || '';
      document.getElementById('f-action-owner').value = a.actionOwner || '';
      document.getElementById('f-action-date').value = a.actionDate || '';

      const ctrls = alasql(`SELECT ctrl_id FROM AssetControls WHERE asset_id = '${id}'`).map(r => r.ctrl_id);
      [1,2,3,4,5,6,7,8].forEach(n => {
          const cb = document.getElementById('ctrl'+n);
          if(cb) cb.checked = ctrls.includes(n);
      });

      updateCIA(); 
      updateRisk(); 
      showSection('add'); 
      window.scrollTo(0,0);

      if (typeof updateTags === "function") {
          setTimeout(updateTags, 50);
      }

  } catch (err) {
      console.error("Edit Error:", err);
      notify("Failed to open asset for editing.", true);
  }
}

function deleteAsset(id) {
  if (!confirm(`Are you sure you want to permanently delete asset ${id}?`)) return;
  
  try {
      alasql(`DELETE FROM Assets WHERE id = '${id}'`);
      alasql(`DELETE FROM AssetControls WHERE asset_id = '${id}'`);
      persistDB(); 
      
      if (typeof renderRegister === "function") renderRegister(); 
      if (typeof renderRiskRegister === "function") renderRiskRegister();
      if (typeof renderDashboard === "function") renderDashboard(); 
      if (typeof renderControls === "function") renderControls();
      if (typeof renderActions === "function") renderActions();
      
      notify(`Asset ${id} deleted successfully.`);
  } catch(err) {
      console.error("Deletion Error:", err);
      notify("Failed to delete asset. Check console.", true);
  }
}

function clearForm() {
  const fields = [
      'f-name','f-group','f-hostname','f-server','f-custodian','f-desc',
      'f-ip', 'f-department',
      'f-risk-desc','f-action-plan','f-action-owner','f-action-date','f-risk-category'
  ];
  fields.forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
  
  if(document.getElementById('f-environment')) document.getElementById('f-environment').value = 'Internal';
  
  if(document.getElementById('f-type')) document.getElementById('f-type').value = '';
  if(document.getElementById('f-id')) document.getElementById('f-id').value = '';
  if(document.getElementById('f-pii')) document.getElementById('f-pii').value = 'N';
  if(document.getElementById('f-spi')) document.getElementById('f-spi').value = 'N';
  if(document.getElementById('f-corp')) document.getElementById('f-corp').value = 'N';
  if(document.getElementById('f-c')) document.getElementById('f-c').value = '2';
  if(document.getElementById('f-i')) document.getElementById('f-i').value = '2';
  if(document.getElementById('f-a')) document.getElementById('f-a').value = '2';
  if(document.getElementById('f-prob')) document.getElementById('f-prob').value = '3';
  if(document.getElementById('f-sev')) document.getElementById('f-sev').value = '3';
  if(document.getElementById('f-effectiveness')) document.getElementById('f-effectiveness').value = 'substantially';
  if(document.getElementById('f-controls')) document.getElementById('f-controls').selectedIndex = -1;
  
  const titleEl = document.getElementById('form-title');
  if(titleEl) titleEl.innerHTML = 'INSERT <span>RECORD</span>';
  updateCIA(); updateRisk();
}

function saveReportData() {
    alasql("DELETE FROM ReportData WHERE id = 1");
    alasql(`INSERT INTO ReportData VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
        g('doc-date'), g('doc-version'), g('doc-author'), g('doc-approval'), g('doc-desc'),
        g('rep-rev-high'), g('rep-init-high'),
        g('rep-prep-name'), g('rep-prep-title'), g('rep-rev-name'), g('rep-rev-title'), g('rep-app-name'), g('rep-app-title')
    ]);
    persistDB();
    notify("Report Details Saved to Database!");
}

function loadReportDataToUI() {
    const r = alasql("SELECT * FROM ReportData WHERE id = 1")[0];
    if(!r) return;
    const mapping = {
        'doc-date': r.docDate, 'doc-version': r.docVersion, 'doc-author': r.docAuthor, 'doc-approval': r.docApproval, 'doc-desc': r.docDesc,
        'rep-rev-high': r.revHigh, 'rep-init-high': r.initHigh,
        'rep-prep-name': r.prepName, 'rep-prep-title': r.prepTitle, 'rep-rev-name': r.revName, 'rep-rev-title': r.revTitle, 'rep-app-name': r.appName, 'rep-app-title': r.appTitle
    };
    for(const [id, val] of Object.entries(mapping)) {
        if(document.getElementById(id)) document.getElementById(id).value = val || '';
    }
}

// ==========================================
// 6. UI RENDERING (SQL Driven)
// ==========================================
function renderRegister() {
  let data = alasql("SELECT * FROM Assets");
  const tbody = document.getElementById('reg-body');
  if(!tbody) return;

  if (!data.length) { tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;">No records in DB.</td></tr>`; return; }

  tbody.innerHTML = data.map(a => `
    <tr>
      <td><span class="badge badge-id">${a.id}</span></td>
      <td><strong>${a.name}</strong></td>
      <td><span class="badge badge-type">${a.type}</span></td>
      <td style="color:var(--text2)">${a.group_name||'—'}</td>
      <td style="color:var(--text2)">${a.hostname||'—'}</td>
      <td>
        <button class="btn btn-sm" onclick="editAsset('${a.id}')">Edit</button>
        <button class="btn btn-sm btn-danger" style="margin-left:4px" onclick="deleteAsset('${a.id}')">Del</button>
      </td>
    </tr>
  `).join('');
}

function renderRiskRegister() {
  let data = alasql("SELECT * FROM Assets");
  data.sort((a,b) => {
    const order = {High:0, Moderate:1, Low:2, 'Very Low':3};
    return (order[a.residual]||4) - (order[b.residual]||4);
  });

  const tbody = document.getElementById('risk-body');
  if(!tbody) return;
  
  if (!data.length) { tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;">No records in DB.</td></tr>`; return; }

  tbody.innerHTML = data.map(a => `
    <tr>
      <td><span class="badge badge-id">${a.id}</span></td>
      <td><strong>${a.name}</strong></td>
      <td style="color:var(--text2);font-size:11px">${(a.riskDesc||'—').substring(0,60)}${(a.riskDesc||'').length>60?'...':''}</td>
      <td>${riskBadge(a.inherit)}</td>
      <td style="font-size:11px;color:var(--text2);text-transform:capitalize;">${a.effectiveness}</td>
      <td>${riskBadge(a.residual)}</td>
    </tr>
  `).join('');
}

function updateMatrixHeatmap() {
  document.querySelectorAll('.mx-count').forEach(el => {
      el.textContent = '';
      el.classList.remove('active');
      el.style.opacity = "0";
  });
  
  const riskCounts = alasql("SELECT prob, sev, COUNT(*) as c FROM Assets WHERE prob IS NOT NULL AND sev IS NOT NULL GROUP BY prob, sev");
  
  riskCounts.forEach(row => {
     const cellId = `mx-${row.prob}-${row.sev}`;
     const cell = document.getElementById(cellId);
     if(cell) {
         let existingCount = cell.querySelector('.mx-count');
         if(!existingCount) {
             existingCount = document.createElement('div');
             existingCount.className = 'mx-count';
             cell.appendChild(existingCount);
         }
         existingCount.textContent = row.c;
         existingCount.style.opacity = "1";
         existingCount.classList.add('active');
     }
  });
}

function renderControls() {
  const total = alasql("SELECT VALUE COUNT(*) FROM Assets");
  const ctrlCounts = alasql("SELECT ctrl_id, COUNT(*) as c FROM AssetControls GROUP BY ctrl_id");
  const colors = ['var(--accent)','var(--accent2)','var(--success)','var(--warn)','var(--purple)','var(--danger)','var(--info)','var(--accent)'];
  
  const barsEl = document.getElementById('ctrl-bars');
  if(barsEl) {
      barsEl.innerHTML = CTRL_NAMES.map((name,i) => {
        const dbRow = ctrlCounts.find(row => row.ctrl_id === (i+1));
        const count = dbRow ? dbRow.c : 0;
        const pct = Math.round((count/total)*100);
        return `<div class="chart-bar-row">
          <div class="chart-bar-label" style="width:200px; text-align:left;">${name} <span style="color:var(--text3); margin-left:8px;">${count} / ${total} (${pct}%)</span></div>
          <div class="chart-bar-track"><div class="chart-bar-fill" style="width:${pct}%;background:${colors[i]}"></div></div>
        </div>`;
      }).join('');
  }

  const effCounts = alasql("SELECT effectiveness, COUNT(*) as c FROM Assets GROUP BY effectiveness");
  const effLabels = {ineffective:'Ineffective', partially:'Partially Effective', substantially:'Substantially Effective', fully:'Fully Effective'};
  const effColors = {ineffective:'var(--danger)', partially:'var(--warn)', substantially:'var(--accent2)', fully:'var(--success)'};
  
  const distEl = document.getElementById('ctrl-effectiveness');
  if(distEl) {
      distEl.innerHTML = Object.keys(effLabels).map(k => {
        const dbRow = effCounts.find(row => row.effectiveness === k);
        const count = dbRow ? dbRow.c : 0;
        const pct = Math.round((count/total)*100);
        return `<div class="chart-bar-row">
          <div class="chart-bar-label" style="width:200px; text-align:left;">${effLabels[k]}</div>
          <div class="chart-bar-track"><div class="chart-bar-fill" style="width:${pct}%;background:${effColors[k]};color:#000">${pct > 8 ? pct+'%' : ''}</div></div>
          <div class="chart-bar-count" style="width:40px; text-align:right;">${count}</div>
        </div>`;
      }).join('');
  }
}

function renderActions() {
  const items = alasql("SELECT * FROM Assets WHERE residual IN ('High', 'Moderate')");
  const el = document.getElementById('actions-content');
  if(!el) return;

  if (!items.length) {
    el.innerHTML = '<div class="empty-state"><div>[✓]</div>No assets with High or Moderate residual risk. Good posture!</div>';
    return;
  }
  el.innerHTML = items.map(a => `
    <div class="card" style="border-left:3px solid ${a.residual==='High'?'var(--danger)':'var(--warn)'}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
        <div>
          <span class="badge badge-id" style="margin-right:8px">${a.id}</span>
          <strong style="font-size:14px">${a.name}</strong>
          <span class="badge badge-type" style="margin-left:8px">${a.type}</span>
        </div>
        ${riskBadge(a.residual)}
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div>
          <div style="font-family:var(--mono);font-size:9px;letter-spacing:1px;text-transform:uppercase;color:var(--text3);margin-bottom:4px">Identified risk</div>
          <div style="font-size:12px;color:var(--text2)">${a.riskDesc||'Not specified'}</div>
          <div style="margin-top:8px;display:flex;gap:8px">
            ${riskBadge(a.inherit)}
            <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">→ effectiveness: ${a.effectiveness}</span>
          </div>
        </div>
        <div>
          <div style="font-family:var(--mono);font-size:9px;letter-spacing:1px;text-transform:uppercase;color:var(--text3);margin-bottom:4px">Action plan</div>
          <div style="font-size:12px;color:var(--text2)">${a.actionPlan||'<span style="color:var(--danger)">No Action Plan Set!</span>'}</div>
          <div style="margin-top:8px;font-family:var(--mono);font-size:10px;color:var(--text3)">
            Owner: <span style="color:var(--text2)">${a.actionOwner||'—'}</span> &nbsp;|&nbsp;
            Target: <span style="color:var(--text2)">${a.actionDate||'—'}</span>
          </div>
        </div>
      </div>
      <div style="margin-top:12px;display:flex;justify-content:flex-end">
        <button class="btn btn-sm" onclick="editAsset('${a.id}')">Edit asset →</button>
      </div>
    </div>
  `).join('');
}

function renderDashboard() {
  const total = alasql("SELECT VALUE COUNT(*) FROM Assets");
  
  const headerTotal = document.getElementById('hdr-total');
  const navTotal = document.getElementById('nav-total');
  if(headerTotal) headerTotal.textContent = total;
  if(navTotal) navTotal.textContent = total;
  
  const highRisk = alasql("SELECT VALUE COUNT(*) FROM Assets WHERE residual = 'High'");
  const headerHigh = document.getElementById('hdr-high');
  const navHigh = document.getElementById('nav-high');
  if(headerHigh) headerHigh.textContent = highRisk;
  if(navHigh) navHigh.textContent = highRisk;

  const actions = alasql("SELECT VALUE COUNT(*) FROM Assets WHERE residual IN ('High', 'Moderate')");
  const navActions = document.getElementById('nav-actions');
  if(navActions) navActions.textContent = actions;

  const dmTotal = document.getElementById('dm-total');
  const dmHigh = document.getElementById('dm-high');
  const dmMod = document.getElementById('dm-mod');
  const dmPii = document.getElementById('dm-pii');
  
  if(dmTotal) dmTotal.textContent = total;
  if(dmHigh) dmHigh.textContent = highRisk;
  if(dmMod) dmMod.textContent = alasql("SELECT VALUE COUNT(*) FROM Assets WHERE residual = 'Moderate'");
  if(dmPii) dmPii.textContent = alasql("SELECT VALUE COUNT(*) FROM Assets WHERE pii = 'Y' OR spi = 'Y'");

  const totalAssets = total || 1;
  const barHtml = (label, val, t, color) => {
    if(!val) return ''; 
    const pct = Math.round((val/t)*100);
    return `<div class="chart-bar-row"><div class="chart-bar-label">${label}</div><div class="chart-bar-track"><div class="chart-bar-fill" style="width:${pct}%;background:${color};color:#000">${pct>10?pct+'%':''}</div></div><div class="chart-bar-count" style="width:24px;text-align:right;">${val}</div></div>`;
  };

  const byType = alasql("SELECT type, COUNT(*) as c FROM Assets GROUP BY type");
  const typeColors = {IA:'var(--accent)',PhA:'var(--accent2)',PA:'var(--success)',SA:'var(--warn)',SV:'var(--purple)', 'FA':'var(--info)'};
  const typeEl = document.getElementById('dash-types');
  if(typeEl) {
      if(!byType.length) typeEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else typeEl.innerHTML = byType.map(r => barHtml(r.type, r.c, totalAssets, typeColors[r.type])).join('');
  }

  const byRes = alasql("SELECT residual, COUNT(*) as c FROM Assets GROUP BY residual");
  const rColors = {'High':'var(--danger)','Moderate':'var(--warn)','Low':'var(--accent2)','Very Low':'var(--success)'};
  const resEl = document.getElementById('dash-residual');
  if(resEl) {
      if(!byRes.length) resEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else resEl.innerHTML = byRes.map(r => barHtml(r.residual, r.c, totalAssets, rColors[r.residual])).join('');
  }

  const byClass = alasql("SELECT ciaClass, COUNT(*) as c FROM Assets GROUP BY ciaClass");
  const cColors = {'Public':'var(--success)','Internal Use':'var(--accent2)','Confidential':'var(--warn)','Restricted':'var(--danger)'};
  const classEl = document.getElementById('dash-class');
  if(classEl) {
      if(!byClass.length) classEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else classEl.innerHTML = byClass.map(r => barHtml(r.ciaClass, r.c, totalAssets, cColors[r.ciaClass])).join('');
  }

  const trEl = document.getElementById('dash-top-risk');
  if(trEl) {
      const topRisks = alasql("SELECT id, name, residual FROM Assets ORDER BY CASE residual WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Moderate' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END LIMIT 5");
      if(!topRisks.length) trEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else trEl.innerHTML = topRisks.map(a => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
          <div><span class="badge badge-id" style="margin-right:6px;font-size:9px">${a.id}</span><span style="font-size:12px;color:var(--text)">${a.name}</span></div>
          ${riskBadge(a.residual)}
        </div>
      `).join('');
  }
}

function exportDataXLSX() {
    if (typeof XLSX === 'undefined') { notify("Excel library loading...", true); return; }
    
    const dbAssets = alasql("SELECT * FROM Assets");
    const rep = alasql("SELECT * FROM ReportData WHERE id = 1")[0] || {};
    
    const headers = [ "Asset ID", "Name of Information Asset", "Description", "Group", "Hostname", "Server", "Custodian", "IP Address", "Environment", "Department", "Type", "PII", "SPI", "Corp Info", "C", "I", "A", "Valuation", "Class", "Risk", "Prob", "Sev", "Inherent", "Control 1", "Control 2", "Control 3", "Control 4", "Control 5", "Control 6", "Control 7", "Control 8", "Control Effect", "Residual", "Action Plan", "Action Owner", "Target Date" ];

    const dataRows = dbAssets.map(a => {
        const ctrls = alasql("SELECT ctrl_id FROM AssetControls WHERE asset_id = ?", [a.id]).map(r => r.ctrl_id);
        return [
            a.id, a.name, a.description, a.group_name, a.hostname, a.server, a.custodian, a.ip_address, a.environment, a.department, a.type, a.pii, a.spi, a.corp,
            a.ciaC, a.ciaI, a.ciaA, a.ciaScore, a.ciaClass, a.riskDesc, a.prob, a.sev, a.inherit,
            ctrls.includes(1)?"Y":"N", ctrls.includes(2)?"Y":"N", ctrls.includes(3)?"Y":"N", ctrls.includes(4)?"Y":"N",
            ctrls.includes(5)?"Y":"N", ctrls.includes(6)?"Y":"N", ctrls.includes(7)?"Y":"N", ctrls.includes(8)?"Y":"N",
            a.effectiveness, a.residual, a.actionPlan, a.actionOwner, a.actionDate
        ];
    });

    const wsData = XLSX.utils.aoa_to_sheet([headers, ...dataRows]);

    const historyHeaders = ["DATE APPROVED", "VERSION NO.", "DESCRIPTION", "CREATED/MODIFIED BY", "APPROVAL"];
    const wsHistory = XLSX.utils.aoa_to_sheet([["DOCUMENT HISTORY"], [], historyHeaders, [rep.docDate||'', rep.docVersion||'', rep.docDesc||'', rep.docAuthor||'', rep.docApproval||'']]);

    const wsHighlights = XLSX.utils.aoa_to_sheet([
        ["INFORMATION SECURITY RISK ASSESSMENT - HIGHLIGHTS"], [],
        ["Revision Highlights:"], [rep.revHigh||''], [],
        ["Initial Overall Highlights:"], [rep.initHigh||'']
    ]);

    const wsSignoffs = XLSX.utils.aoa_to_sheet([
        ["SIGN OFF SHEET"], [],
        ["DESCRIPTION:", "Information Asset Register"], [],
        ["PREPARED BY"], [rep.prepName||'', rep.prepTitle||''], [],
        ["REVIEWED BY"], [rep.revName||'', rep.revTitle||''], [],
        ["APPROVED BY"], [rep.appName||'', rep.appTitle||'']
    ]);

    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, wsHistory, "Document History");
    XLSX.utils.book_append_sheet(wb, wsHighlights, "Highlights");
    XLSX.utils.book_append_sheet(wb, wsData, "IAR_Data");
    XLSX.utils.book_append_sheet(wb, wsSignoffs, "SIGN OFF");
    
    XLSX.writeFile(wb, "ImpactLens_IAR_Export.xlsx");
    notify("Exported to Excel successfully!");
}

// ==========================================
// 7. MULTI-SELECT DROPDOWN LOGIC
// ==========================================
document.addEventListener('click', function(event) {
    const wrapper = document.querySelector('.multi-select-wrapper');
    const dropdown = document.getElementById('ctrl-dropdown');
    if (wrapper && dropdown && !wrapper.contains(event.target)) {
        dropdown.classList.remove('show');
    }
});

function updateTags() {
    const container = document.getElementById('selected-controls-tags');
    if (!container) return;
    container.innerHTML = '';
    
    [1,2,3,4,5,6,7,8].forEach(n => {
        const cb = document.getElementById('ctrl'+n);
        if (cb && cb.checked) {
            const tag = document.createElement('div');
            tag.className = 'tag';
            tag.innerHTML = `${CTRL_NAMES[n-1]} <span class="tag-close" onclick="removeTag(${n}, event)">×</span>`;
            container.appendChild(tag);
        }
    });
}

function removeTag(n, event) {
    event.stopPropagation();
    const cb = document.getElementById('ctrl'+n);
    if (cb) cb.checked = false;
    updateTags();
}

// ==========================================
// 8. INITIALIZATION
// ==========================================
setTimeout(() => { renderDashboard(); }, 200); 
showSection('dashboard');
