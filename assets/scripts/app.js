/* ==========================================
   IMPACTLENS - MAIN APPLICATION
   Comprehensive risk assessment system
   ========================================== */

// Helper to generate dynamic dates so the 14-day alert ALWAYS works during your presentation
const getDynamicDate = (daysToAdd) => {
    const d = new Date();
    d.setDate(d.getDate() + daysToAdd);
    return d.toISOString().split('T')[0];
};

// ==========================================
// 1. SQL DATABASE INITIALIZATION (AlaSQL)
// ==========================================
alasql(`CREATE TABLE IF NOT EXISTS Assets (
    id STRING PRIMARY KEY, type STRING, name STRING, group_name STRING, 
    hostname STRING, server STRING, custodian STRING, description STRING, 
    ip_address STRING, environment STRING, department STRING, 
    pii STRING, spi STRING, corp STRING, 
    ciaC INT, ciaI INT, ciaA INT, ciaScore INT, ciaClass STRING, 
    riskCategory STRING, riskDesc STRING, prob INT, sev INT, inherit STRING, 
    residual STRING,
    actionType STRING, actionStatus STRING, actionPlan STRING, actionOwner STRING, actionDate STRING
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
         'cyber_ext_leak', 'Accidental data leak of sensitive health information via unsecured sharing or misplacement.', 
         3, 5, 'High', 'Moderate', 
         'Mitigate', 'In Progress', 'Enforce strict physical access to the clinic records room and implement DLP tools for digital health data.', 
         'Head Physician', '${getDynamicDate(5)}'),

        ('PhA-001', 'PhA', 'CET Engineering Lab Computers', 'CET', 
         'CET-LAB-XX', 'Lab Workstations', 'CET Lab Technician', 
         'High-performance desktops used for CAD and simulations.', 
         'DHCP', 'Internal', 'Engineering',
         'N', 'N', 'N', 1, 2, 2, 5, 'Internal Use', 
         'phys_theft', 'Theft of physical hardware components during off-hours.', 
         3, 3, 'Moderate', 'Moderate', 
         'Mitigate', 'Pending', 'Install physical cable locks on all lab PCs and upgrade lab CCTV coverage.', 
         'Security Office', '${getDynamicDate(10)}'),

        ('SA-001', 'SA', 'PLM Library Management System', 'Library', 
         'LIB-APP-01', 'Library App Server', 'ITC Database Administrator', 
         'System managing book inventory and borrowing records.', 
         '10.20.5.15', 'Hybrid', 'Library Services',
         'Y', 'N', 'N', 2, 2, 3, 7, 'Confidential', 
         'cyber_int_vuln', 'Unpatched software vulnerabilities leading to system disruption.', 
         4, 3, 'High', 'Moderate', 
         'Mitigate', 'Done', 'Establish a monthly patch management routine for the library server OS.', 
         'ITC SecOps', '${getDynamicDate(-5)}'),

        ('PA-001', 'PA', 'University President & Board', 'Admin', 
         'EXEC-LPT-XX', 'Exec Endpoints', 'Office of the University Sec', 
         'Top-level executive management with highest signing authority.', 
         'DHCP', 'Hybrid', 'Administration',
         'Y', 'N', 'Y', 3, 3, 3, 9, 'Restricted', 
         'hr_insider', 'Targeted spear-phishing (Whaling) attempting to authorize fraudulent wire transfers.', 
         3, 5, 'High', 'High', 
         'Avoid', 'Pending', 'Mandate executive anti-phishing training and enforce out-of-band verbal verification for transfers.', 
         'CISO', '${getDynamicDate(40)}'),

        ('SV-001', 'SV', 'PLM Official Website', 'ITC', 
         'WEB-PROD-01', 'Public Web Server', 'ITC Web Development Team', 
         'Primary public-facing portal for university info.', 
         '203.177.X.X', 'Internet Facing', 'ITC',
         'N', 'N', 'Y', 1, 2, 3, 6, 'Confidential', 
         'cyber_ext_ddos', 'DDoS attack during admissions season rendering the site inaccessible.', 
         4, 3, 'High', 'Moderate', 
         'Transfer', 'In Progress', 'Route website traffic through a cloud-based DDoS mitigation and CDN service.', 
         'ITC Infra', '${getDynamicDate(2)}'),

        ('FA-001', 'FA', 'University Cashier Main Vault', 'Finance', 
         'N/A', 'N/A', 'Head Cashier / Security', 
         'Physical safe holding daily tuition fee collections.', 
         'N/A', 'Internal', 'Finance',
         'N', 'N', 'Y', 3, 3, 3, 9, 'Restricted', 
         'phys_theft', 'Theft or armed robbery targeting physical cash collections.', 
         2, 4, 'Moderate', 'Low', 
         'Transfer', 'Done', 'Insure the vault contents via third party.', 'Security', '${getDynamicDate(60)}'),

        ('IA-002', 'IA', 'PLM Alumni Database', 'Alumni Office', 
         'ALUM-DB-01', 'Alumni Records DB', 'ITC Enterprise Systems Team', 
         'Contact info and employment history of former students.', 
         '10.50.2.20', 'Internal', 'Alumni Affairs',
         'Y', 'N', 'N', 3, 2, 2, 7, 'Confidential', 
         'hr_insider', 'Unauthorized extraction of the database by an insider.', 
         3, 4, 'High', 'High', 
         'Mitigate', 'Pending', 'Enforce strict RBAC limiting export capabilities and monitor query logs.', 
         'ITC SecOps', '${getDynamicDate(12)}'),

        ('PhA-002', 'PhA', 'Campus Security CCTV NVR', 'Security', 
         'SEC-NVR-01', 'Video Storage Array', 'ITC Infrastructure Team', 
         'Network Video Recorder storing 30 days of security footage.', 
         '10.99.1.50', 'Internal', 'Campus Security',
         'N', 'N', 'N', 3, 3, 3, 9, 'Restricted', 
         'phys_destruct', 'Hardware failure due to overheating in the security office closet.', 
         3, 4, 'High', 'Moderate', 
         'Mitigate', 'In Progress', 'Relocate the NVR to the main climate-controlled server room with RAID 5.', 
         'Chief of Security', '${getDynamicDate(45)}'),

        ('SA-002', 'SA', 'HR Payroll & Benefits System', 'HR', 
         'HR-APP-01', 'Payroll Application', 'ITC Database Administrator', 
         'System calculating faculty salaries and tax deductions.', 
         '10.30.1.10', 'Internal', 'Human Resources',
         'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 
         'hr_insider', 'Disgruntled employee modifying salary bands (Insider Threat).', 
         2, 5, 'Moderate', 'Moderate', 
         'Mitigate', 'Pending', 'Implement strict segregation of duties (maker-checker rule) for payroll changes.', 
         'HR Director', '${getDynamicDate(8)}'),

        ('FA-002', 'FA', 'University Digital Banking Portal', 'Finance', 
         'BANK-GW-01', 'Banking Gateway', 'Finance IT Support', 
         'Online access to operational bank accounts for payments.', 
         '10.40.1.5', 'Internet Facing', 'Finance',
         'Y', 'Y', 'Y', 3, 3, 3, 9, 'Restricted', 
         'cyber_int_unauth', 'Unauthorized access to admin accounts via credential stuffing.', 
         3, 5, 'High', 'Low', 
         'Mitigate', 'Pending', 'Require physical hardware security keys for banking portal access.', 
         'VP for Finance', '${getDynamicDate(50)}')
    `);
    
    alasql(`INSERT INTO AssetControls VALUES 
        ('IA-001', 1), ('IA-001', 3), ('IA-001', 7), ('IA-001', 12),
        ('PhA-001', 5), ('PhA-001', 8),
        ('SA-001', 1), ('SA-001', 11),
        ('PA-001', 1),
        ('SV-001', 10), ('SV-001', 12), ('SV-001', 13),
        ('FA-001', 1), ('FA-001', 2), ('FA-001', 5),
        ('IA-002', 1), ('IA-002', 3), ('IA-002', 12),
        ('PhA-002', 1), ('PhA-002', 5), ('PhA-002', 6),
        ('SA-002', 1), ('SA-002', 2), ('SA-002', 3), ('SA-002', 4),
        ('FA-002', 3), ('FA-002', 4), ('FA-002', 10)
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

const CIA_CLASS = {
  3:'Public',4:'Internal Use',5:'Internal Use',6:'Confidential',
  7:'Confidential',8:'Restricted',9:'Restricted'
};

const CTRL_NAMES = [
  'Documented procedures', 'Segregation of duties', 'Role-Based Access Control (RBAC)', 
  'Multi-Factor Authentication (MFA)', 'Physical controls (CCTV, Locks)', 'Automated Information backup', 
  'Encryption (At Rest / In Transit)', 'Asset disposal procedures', 'Endpoint Detection & Response (EDR)', 
  'Network Firewall / WAF', 'Vulnerability Scanning & Patching', 'Network Segmentation (VLANs)', 'Incident Response Plan'
];

const controlMap = {
    'phys_theft': [5, 7, 8], 'phys_destruct': [5, 6, 13], 'hr_insider': [2, 3, 4, 12],
    'hr_accidental': [1, 3, 6], 'cyber_ext_ransomware': [4, 6, 9, 10, 11, 13], 
    'cyber_ext_leak': [3, 4, 7, 9, 10], 'cyber_ext_ddos': [10, 12, 13], 'cyber_ext_supply': [1, 3, 4, 10, 13],
    'cyber_int_unauth': [2, 3, 4, 9], 'cyber_int_vuln': [9, 10, 11, 12], 'legal_dpa': [1, 7, 8]
};

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

function generateSequentialId(type) {
    if (!type) return '';
    const existing = alasql(`SELECT id FROM Assets WHERE type = '${type}'`);
    let maxNumber = 0;
    existing.forEach(row => {
        const parts = row.id.split('-');
        if (parts.length === 2) {
            const num = parseInt(parts[1], 10);
            if (!isNaN(num) && num > maxNumber) maxNumber = num;
        }
    });
    return `${type}-${String(maxNumber + 1).padStart(3, '0')}`;
}

// ==========================================
// 3. MASTER IAS ENFORCEMENT ENGINE
// ==========================================
function runEnforcementEngine() {
    const type = document.getElementById('f-type').value;

    if (!editingId) {
        const currentId = document.getElementById('f-id').value;
        if (type && (!currentId || !currentId.startsWith(type + '-'))) {
            document.getElementById('f-id').value = generateSequentialId(type);
        } else if (!type) {
            document.getElementById('f-id').value = '';
        }
    }

    const env = document.getElementById('f-environment') ? document.getElementById('f-environment').value : 'Internal';
    
    // GUARDRAIL 1: Threat Restrictions based on Asset Type
    const optPhys = document.getElementById('opt-phys');
    const optHr = document.getElementById('opt-hr');
    const optCyberExt = document.getElementById('opt-cyber-ext');
    const optCyberInt = document.getElementById('opt-cyber-int');
    const optComp = document.getElementById('opt-comp');

    if (type === 'PhA') {
        if(optCyberExt) optCyberExt.disabled = true; if(optCyberInt) optCyberInt.disabled = true; if(optComp) optComp.disabled = true;
        if(optPhys) optPhys.disabled = false; if(optHr) optHr.disabled = false;
    } else if (type === 'PA') {
        if(optCyberExt) optCyberExt.disabled = true; if(optCyberInt) optCyberInt.disabled = true; if(optPhys) optPhys.disabled = true;
        if(optComp) optComp.disabled = false; if(optHr) optHr.disabled = false;
    } else if (type === 'SA' || type === 'SV' || type === 'IA' || type === 'FA') {
        if(optPhys) optPhys.disabled = true;
        if(optCyberExt) optCyberExt.disabled = false; if(optCyberInt) optCyberInt.disabled = false;
        if(optComp) optComp.disabled = false; if(optHr) optHr.disabled = false;
    } else {
        [optPhys, optHr, optCyberExt, optCyberInt, optComp].forEach(el => { if(el) el.disabled = false; });
    }

    // GUARDRAIL 2: Asset Type Data Overrides (Force Data values first)
    if (type === 'PhA') {
        ['f-pii','f-spi','f-corp'].forEach(id => { const el = document.getElementById(id); if(el) { el.value = 'N'; el.disabled = true; } });
    } else if (type === 'PA') {
        ['f-spi','f-corp'].forEach(id => { const el = document.getElementById(id); if(el) el.disabled = false; });
        const elPii = document.getElementById('f-pii'); if(elPii) { elPii.value = 'Y'; elPii.disabled = true; }
    } else if (type === 'FA') {
        ['f-pii','f-spi','f-corp'].forEach(id => { const el = document.getElementById(id); if(el) { el.value = 'Y'; el.disabled = true; } });
    } else {
        ['f-pii','f-spi','f-corp'].forEach(id => { const el = document.getElementById(id); if(el) el.disabled = false; });
    }

    // Now read the dynamically updated DOM states for the CIA locks!
    const currentPii = document.getElementById('f-pii') ? document.getElementById('f-pii').value : 'N';
    const currentSpi = document.getElementById('f-spi') ? document.getElementById('f-spi').value : 'N';
    
    // GUARDRAIL 3: Data Drives CIA
    const lockC = document.getElementById('lock-c');
    const lockA = document.getElementById('lock-a');
    
    if (type === 'FA') {
        ['f-c','f-i','f-a'].forEach(id => { const el = document.getElementById(id); if(el) { el.value = '3'; el.disabled = true; } });
        if(lockC) lockC.textContent = '🔒'; if(lockA) lockA.textContent = '🔒';
    } else {
        const hasPiiSpi = (currentPii === 'Y') || (currentSpi === 'Y');
        const elC = document.getElementById('f-c');
        if (hasPiiSpi && elC) { elC.value = '3'; elC.disabled = true; if(lockC) lockC.textContent = '🔒 Data Driven'; } 
        else if(elC) { elC.disabled = false; if(lockC) lockC.textContent = ''; }

        const elA = document.getElementById('f-a');
        if (env === 'Internet Facing' && elA) { elA.value = '3'; elA.disabled = true; if(lockA) lockA.textContent = '🔒 Env Driven'; } 
        else if(elA) { elA.disabled = false; if(lockA) lockA.textContent = ''; }
        
        const elI = document.getElementById('f-i');
        if(elI) elI.disabled = false;
    }

    const score = (+g('f-c')) + (+g('f-i')) + (+g('f-a'));
    const classEl = document.getElementById('cia-class');
    if(classEl) classEl.textContent = CIA_CLASS[score] || 'N/A';

    // GUARDRAIL 4: Mistake-Proof Controls
    const threat = g('f-risk-category');
    const validControls = controlMap[threat] || [1,2,3,4,5,6,7,8,9,10,11,12,13];

    for(let i=1; i<=13; i++) {
        const cb = document.getElementById('ctrl'+i);
        const label = cb ? cb.parentElement : null;
        if(cb && label) {
            if(validControls.includes(i)) {
                cb.disabled = false; label.style.opacity = '1'; label.style.textDecoration = 'none'; label.style.cursor = 'pointer';
            } else {
                cb.disabled = true; cb.checked = false; label.style.opacity = '0.3'; label.style.textDecoration = 'line-through'; label.style.cursor = 'not-allowed';
            }
        }
    }
    
    if (typeof updateTagsUI === "function") updateTagsUI();
    calculateRiskMath();
}

function calculateRiskMath() {
    let p = parseInt(g('f-prob')) || 3;
    let s = parseInt(g('f-sev')) || 3;
    const threat = g('f-risk-category');
    const env = g('f-environment');
    const currentPii = g('f-pii');
    const currentSpi = g('f-spi');

    if (env === 'Internet Facing' && threat.startsWith('cyber_ext')) p = Math.min(5, p + 1);
    if ((currentPii === 'Y' || currentSpi === 'Y') && (threat === 'cyber_ext_leak' || threat === 'legal_dpa')) s = 5;

    const inherentRating = INHERIT[s + '-' + p] || 'Moderate';
    const rEl = document.getElementById('r-inherit');
    if(rEl) { rEl.textContent = inherentRating; rEl.style.color = riskColor(inherentRating); }
    
    const validControls = controlMap[threat] || [1,2,3,4,5,6,7,8,9,10,11,12,13]; 
    let activeValidCount = 0;
    let pRed = 0, sRed = 0;

    for(let i=1; i<=13; i++) {
        const cb = document.getElementById('ctrl'+i);
        if(cb && cb.checked && validControls.includes(i)) {
            activeValidCount++;
            if ([1,2,3,4,5,8,10,11,12].includes(i)) pRed += 1.0; 
            if ([6,7,9,13].includes(i)) sRed += 1.0; 
        }
    }

    let resP = Math.max(1, p - Math.floor(pRed / 1.5));
    let resS = Math.max(1, s - Math.floor(sRed / 1.5));
    const residualRating = INHERIT[resS + '-' + resP] || 'Low';
    
    const resEl = document.getElementById('r-residual');
    if(resEl) { resEl.textContent = residualRating; resEl.style.color = riskColor(residualRating); }
    
    const fbEl = document.getElementById('control-feedback');
    if (fbEl) fbEl.textContent = `(${activeValidCount} relevant mitigating controls applied)`;

    // GUARDRAIL 5: Risk Appetite Enforcement
    const actTypeSelect = document.getElementById('f-action-type');
    const lockTreat = document.getElementById('lock-treat');
    
    if (actTypeSelect) {
        if (residualRating === 'High') {
            if (actTypeSelect.value === 'Accept') actTypeSelect.value = 'Mitigate';
            Array.from(actTypeSelect.options).forEach(opt => { if (opt.value === 'Accept') opt.disabled = true; });
            if(lockTreat) lockTreat.textContent = '🔒 Cannot accept High Risk';
        } else {
            Array.from(actTypeSelect.options).forEach(opt => opt.disabled = false);
            if(lockTreat) lockTreat.textContent = '';
        }
    }

    const apSection = document.getElementById('action-plan-section');
    if(apSection && actTypeSelect) {
        apSection.style.display = (actTypeSelect.value === 'Accept' || residualRating === 'Very Low') ? 'none' : 'block';
    }
}

function applyRiskTemplate() {
    const key = g('f-risk-category');
    if (RISK_TEMPLATES[key]) {
        const descEl = document.getElementById('f-risk-desc');
        const probEl = document.getElementById('f-prob');
        const sevEl = document.getElementById('f-sev');
        const apEl = document.getElementById('f-action-plan');
        
        if(descEl) descEl.value = RISK_TEMPLATES[key].desc;
        if(probEl) probEl.value = RISK_TEMPLATES[key].prob;
        if(sevEl) sevEl.value = RISK_TEMPLATES[key].sev;
        if(apEl && !apEl.value) apEl.value = RISK_TEMPLATES[key].action;
        
        notify("Risk template applied.");
    }
    runEnforcementEngine();
}

function riskColor(r) { return { 'Very Low': 'var(--success)', 'Low': 'var(--accent2)', 'Moderate': 'var(--warn)', 'High': 'var(--danger)' }[r] || 'var(--text)'; }
function riskBadge(r) { const cls = { 'Very Low': 'badge-vl', 'Low': 'badge-lo', 'Moderate': 'badge-mo', 'High': 'badge-hi' }[r] || 'badge-lo'; return `<span class="badge ${cls}">${r||'—'}</span>`; }

// ==========================================
// 4. NAVIGATION & UTILS
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

function g(id) { const el = document.getElementById(id); return el ? el.value : ''; }

// ==========================================
// 5. UI LOGIC (Multi-Select & Alerts)
// ==========================================
document.addEventListener('click', function(event) {
    const wrapper = document.querySelector('.multi-select-wrapper');
    const dropdown = document.getElementById('ctrl-dropdown');
    if (wrapper && dropdown && !wrapper.contains(event.target)) {
        dropdown.classList.remove('show');
    }
});

function updateTagsUI() {
    const container = document.getElementById('selected-controls-tags');
    if (!container) return;
    container.innerHTML = '';
    
    [1,2,3,4,5,6,7,8,9,10,11,12,13].forEach(n => {
        const cb = document.getElementById('ctrl'+n);
        if (cb && cb.checked) {
            const tag = document.createElement('div');
            tag.className = 'tag';
            tag.innerHTML = `${CTRL_NAMES[n-1]} <span class="tag-close" onclick="removeTag(${n}, event)">×</span>`;
            container.appendChild(tag);
        }
    });
}

function updateTags() {
    updateTagsUI();
    runEnforcementEngine(); 
}

function removeTag(n, event) {
    event.stopPropagation();
    const cb = document.getElementById('ctrl'+n);
    if (cb) cb.checked = false;
    updateTags();
}

function calculateDeadlines() {
    const today = new Date(); today.setHours(0,0,0,0);
    const limit = new Date(today); limit.setDate(today.getDate() + 14);
    let dCount = 0;
    alasql("SELECT actionDate, actionStatus, actionType FROM Assets").forEach(a => {
        if (a.actionDate && a.actionStatus !== 'Done' && a.actionType !== 'Accept') {
            const target = new Date(a.actionDate); target.setHours(0,0,0,0);
            if (target <= limit) dCount++;
        }
    });
    
    const hCount = alasql("SELECT VALUE COUNT(*) FROM Assets WHERE residual = 'High'");
    
    const highBadge = document.getElementById('hdr-high');
    if(highBadge) highBadge.textContent = hCount;

    const deadBadge = document.getElementById('hdr-deadlines');
    if(deadBadge) {
        deadBadge.textContent = dCount;
        deadBadge.style.color = dCount > 0 ? "var(--danger)" : "var(--warn)";
    }
}

// ==========================================
// 6. SQL CRUD OPERATIONS
// ==========================================
function saveAssetToDB() {
  const type = g('f-type');
  const name = g('f-name').trim();
  if (!type) return notify('Error: Select an asset type', true);
  if (!name) return notify('Error: Enter an asset name', true);
  
  const id = editingId || g('f-id');
  const residual = document.getElementById('r-residual') ? document.getElementById('r-residual').textContent : 'Low';
  const inherit = document.getElementById('r-inherit') ? document.getElementById('r-inherit').textContent : 'Moderate';
  
  const p = parseInt(g('f-prob')) || 3;
  const s = parseInt(g('f-sev')) || 3;
  const c = +g('f-c'), ii = +g('f-i'), a = +g('f-a');

  alasql(`DELETE FROM Assets WHERE id = '${id}'`);
  alasql(`DELETE FROM AssetControls WHERE asset_id = '${id}'`);

  alasql(`INSERT INTO Assets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, [
      id, type, name, g('f-group'), 
      g('f-hostname'), g('f-server'), g('f-custodian'), g('f-desc'), 
      g('f-ip'), g('f-environment'), g('f-department'),
      g('f-pii'), g('f-spi'), g('f-corp'),
      c, ii, a, c+ii+a, document.getElementById('cia-class').textContent, 
      g('f-risk-category'), g('f-risk-desc'), p, s, inherit, residual, 
      g('f-action-type'), g('f-action-status'), g('f-action-plan'), g('f-action-owner'), g('f-action-date')
  ]);

  for(let i=1; i<=13; i++) { 
      const cb = document.getElementById('ctrl'+i);
      if(cb && cb.checked && !cb.disabled) { alasql("INSERT INTO AssetControls VALUES (?,?)", [id, i]); }
  }

  persistDB(); editingId = null; clearForm(); notify(`Asset ${id} saved successfully!`);
  showSection('register'); renderDashboard();
}

function editAsset(id) {
  try {
      const a = alasql(`SELECT * FROM Assets WHERE id = '${id}'`)[0];
      if (!a) return notify("Error finding asset.", true);

      editingId = id;
      const titleEl = document.getElementById('form-title');
      if(titleEl) titleEl.innerHTML = 'UPDATE <span>RECORD</span>';

      const map = { 
          'f-type':a.type, 'f-id':a.id, 'f-name':a.name, 'f-group':a.group_name, 'f-desc':a.description, 
          'f-hostname':a.hostname, 'f-server':a.server, 'f-custodian':a.custodian, 
          'f-ip':a.ip_address, 'f-environment':a.environment, 'f-department':a.department, 
          'f-pii':a.pii, 'f-spi':a.spi, 'f-corp':a.corp, 
          'f-c':a.ciaC, 'f-i':a.ciaI, 'f-a':a.ciaA, 
          'f-risk-category':a.riskCategory, 'f-risk-desc':a.riskDesc, 'f-prob':a.prob, 'f-sev':a.sev, 
          'f-action-type':a.actionType, 'f-action-status':a.actionStatus, 
          'f-action-plan':a.actionPlan, 'f-action-owner':a.actionOwner, 'f-action-date':a.actionDate 
      };
      
      for(let key in map) { 
          const el = document.getElementById(key);
          if(el !== null) el.value = map[key] || ''; 
      }

      const ctrls = alasql(`SELECT ctrl_id FROM AssetControls WHERE asset_id = '${id}'`).map(r => r.ctrl_id);
      for(let i=1; i<=13; i++) { 
          const cb = document.getElementById('ctrl'+i); 
          if(cb) cb.checked = ctrls.includes(i); 
      }

      runEnforcementEngine(); 
      setTimeout(updateTagsUI, 50); 
      showSection('add'); window.scrollTo(0,0);
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
  const fields = ['f-name','f-group','f-hostname','f-server','f-custodian','f-desc', 'f-ip', 'f-department', 'f-risk-desc','f-action-plan','f-action-owner','f-action-date','f-risk-category'];
  fields.forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
  
  const selects = ['f-type', 'f-id'];
  selects.forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });

  if(document.getElementById('f-environment')) document.getElementById('f-environment').value = 'Internal';
  if(document.getElementById('f-pii')) document.getElementById('f-pii').value = 'N';
  if(document.getElementById('f-spi')) document.getElementById('f-spi').value = 'N';
  if(document.getElementById('f-corp')) document.getElementById('f-corp').value = 'N';
  if(document.getElementById('f-c')) document.getElementById('f-c').value = '2';
  if(document.getElementById('f-i')) document.getElementById('f-i').value = '2';
  if(document.getElementById('f-a')) document.getElementById('f-a').value = '2';
  if(document.getElementById('f-prob')) document.getElementById('f-prob').value = '3';
  if(document.getElementById('f-sev')) document.getElementById('f-sev').value = '3';
  if(document.getElementById('f-action-type')) document.getElementById('f-action-type').value = 'Mitigate';
  if(document.getElementById('f-action-status')) document.getElementById('f-action-status').value = 'Pending';
  
  for(let i=1; i<=13; i++) { const cb = document.getElementById('ctrl'+i); if(cb) cb.checked = false; }
  
  editingId = null;
  const titleEl = document.getElementById('form-title');
  if(titleEl) titleEl.innerHTML = 'INSERT <span>RECORD</span>';
  
  runEnforcementEngine(); 
  updateTagsUI();
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
        const el = document.getElementById(id);
        if(el) el.value = val || '';
    }
}

// ==========================================
// 7. UI RENDERING (SQL Driven)
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

  tbody.innerHTML = data.map(a => {
    const ctrls = alasql("SELECT ctrl_id FROM AssetControls WHERE asset_id = ?", [a.id]).length;
    return `
    <tr>
      <td><span class="badge badge-id">${a.id}</span></td>
      <td><strong>${a.name}</strong></td>
      <td style="color:var(--text2);font-size:11px">${(a.riskDesc||'—').substring(0,60)}${(a.riskDesc||'').length>60?'...':''}</td>
      <td>${riskBadge(a.inherit)}</td>
      <td style="font-size:11px;color:var(--text2);">${ctrls} Controls</td>
      <td>${riskBadge(a.residual)}</td>
    </tr>
  `}).join('');
}

function updateMatrixHeatmap() {
  document.querySelectorAll('.mx-count').forEach(el => { el.textContent = ''; el.classList.remove('active'); el.style.opacity = "0"; });
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
  const total = alasql("SELECT VALUE COUNT(*) FROM Assets") || 1;
  const ctrlCounts = alasql("SELECT ctrl_id, COUNT(*) as c FROM AssetControls GROUP BY ctrl_id");
  const colors = ['var(--accent)','var(--accent2)','var(--success)','var(--warn)','var(--purple)','var(--danger)','var(--info)','var(--accent)', 'var(--accent2)','var(--success)','var(--warn)','var(--purple)','var(--danger)'];
  
  const barsEl = document.getElementById('ctrl-bars');
  if(barsEl) {
      barsEl.innerHTML = CTRL_NAMES.map((name,i) => {
        const dbRow = ctrlCounts.find(row => row.ctrl_id === (i+1));
        const count = dbRow ? dbRow.c : 0;
        const pct = Math.round((count/total)*100);
        return `<div class="chart-bar-row">
          <div class="chart-bar-label" style="width:250px; text-align:left;">${name} <span style="color:var(--text3); margin-left:8px;">${count} / ${total} (${pct}%)</span></div>
          <div class="chart-bar-track"><div class="chart-bar-fill" style="width:${pct}%;background:${colors[i]}"></div></div>
        </div>`;
      }).join('');
  }
}

// GROUPED ACTIONS UI (Mitigate, Transfer, Avoid)
function renderActions() {
    const items = alasql("SELECT * FROM Assets WHERE residual IN ('High', 'Moderate') AND actionType != 'Accept' ORDER BY actionDate ASC");
    const el = document.getElementById('actions-content');
    if(!el) return;

    if (!items.length) {
        el.innerHTML = '<div class="empty-state"><div>[✓]</div>No pending actions for High or Moderate risks. Excellent posture!</div>';
        return;
    }

    const groups = { 'Mitigate': [], 'Transfer': [], 'Avoid': [] };
    items.forEach(a => { if (groups[a.actionType]) groups[a.actionType].push(a); else groups['Mitigate'].push(a); });

    let html = '';
    for (const [strategy, groupItems] of Object.entries(groups)) {
        if (groupItems.length === 0) continue;
        
        html += `<div style="margin-bottom:32px;">
            <div style="font-family:var(--mono); font-size:14px; color:var(--text); border-bottom:1px solid var(--border); padding-bottom:8px; margin-bottom:16px;">
                <span style="color:var(--accent2)">Strategy Category:</span> ${strategy.toUpperCase()} (${groupItems.length} items)
            </div>`;
        
        html += groupItems.map(a => `
            <div class="card" style="border-left:3px solid ${a.residual==='High'?'var(--danger)':'var(--warn)'}; margin-bottom:12px; padding:16px 24px;">
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
                        <div style="font-family:var(--mono);font-size:9px;letter-spacing:1px;text-transform:uppercase;color:var(--text3);margin-bottom:4px">Action Plan / Goal - <span style="color:var(--accent2)">${a.actionStatus}</span></div>
                        <div style="font-size:12px;color:var(--text2)">${a.actionPlan||'<span style="color:var(--danger)">No Action Plan Set!</span>'}</div>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-family:var(--mono);font-size:9px;letter-spacing:1px;text-transform:uppercase;color:var(--text3);margin-bottom:4px">Target Timeline</div>
                        <div style="font-size:13px;color:var(--text)">${a.actionDate||'Not Set'}</div>
                        <div style="margin-top:8px;font-family:var(--mono);font-size:10px;color:var(--text3)">Owner: <span style="color:var(--text2)">${a.actionOwner||'—'}</span></div>
                    </div>
                </div>
                <div style="margin-top:12px;display:flex;justify-content:flex-end">
                    <button class="btn btn-sm" onclick="editAsset('${a.id}')">Update Asset →</button>
                </div>
            </div>
        `).join('');
        html += `</div>`; 
    }
    el.innerHTML = html;
}

function renderDashboard() {
  const total = alasql("SELECT VALUE COUNT(*) FROM Assets");
  
  const headerTotal = document.getElementById('hdr-total');
  const navTotal = document.getElementById('nav-total');
  if(headerTotal) headerTotal.textContent = total;
  if(navTotal) navTotal.textContent = total;
  
  const dmTotal = document.getElementById('dm-total');
  const dmHigh = document.getElementById('dm-high');
  const dmMod = document.getElementById('dm-mod');
  const dmPii = document.getElementById('dm-pii');
  
  if(dmTotal) dmTotal.textContent = total;
  if(dmHigh) dmHigh.textContent = alasql("SELECT VALUE COUNT(*) FROM Assets WHERE residual = 'High'");
  if(dmMod) dmMod.textContent = alasql("SELECT VALUE COUNT(*) FROM Assets WHERE residual = 'Moderate'");
  if(dmPii) dmPii.textContent = alasql("SELECT VALUE COUNT(*) FROM Assets WHERE pii = 'Y' OR spi = 'Y'");

  // Update the side navigation badge correctly
  const actionsCount = alasql("SELECT * FROM Assets WHERE residual IN ('High', 'Moderate') AND actionType != 'Accept'").length;
  const navActions = document.getElementById('nav-actions');
  if(navActions) navActions.textContent = actionsCount;

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
  calculateDeadlines();
}

function exportDataXLSX() {
    if (typeof XLSX === 'undefined') { notify("Excel library loading...", true); return; }
    
    const dbAssets = alasql("SELECT * FROM Assets");
    const rep = alasql("SELECT * FROM ReportData WHERE id = 1")[0] || {};
    
    const headers = [ "Asset ID", "Name of Information Asset", "Description", "Group", "Hostname", "Server", "Custodian", "IP Address", "Environment", "Department", "Type", "PII", "SPI", "Corp Info", "C", "I", "A", "Valuation", "Class", "Risk Threat", "Prob", "Sev", "Inherent", "C1 (Procedures)", "C2 (Segregation)", "C3 (RBAC)", "C4 (MFA)", "C5 (Physical)", "C6 (Backup)", "C7 (Encryption)", "C8 (Disposal)", "C9 (EDR)", "C10 (Firewall)", "C11 (Patching)", "C12 (VLANs)", "C13 (IR Plan)", "Residual", "Strategy", "Status", "Action Plan", "Action Owner", "Target Date" ];

    const dataRows = dbAssets.map(a => {
        const ctrls = alasql("SELECT ctrl_id FROM AssetControls WHERE asset_id = ?", [a.id]).map(r => r.ctrl_id);
        return [
            a.id, a.name, a.description, a.group_name, a.hostname, a.server, a.custodian, a.ip_address, a.environment, a.department, a.type, a.pii, a.spi, a.corp,
            a.ciaC, a.ciaI, a.ciaA, a.ciaScore, a.ciaClass, a.riskDesc, a.prob, a.sev, a.inherit,
            ctrls.includes(1)?"Y":"N", ctrls.includes(2)?"Y":"N", ctrls.includes(3)?"Y":"N", ctrls.includes(4)?"Y":"N",
            ctrls.includes(5)?"Y":"N", ctrls.includes(6)?"Y":"N", ctrls.includes(7)?"Y":"N", ctrls.includes(8)?"Y":"N",
            ctrls.includes(9)?"Y":"N", ctrls.includes(10)?"Y":"N", ctrls.includes(11)?"Y":"N", ctrls.includes(12)?"Y":"N", ctrls.includes(13)?"Y":"N",
            a.residual, a.actionType, a.actionStatus, a.actionPlan, a.actionOwner, a.actionDate
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
// 8. INITIALIZATION
// ==========================================
setTimeout(() => { runEnforcementEngine(); renderDashboard(); }, 200); 
showSection('dashboard');