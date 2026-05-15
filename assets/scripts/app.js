/* ==========================================
   IMPACTLENS - MAIN APPLICATION
   Enterprise Risk Assessment (Supabase Cloud Version)
   ========================================== */

// 1. SUPABASE INITIALIZATION
const supabaseUrl = 'https://haspklehikocqswmgmtk.supabase.co';
const supabaseKey = 'sb_publishable_O1qHjWdSJ1hZYraL8mmxYQ_CPRr0Sv6';
const supabase = window.supabase.createClient(supabaseUrl, supabaseKey);

// Global State (Replaces AlaSQL in-memory tables)
let globalAssets = [];
let globalControls = [];
let globalReport = {};
let editingId = null;

// Helper to generate dynamic dates
const getDynamicDate = (daysToAdd) => {
    const d = new Date(); d.setDate(d.getDate() + daysToAdd);
    return d.toISOString().split('T')[0];
};

// ==========================================
// 2. CONSTANTS & IAS MAPPING
// ==========================================
const INHERIT = { 
  '5-1':'Moderate','5-2':'Moderate','5-3':'High','5-4':'High','5-5':'High', 
  '4-1':'Low','4-2':'Moderate','4-3':'Moderate','4-4':'High','4-5':'High', 
  '3-1':'Low','3-2':'Moderate','3-3':'Moderate','3-4':'Moderate','3-5':'High', 
  '2-1':'Low','2-2':'Low','2-3':'Moderate','2-4':'Moderate','2-5':'Moderate', 
  '1-1':'Very Low','1-2':'Low','1-3':'Low','1-4':'Low','1-5':'Moderate' 
};

const CIA_CLASS = { 3:'Public',4:'Internal Use',5:'Internal Use',6:'Confidential', 7:'Confidential',8:'Restricted',9:'Restricted' };

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

// THE STRICT CYBERSECURITY PROFILES MATRIX
const ASSET_PROFILES = {
    'IA':  { pii: 'Y', spi: 'Y', corp: 'N', c: 3, i: 3, a: 2 },
    'PhA': { pii: 'N', spi: 'N', corp: 'N', c: 1, i: 2, a: 2 },
    'PA':  { pii: 'Y', spi: 'N', corp: 'Y', c: 3, i: 3, a: 3 },
    'SA':  { pii: 'Y', spi: 'N', corp: 'N', c: 2, i: 2, a: 3 },
    'SV':  { pii: 'N', spi: 'N', corp: 'Y', c: 1, i: 2, a: 3 },
    'FA':  { pii: 'Y', spi: 'Y', corp: 'Y', c: 3, i: 3, a: 3 }
};

function generateSequentialId(type) {
    if (!type) return '';
    const existing = globalAssets.filter(a => a.type === type);
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
function runEnforcementEngine(skipAutoTemplate = false) {
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
    
    // GUARDRAIL 1: STRICT CYBERSECURITY DATA & CIA LOCKS
    const lockC = document.getElementById('lock-c');
    const lockI = document.getElementById('lock-i');
    const lockA = document.getElementById('lock-a');

    if (type && ASSET_PROFILES[type]) {
        const profile = ASSET_PROFILES[type];
        
        // Auto-fill and completely lock ALL 6 fields based on the selected Type
        ['f-pii', 'f-spi', 'f-corp', 'f-c', 'f-i', 'f-a'].forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                const key = id.replace('f-', '');
                el.value = profile[key];
                el.disabled = true;
            }
        });

        const elA = document.getElementById('f-a');
        if (env === 'Internet Facing' && elA) {
            elA.value = '3';
        }

        if(lockC) lockC.textContent = '🔒 System Enforced';
        if(lockI) lockI.textContent = '🔒 System Enforced';
        if(lockA) lockA.textContent = (env === 'Internet Facing') ? '🔒 Env Driven' : '🔒 System Enforced';

    } else {
        ['f-pii', 'f-spi', 'f-corp', 'f-c', 'f-i', 'f-a'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.disabled = false; 
        });
        if(lockC) lockC.textContent = '';
        if(lockI) lockI.textContent = '';
        if(lockA) lockA.textContent = '';
    }

    const score = (+g('f-c')) + (+g('f-i')) + (+g('f-a'));
    const classEl = document.getElementById('cia-class');
    if(classEl) classEl.textContent = CIA_CLASS[score] || 'N/A';

    // GUARDRAIL 2: Threat Restrictions based on Asset Type
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

    const riskSelect = document.getElementById('f-risk-category');
    if (riskSelect && riskSelect.options[riskSelect.selectedIndex] && riskSelect.options[riskSelect.selectedIndex].disabled) {
        riskSelect.value = ""; 
    }

    // GUARDRAIL 3: Mistake-Proof Controls
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

    // Risk Escalations
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

    // Risk Appetite Enforcement
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
// 4. SUPABASE CLOUD SYNC & UI NAVIGATION
// ==========================================

async function syncFromCloud() {
    try {
        const { data: aData, error: aErr } = await supabase.from('Assets').select('*');
        if (aErr) throw aErr;
        globalAssets = aData || [];

        const { data: cData, error: cErr } = await supabase.from('AssetControls').select('*');
        if (cErr) throw cErr;
        globalControls = cData || [];

        const { data: rData } = await supabase.from('ReportData').select('*').eq('id', 1).single();
        globalReport = rData || {};
    } catch (err) {
        console.error("Cloud Sync Error: ", err);
        notify("Failed to connect to Supabase DB. Make sure your tables are created.", true);
    }
}

async function showSection(name) {
  // Sync before drawing UI to ensure fresh cloud data
  if (['dashboard', 'register', 'risk', 'controls', 'actions', 'report'].includes(name)) {
      await syncFromCloud();
  }

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
    if (wrapper && dropdown && !wrapper.contains(event.target)) dropdown.classList.remove('show');
});

function updateTagsUI() {
    const cont = document.getElementById('selected-controls-tags');
    if (!cont) return; cont.innerHTML = '';
    [1,2,3,4,5,6,7,8,9,10,11,12,13].forEach(n => {
        const cb = document.getElementById('ctrl'+n);
        if (cb && cb.checked) {
            cont.innerHTML += `<div class="tag">${CTRL_NAMES[n-1]} <span class="tag-close" onclick="removeTag(${n}, event)">×</span></div>`;
        }
    });
}

function updateTags() { updateTagsUI(); runEnforcementEngine(); }

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
    
    globalAssets.forEach(a => {
        if (a.actionDate && a.actionStatus !== 'Done' && a.actionType !== 'Accept') {
            const target = new Date(a.actionDate); target.setHours(0,0,0,0);
            if (target <= limit) dCount++;
        }
    });
    
    const hCount = globalAssets.filter(a => a.residual === 'High').length;
    const actionsCount = globalAssets.filter(a => ['High', 'Moderate'].includes(a.residual) && a.actionType !== 'Accept').length;
    
    if(document.getElementById('hdr-high')) document.getElementById('hdr-high').textContent = hCount;
    if(document.getElementById('hdr-deadlines')) {
        document.getElementById('hdr-deadlines').textContent = dCount;
        document.getElementById('hdr-deadlines').style.color = dCount > 0 ? "var(--danger)" : "var(--warn)";
    }
    if(document.getElementById('nav-actions')) document.getElementById('nav-actions').textContent = actionsCount;
}

// ==========================================
// 6. SUPABASE CRUD OPERATIONS
// ==========================================
async function saveAssetToDB() {
  const type = g('f-type');
  const name = g('f-name').trim();
  if (!type) return notify('Error: Select an asset type', true);
  if (!name) return notify('Error: Enter an asset name', true);
  
  const id = editingId || g('f-id');
  const residual = document.getElementById('r-residual') ? document.getElementById('r-residual').textContent : 'Low';
  const inherit = document.getElementById('r-inherit') ? document.getElementById('r-inherit').textContent : 'Moderate';
  
  const p = parseInt(g('f-prob')) || 3;
  const s = parseInt(g('f-sev')) || 3;
  
  // Force retrieval of locked values directly
  const c = parseInt(document.getElementById('f-c').value) || 2;
  const ii = parseInt(document.getElementById('f-i').value) || 2;
  const a = parseInt(document.getElementById('f-a').value) || 2;
  
  const pii = document.getElementById('f-pii').value;
  const spi = document.getElementById('f-spi').value;
  const corp = document.getElementById('f-corp').value;

  const payload = {
      id: id, type: type, name: name, group_name: g('f-group'), 
      hostname: g('f-hostname'), server: g('f-server'), custodian: g('f-custodian'), description: g('f-desc'), 
      ip_address: g('f-ip'), environment: g('f-environment'), department: g('f-department'),
      pii: pii, spi: spi, corp: corp,
      ciaC: c, ciaI: ii, ciaA: a, ciaScore: c+ii+a, ciaClass: document.getElementById('cia-class').textContent, 
      riskCategory: g('f-risk-category'), riskDesc: g('f-risk-desc'), prob: p, sev: s, inherit: inherit, residual: residual, 
      actionType: g('f-action-type'), actionStatus: g('f-action-status'), actionPlan: g('f-action-plan'), actionOwner: g('f-action-owner'), actionDate: g('f-action-date')
  };

  // 1. Upsert to Supabase
  const { error: assetErr } = await supabase.from('Assets').upsert(payload);
  if (assetErr) return notify('Cloud Error: ' + assetErr.message, true);

  // 2. Clear old controls and insert new ones
  await supabase.from('AssetControls').delete().eq('asset_id', id);

  const controls = [];
  for(let i=1; i<=13; i++) { 
      const cb = document.getElementById('ctrl'+i);
      if(cb && cb.checked && !cb.disabled) { controls.push({ asset_id: id, ctrl_id: i }); }
  }
  
  if(controls.length > 0) {
      const { error: ctrlErr } = await supabase.from('AssetControls').insert(controls);
      if (ctrlErr) return notify('Cloud Error saving controls.', true);
  }

  editingId = null; 
  clearForm(); 
  notify(`Asset ${id} saved to Cloud!`);
  showSection('register'); 
}

function editAsset(id) {
  try {
      const a = globalAssets.find(x => x.id === id);
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
      
      const typeEl = document.getElementById('f-type');
      if(typeEl) typeEl.dataset.lastType = a.type;

      const ctrls = globalControls.filter(x => x.asset_id === id).map(x => x.ctrl_id);
      for(let i=1; i<=13; i++) { 
          const cb = document.getElementById('ctrl'+i); 
          if(cb) cb.checked = ctrls.includes(i); 
      }

      runEnforcementEngine(true); 
      setTimeout(updateTagsUI, 50); 
      
      document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
      document.getElementById('sec-add').classList.add('active');
      window.scrollTo(0,0);
  } catch (err) {
      console.error("Edit Error:", err);
      notify("Failed to open asset for editing.", true);
  }
}

async function deleteAsset(id) {
  if (!confirm(`Are you sure you want to permanently delete asset ${id} from Cloud?`)) return;
  try {
      const { error } = await supabase.from('Assets').delete().eq('id', id);
      if (error) throw error;
      
      notify(`Asset ${id} deleted from Cloud.`);
      showSection('register');
  } catch(err) {
      console.error("Deletion Error:", err);
      notify("Failed to delete asset from Cloud.", true);
  }
}

function clearForm() {
  const fields = ['f-name','f-group','f-hostname','f-server','f-custodian','f-desc', 'f-ip', 'f-department', 'f-risk-desc','f-action-plan','f-action-owner','f-action-date','f-risk-category'];
  fields.forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
  
  const selects = ['f-type', 'f-id'];
  selects.forEach(id => { const el = document.getElementById(id); if(el) { el.value = ''; el.dataset.lastType = ''; } });

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

async function saveReportData() {
    const payload = {
        id: 1, docDate: g('doc-date'), docVersion: g('doc-version'), docAuthor: g('doc-author'), docApproval: g('doc-approval'), docDesc: g('doc-desc'),
        revHigh: g('rep-rev-high'), initHigh: g('rep-init-high'),
        prepName: g('rep-prep-name'), prepTitle: g('rep-prep-title'), revName: g('rep-rev-name'), revTitle: g('rep-rev-title'), appName: g('rep-app-name'), appTitle: g('rep-app-title')
    };
    const { error } = await supabase.from('ReportData').upsert(payload);
    if(error) notify("Cloud save failed.", true);
    else notify("Report Details Saved to Database!");
}

function loadReportDataToUI() {
    const r = globalReport;
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
// 7. UI RENDERING (From Cloud Memory)
// ==========================================
function renderRegister() {
  const tbody = document.getElementById('reg-body');
  if(!tbody) return;

  if (!globalAssets.length) { tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;">No records in DB.</td></tr>`; return; }

  tbody.innerHTML = globalAssets.map(a => `
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
  let data = [...globalAssets];
  data.sort((a,b) => {
    const order = {High:0, Moderate:1, Low:2, 'Very Low':3};
    return (order[a.residual]||4) - (order[b.residual]||4);
  });

  const tbody = document.getElementById('risk-body');
  if(!tbody) return;
  
  if (!data.length) { tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;">No records in DB.</td></tr>`; return; }

  tbody.innerHTML = data.map(a => {
    const ctrls = globalControls.filter(c => c.asset_id === a.id).length;
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
  
  const riskCounts = {};
  globalAssets.forEach(a => {
      if(a.prob && a.sev) {
          const key = `${a.prob}-${a.sev}`;
          riskCounts[key] = (riskCounts[key] || 0) + 1;
      }
  });

  for(const [key, count] of Object.entries(riskCounts)) {
     const cellId = `mx-${key}`;
     const cell = document.getElementById(cellId);
     if(cell) {
         let existingCount = cell.querySelector('.mx-count');
         if(!existingCount) {
             existingCount = document.createElement('div');
             existingCount.className = 'mx-count';
             cell.appendChild(existingCount);
         }
         existingCount.textContent = count;
         existingCount.style.opacity = "1";
         existingCount.classList.add('active');
     }
  }
}

function renderControls() {
  const total = globalAssets.length || 1;
  const ctrlCounts = {};
  globalControls.forEach(c => {
      ctrlCounts[c.ctrl_id] = (ctrlCounts[c.ctrl_id] || 0) + 1;
  });
  
  const colors = ['var(--accent)','var(--accent2)','var(--success)','var(--warn)','var(--purple)','var(--danger)','var(--info)','var(--accent)', 'var(--accent2)','var(--success)','var(--warn)','var(--purple)','var(--danger)'];
  
  const barsEl = document.getElementById('ctrl-bars');
  if(barsEl) {
      barsEl.innerHTML = CTRL_NAMES.map((name,i) => {
        const count = ctrlCounts[i+1] || 0;
        const pct = Math.round((count/total)*100);
        return `<div class="chart-bar-row">
          <div class="chart-bar-label" style="width:250px; text-align:left;">${name} <span style="color:var(--text3); margin-left:8px;">${count} / ${total} (${pct}%)</span></div>
          <div class="chart-bar-track"><div class="chart-bar-fill" style="width:${pct}%;background:${colors[i]}"></div></div>
        </div>`;
      }).join('');
  }
}

function renderActions() {
    const items = globalAssets.filter(a => ['High', 'Moderate'].includes(a.residual) && a.actionType !== 'Accept')
                              .sort((a,b) => new Date(a.actionDate||'2099-01-01') - new Date(b.actionDate||'2099-01-01'));
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
  const total = globalAssets.length;
  
  if(document.getElementById('hdr-total')) document.getElementById('hdr-total').textContent = total;
  if(document.getElementById('nav-total')) document.getElementById('nav-total').textContent = total;
  if(document.getElementById('dm-total')) document.getElementById('dm-total').textContent = total;
  
  const highRisk = globalAssets.filter(a => a.residual === 'High').length;
  const modRisk = globalAssets.filter(a => a.residual === 'Moderate').length;
  const piiCount = globalAssets.filter(a => a.pii === 'Y' || a.spi === 'Y').length;
  
  if(document.getElementById('dm-high')) document.getElementById('dm-high').textContent = highRisk;
  if(document.getElementById('dm-mod')) document.getElementById('dm-mod').textContent = modRisk;
  if(document.getElementById('dm-pii')) document.getElementById('dm-pii').textContent = piiCount;

  const barHtml = (label, val, t, color) => {
    if(!val) return ''; 
    const pct = Math.round((val/t)*100);
    return `<div class="chart-bar-row"><div class="chart-bar-label">${label}</div><div class="chart-bar-track"><div class="chart-bar-fill" style="width:${pct}%;background:${color};color:#000">${pct>10?pct+'%':''}</div></div><div class="chart-bar-count" style="width:24px;text-align:right;">${val}</div></div>`;
  };

  const byType = {}; globalAssets.forEach(a => byType[a.type] = (byType[a.type] || 0) + 1);
  const typeColors = {IA:'var(--accent)',PhA:'var(--accent2)',PA:'var(--success)',SA:'var(--warn)',SV:'var(--purple)', 'FA':'var(--info)'};
  const typeEl = document.getElementById('dash-types');
  if(typeEl) {
      if(Object.keys(byType).length === 0) typeEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else typeEl.innerHTML = Object.keys(byType).map(t => barHtml(t, byType[t], total || 1, typeColors[t])).join('');
  }

  const byRes = {}; globalAssets.forEach(a => byRes[a.residual] = (byRes[a.residual] || 0) + 1);
  const rColors = {'High':'var(--danger)','Moderate':'var(--warn)','Low':'var(--accent2)','Very Low':'var(--success)'};
  const resEl = document.getElementById('dash-residual');
  if(resEl) {
      if(Object.keys(byRes).length === 0) resEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else resEl.innerHTML = Object.keys(byRes).map(r => barHtml(r, byRes[r], total || 1, rColors[r])).join('');
  }

  const byClass = {}; globalAssets.forEach(a => byClass[a.ciaClass] = (byClass[a.ciaClass] || 0) + 1);
  const cColors = {'Public':'var(--success)','Internal Use':'var(--accent2)','Confidential':'var(--warn)','Restricted':'var(--danger)'};
  const classEl = document.getElementById('dash-class');
  if(classEl) {
      if(Object.keys(byClass).length === 0) classEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else classEl.innerHTML = Object.keys(byClass).map(c => barHtml(c, byClass[c], total || 1, cColors[c])).join('');
  }

  const trEl = document.getElementById('dash-top-risk');
  if(trEl) {
      const sevMap = { 'Critical': 1, 'High': 2, 'Moderate': 3, 'Low': 4, 'Very Low': 5 };
      const topRisks = [...globalAssets].sort((a, b) => (sevMap[a.residual] || 6) - (sevMap[b.residual] || 6)).slice(0, 5);
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
    
    const rep = globalReport;
    const headers = [ "Asset ID", "Name of Information Asset", "Description", "Group", "Hostname", "Server", "Custodian", "IP Address", "Environment", "Department", "Type", "PII", "SPI", "Corp Info", "C", "I", "A", "Valuation", "Class", "Risk Threat", "Prob", "Sev", "Inherent", "C1 (Procedures)", "C2 (Segregation)", "C3 (RBAC)", "C4 (MFA)", "C5 (Physical)", "C6 (Backup)", "C7 (Encryption)", "C8 (Disposal)", "C9 (EDR)", "C10 (Firewall)", "C11 (Patching)", "C12 (VLANs)", "C13 (IR Plan)", "Residual", "Strategy", "Status", "Action Plan", "Action Owner", "Target Date" ];

    const dataRows = globalAssets.map(a => {
        const ctrls = globalControls.filter(c => c.asset_id === a.id).map(c => c.ctrl_id);
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
setTimeout(() => { showSection('dashboard'); runEnforcementEngine(); }, 200);