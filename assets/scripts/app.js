/* ==========================================
   IMPACTLENS - MAIN APPLICATION
   Enterprise Risk Assessment (Pure Supabase Cloud)
   ========================================== */

// 1. SUPABASE INITIALIZATION
const supabaseUrl = 'https://haspklehikocqswmgmtk.supabase.co';
const supabaseKey = 'sb_publishable_O1qHjWdSJ1hZYraL8mmxYQ_CPRr0Sv6';

let supabaseClient = null;
function initSupabaseClient() {
    const lib = window.supabase;
    if (!lib?.createClient) {
        throw new Error('Supabase SDK failed to load. Check your network and refresh the page.');
    }
    return lib.createClient(supabaseUrl, supabaseKey, {
        auth: {
            persistSession: true,
            autoRefreshToken: true,
            detectSessionInUrl: true
        }
    });
}

try {
    supabaseClient = initSupabaseClient();
} catch (err) {
    console.error(err);
    document.addEventListener('DOMContentLoaded', () => {
        const el = document.getElementById('login-error');
        if (el) {
            el.textContent = err.message;
            el.hidden = false;
        }
    });
}

// Global Memory State
let globalAssets = [];
let globalControls = [];
let globalReport = {};
let globalLogs = [];
let editingId = null;
let currentUser = null;
let currentRole = null; // 'user' | 'infosec' | 'admin'
let currentProfile = null;
let pendingVerifyEmail = null;
let syncInFlight = null;
let currentAccessToken = null; // Captured on sign-in; used for direct REST calls.
const ASSET_STATUS = { DRAFT: 'Draft', PENDING: 'Pending Approval', APPROVED: 'Approved', REJECTED: 'Rejected' };

// ---------------------------------------------------------------
// Direct PostgREST fetch helper. Bypasses supabase-js's internal
// builder + lock machinery so a stuck SDK never blocks the UI.
// ---------------------------------------------------------------
async function directFetch(path, { method = 'GET', body, params, prefer, timeoutMs = 12000 } = {}) {
    if (!currentAccessToken) {
        throw new Error('Not signed in (no access token).');
    }
    const url = new URL(supabaseUrl + '/rest/v1/' + path);
    if (params) Object.entries(params).forEach(([k, v]) => v != null && url.searchParams.set(k, v));
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    let res;
    try {
        res = await fetch(url.toString(), {
            method,
            headers: {
                'apikey': supabaseKey,
                'Authorization': 'Bearer ' + currentAccessToken,
                'Content-Type': 'application/json',
                ...(prefer ? { 'Prefer': prefer } : {})
            },
            body: body ? JSON.stringify(body) : undefined,
            signal: ctrl.signal
        });
    } catch (err) {
        clearTimeout(timer);
        if (err?.name === 'AbortError') {
            throw new Error('Network timeout — Supabase did not respond within ' + (timeoutMs / 1000) + 's. Check your internet connection or Edge Tracking Prevention settings for *.supabase.co.');
        }
        throw err;
    }
    clearTimeout(timer);
    const text = await res.text();
    let data = null;
    if (text) { try { data = JSON.parse(text); } catch (_) { data = text; } }
    if (!res.ok) {
        const msg = (data && (data.message || data.hint || data.details)) || `HTTP ${res.status}`;
        const err = new Error(msg);
        err.status = res.status;
        err.body   = data;
        throw err;
    }
    return data;
}

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

/**
 * Per-control framework mapping (1–13) with SPECIFIC clause / subcategory IDs.
 * Sources:
 *   - NIST CSF 2.0 (Feb 2024) — subcategories within GV/ID/PR/DE/RS/RC functions.
 *   - ISO/IEC 27001:2022 Annex A + ISO/IEC 27002:2022 (93 controls reorganized
 *     into 4 themes: Organizational, People, Physical, Technological).
 *   - CIS Controls v8 (May 2021) — 18 controls and 153 safeguards.
 *   - SOC 2 / TSC 2017 (revised 2022) — Common Criteria CC1–CC9 + Availability,
 *     Confidentiality, Privacy, Processing Integrity supplemental criteria.
 *   - PCI-DSS v4.0 (Mar 2022) — applies when asset type = FA (Financial Asset).
 */
const CONTROL_COMPLIANCE = {
  1:  { name: 'Documented procedures',
        nist: ['GV.PO-01', 'GV.PO-02', 'ID.GV-01'],
        iso:  ['A.5.1', 'A.5.36', 'A.5.37'],
        cis:  ['14.1', '14.2'],
        soc2: ['CC1.1', 'CC2.2'],
        pci:  ['12.1'] },
  2:  { name: 'Segregation of duties',
        nist: ['GV.RR-02', 'PR.AA-05'],
        iso:  ['A.5.3', 'A.5.16'],
        cis:  ['6.8'],
        soc2: ['CC5.1', 'CC6.3'],
        pci:  ['7.2.4'] },
  3:  { name: 'Role-Based Access Control (RBAC)',
        nist: ['PR.AA-01', 'PR.AA-05'],
        iso:  ['A.5.15', 'A.5.18', 'A.8.2', 'A.8.3'],
        cis:  ['6.1', '6.2', '6.5', '6.6', '6.8'],
        soc2: ['CC6.1', 'CC6.2', 'CC6.3'],
        pci:  ['7.2', '7.3'] },
  4:  { name: 'Multi-Factor Authentication (MFA)',
        nist: ['PR.AA-03'],
        iso:  ['A.8.5'],
        cis:  ['6.3', '6.4', '6.5'],
        soc2: ['CC6.1'],
        pci:  ['8.4.2', '8.5.1'] },
  5:  { name: 'Physical controls (CCTV, Locks)',
        nist: ['PR.AA-06'],
        iso:  ['A.7.1', 'A.7.2', 'A.7.4', 'A.7.6'],
        cis:  ['1.1'],
        soc2: ['CC6.4'],
        pci:  ['9.1', '9.2', '9.3'] },
  6:  { name: 'Automated Information backup',
        nist: ['PR.DS-11', 'RC.RP-01'],
        iso:  ['A.8.13'],
        cis:  ['11.1', '11.2', '11.3', '11.4'],
        soc2: ['A1.2', 'CC9.1'],
        pci:  ['12.10.5'] },
  7:  { name: 'Encryption (At Rest / In Transit)',
        nist: ['PR.DS-01', 'PR.DS-02'],
        iso:  ['A.8.24'],
        cis:  ['3.10', '3.11'],
        soc2: ['CC6.1', 'CC6.7'],
        pci:  ['3.5', '3.6', '4.2'] },
  8:  { name: 'Asset disposal procedures',
        nist: ['PR.DS-10'],
        iso:  ['A.7.14', 'A.8.10'],
        cis:  ['3.5'],
        soc2: ['CC6.5'],
        pci:  ['3.2.1', '9.4.7'] },
  9:  { name: 'Endpoint Detection & Response (EDR)',
        nist: ['DE.CM-01', 'DE.CM-09', 'RS.MA-01'],
        iso:  ['A.8.7', 'A.8.16'],
        cis:  ['10.1', '10.2', '10.6', '13.1'],
        soc2: ['CC7.2', 'CC7.3'],
        pci:  ['5.2', '5.3', '11.5'] },
  10: { name: 'Network Firewall / WAF',
        nist: ['PR.IR-01', 'PR.PS-01'],
        iso:  ['A.8.20', 'A.8.21', 'A.8.22'],
        cis:  ['12.1', '12.2', '13.4'],
        soc2: ['CC6.1', 'CC6.6'],
        pci:  ['1.2', '1.3', '1.4'] },
  11: { name: 'Vulnerability Scanning & Patching',
        nist: ['ID.RA-01', 'PR.PS-02'],
        iso:  ['A.8.8'],
        cis:  ['7.1', '7.3', '7.4', '7.6'],
        soc2: ['CC7.1'],
        pci:  ['6.3.3', '11.3'] },
  12: { name: 'Network Segmentation (VLANs)',
        nist: ['PR.IR-02', 'PR.AA-05'],
        iso:  ['A.8.22'],
        cis:  ['12.2', '13.4'],
        soc2: ['CC6.6'],
        pci:  ['1.4.4', '11.4.5'] },
  13: { name: 'Incident Response Plan',
        nist: ['RS.MA-01', 'RS.MA-02', 'RC.RP-01', 'RC.RP-04'],
        iso:  ['A.5.24', 'A.5.25', 'A.5.26', 'A.5.27'],
        cis:  ['17.1', '17.2', '17.3', '17.4'],
        soc2: ['CC7.3', 'CC7.4', 'CC7.5'],
        pci:  ['12.10'] }
};

/**
 * Threat → relevant controls (defense-in-depth applicability).
 * NIST SP 800-30 Rev. 1 threat-source → mitigation mapping.
 * A control is "relevant" if its activation reduces probability or severity
 * for that threat source. Other controls remain checkable but offer no
 * mathematical reduction for this threat.
 */
const controlMap = {
    'phys_theft':           [1, 5, 7, 8],               // Procedures, Phys, Crypto, Disposal
    'phys_destruct':        [1, 5, 6, 12, 13],          // + DR plan, segmentation
    'hr_insider':           [1, 2, 3, 4, 9, 12],        // SoD, RBAC, MFA, EDR, Seg
    'hr_accidental':        [1, 3, 6, 13],              // Procedures, RBAC, Backup, IR
    'cyber_ext_ransomware': [1, 4, 6, 7, 9, 10, 11, 13],
    'cyber_ext_leak':       [1, 3, 4, 7, 9, 10, 12],
    'cyber_ext_ddos':       [10, 11, 12, 13],
    'cyber_ext_supply':     [1, 3, 4, 7, 10, 11, 13],
    'cyber_int_unauth':     [1, 2, 3, 4, 9, 13],
    'cyber_int_vuln':       [1, 9, 10, 11, 12],
    'legal_dpa':            [1, 3, 7, 8, 13]
};

/**
 * NIST SP 800-30 / ISO 27005-aligned weighting per control. Each weight
 * represents how much a fully-implemented instance of the control reduces
 * Probability vs. Severity for the threats it applies to. Weights are then
 * combined with diminishing returns and synergy bonuses in calculateRiskMath.
 */
const CONTROL_WEIGHTS = {
    1:  { p: 0.5, s: 0.3 },   // Documented procedures (governance)
    2:  { p: 0.6, s: 0.3 },   // Segregation of duties
    3:  { p: 0.9, s: 0.4 },   // RBAC
    4:  { p: 1.0, s: 0.4 },   // MFA — strongest preventive control vs. account takeover
    5:  { p: 0.7, s: 0.4 },   // Physical
    6:  { p: 0.0, s: 1.2 },   // Backup — pure recovery; reduces severity not probability
    7:  { p: 0.0, s: 1.4 },   // Encryption — limits impact even if breached
    8:  { p: 0.3, s: 0.5 },   // Disposal
    9:  { p: 0.6, s: 0.7 },   // EDR — early detection limits dwell time and impact
    10: { p: 0.9, s: 0.4 },   // Firewall / WAF
    11: { p: 0.9, s: 0.3 },   // Vulnerability mgmt
    12: { p: 0.7, s: 0.5 },   // Network segmentation
    13: { p: 0.0, s: 1.1 }    // IRP — recovery / containment
};

/**
 * Synergy bonuses — paired controls reinforce each other beyond simple sum.
 * Each entry: when ALL listed controls are active, add the bonus to the
 * cumulative reduction.
 */
const CONTROL_SYNERGIES = [
    { ids: [3, 4],     pBonus: 0.5, sBonus: 0.0, label: 'RBAC + MFA' },
    { ids: [6, 13],    pBonus: 0.0, sBonus: 0.5, label: 'Backup + IRP (BCP-DR)' },
    { ids: [9, 10],    pBonus: 0.4, sBonus: 0.0, label: 'EDR + Firewall (network defense in depth)' },
    { ids: [7, 12],    pBonus: 0.0, sBonus: 0.4, label: 'Encryption + Segmentation (zero-trust pattern)' },
    { ids: [11, 9, 13],pBonus: 0.3, sBonus: 0.3, label: 'Vuln Mgmt + EDR + IRP (NIST detect–respond loop)' }
];

/**
 * MANDATORY control sets — when ANY of these baselines is unmet, the system
 * floors the residual rating at 'Moderate' (or 'High' for PCI-DSS gaps) and
 * surfaces the missing controls with framework citations in the gap panel.
 */
const MANDATORY_CONTROLS = {
    // Asset-class minima (CIA score ≥ 8 → Restricted)
    restrictedClass:   { ids: [3, 4, 6, 7, 13], floor: 'Moderate',
        rationale: 'ISO 27001:2022 §A.5.10–A.5.15 + NIST CSF PR.AA + PR.DS require RBAC, MFA, Backup, Encryption and Incident Response for Restricted-class data.' },
    // Confidential class (score 6–7) — slightly relaxed
    confidentialClass: { ids: [3, 7, 13], floor: 'Moderate',
        rationale: 'ISO 27001:2022 §A.8.2 + NIST CSF PR.DS-01/02 require RBAC, Encryption and an Incident Response capability for Confidential data.' },
    // Financial Asset → PCI-DSS minimums
    fa:                { ids: [4, 7, 11, 12], floor: 'High',
        rationale: 'PCI-DSS v4.0 Req 3 (encrypt stored CHD), Req 4 (encrypt transmission), Req 8.4 (MFA), Req 11.3 (vuln scan) and Req 1.4.4 (segmentation) are mandatory for any asset that processes, stores or transmits cardholder data.' },
    // PII / SPI → Philippine DPA + GDPR equivalents
    pii:               { ids: [1, 3, 6, 7], floor: 'Moderate',
        rationale: 'RA 10173 (PH Data Privacy Act) §20 + ISO 27701 + GDPR Art. 32 require documented privacy procedures, access control, secure backup and encryption for PII / SPI processing.' },
    // Internet-facing assets → exposure baseline
    internetFacing:    { ids: [10, 11, 13], floor: 'Moderate',
        rationale: 'CIS Controls v8 §12 + §17 + NIST CSF PR.IR-01, DE.CM-01 require boundary defense (WAF), continuous vulnerability management and an Incident Response Plan for any Internet-exposed asset.' }
};

const RESIDUAL_FLOOR_RANK = { 'Very Low': 0, 'Low': 1, 'Moderate': 2, 'High': 3 };
const RESIDUAL_FLOOR_NAME = ['Very Low', 'Low', 'Moderate', 'High'];

/** Resolve which mandatory baselines apply to the current asset state. */
function getApplicableMandatorySets(ctx) {
    const sets = [];
    const ciaScore = (parseInt(ctx.c) || 0) + (parseInt(ctx.i) || 0) + (parseInt(ctx.a) || 0);
    if (ciaScore >= 8)            sets.push({ key: 'restrictedClass', ...MANDATORY_CONTROLS.restrictedClass });
    else if (ciaScore >= 6)       sets.push({ key: 'confidentialClass', ...MANDATORY_CONTROLS.confidentialClass });
    if (ctx.type === 'FA')        sets.push({ key: 'fa', ...MANDATORY_CONTROLS.fa });
    if (ctx.pii === 'Y' || ctx.spi === 'Y') sets.push({ key: 'pii', ...MANDATORY_CONTROLS.pii });
    if (ctx.environment === 'Internet Facing') sets.push({ key: 'internetFacing', ...MANDATORY_CONTROLS.internetFacing });
    return sets;
}

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
    'IA':  { pii: 'Y', spi: 'Y', corp: 'Y', c: 3, i: 3, a: 3 },
    'PhA': { pii: 'N', spi: 'N', corp: 'N', c: 1, i: 1, a: 2 },
    'PA':  { pii: 'Y', spi: 'N', corp: 'Y', c: 3, i: 2, a: 2 },
    'SA':  { pii: 'N', spi: 'N', corp: 'Y', c: 2, i: 3, a: 3 },
    'SV':  { pii: 'N', spi: 'N', corp: 'Y', c: 2, i: 2, a: 3 },
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
    
    // ---------------------------------------------------------
    // GUARDRAIL 1: STRICT CYBERSECURITY DATA & CIA LOCKS
    // ---------------------------------------------------------
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
                el.disabled = true; // Hardcoded completely
            }
        });

        // Special Rule: Internet Facing always forces Availability to 3
        const elA = document.getElementById('f-a');
        if (env === 'Internet Facing' && elA) {
            elA.value = '3';
        }

        if(lockC) lockC.textContent = '🔒 System Enforced';
        if(lockI) lockI.textContent = '🔒 System Enforced';
        if(lockA) lockA.textContent = (env === 'Internet Facing') ? '🔒 Env Driven' : '🔒 System Enforced';

    } else {
        // Unlock fields if no type is selected
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

    // ---------------------------------------------------------
    // GUARDRAIL 2: Threat Restrictions based on Asset Type
    // ---------------------------------------------------------
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

    // ---------------------------------------------------------
    // GUARDRAIL 3: Mistake-Proof Controls
    //
    // A control gets enabled if it is EITHER:
    //   (a) threat-relevant — defense-in-depth applicability per
    //       NIST SP 800-30 (controlMap), so it lowers P/S, OR
    //   (b) compliance-mandatory — required by an applicable baseline
    //       (Restricted/Confidential class, FA/PCI-DSS, PII, Internet
    //       Facing) so unchecking it floors residual risk.
    //
    // Previously only (a) was enabled, which made it impossible to
    // satisfy a mandatory baseline whose controls fell outside the
    // threat's relevant set (e.g. ddos threat + Restricted-class asset
    // disabled the very controls — RBAC/MFA/Backup/Encryption — that
    // the standards-based floor demands).
    // ---------------------------------------------------------
    const threat = g('f-risk-category');
    const relevantControls = new Set(controlMap[threat] || [1,2,3,4,5,6,7,8,9,10,11,12,13]);

    const mandatoryCtx = {
        type,
        c: parseInt(g('f-c')) || 0,
        i: parseInt(g('f-i')) || 0,
        a: parseInt(g('f-a')) || 0,
        pii: g('f-pii'),
        spi: g('f-spi'),
        environment: g('f-environment')
    };
    const mandatoryIds = new Set();
    getApplicableMandatorySets(mandatoryCtx).forEach(set => set.ids.forEach(id => mandatoryIds.add(id)));

    for (let i = 1; i <= 13; i++) {
        const cb = document.getElementById('ctrl' + i);
        const label = cb ? cb.parentElement : null;
        if (!cb || !label) continue;
        const isRelevant  = relevantControls.has(i);
        const isMandatory = mandatoryIds.has(i);
        // strip prior modifier classes
        label.classList.remove('ctrl-relevant', 'ctrl-mandatory', 'ctrl-both', 'ctrl-disabled');

        if (isRelevant && isMandatory) {
            cb.disabled = false;
            label.classList.add('ctrl-both');
            label.style.opacity = '1';
            label.style.textDecoration = 'none';
            label.style.cursor = 'pointer';
            label.title = 'Mitigates this threat AND required by a compliance baseline.';
        } else if (isRelevant) {
            cb.disabled = false;
            label.classList.add('ctrl-relevant');
            label.style.opacity = '1';
            label.style.textDecoration = 'none';
            label.style.cursor = 'pointer';
            label.title = 'Effective control for the selected threat (lowers Probability / Severity).';
        } else if (isMandatory) {
            // Compliance baseline overrides the threat-relevance restriction so
            // the user can actually satisfy the standards-based floor.
            cb.disabled = false;
            label.classList.add('ctrl-mandatory');
            label.style.opacity = '0.85';
            label.style.textDecoration = 'none';
            label.style.cursor = 'pointer';
            label.title = 'Not threat-relevant — does not reduce P/S for this threat — but REQUIRED to lift the compliance residual floor.';
        } else {
            cb.disabled = true;
            cb.checked = false;
            label.classList.add('ctrl-disabled');
            label.style.opacity = '0.3';
            label.style.textDecoration = 'line-through';
            label.style.cursor = 'not-allowed';
            label.title = 'Not relevant for the selected threat and not part of any active compliance baseline.';
        }
    }

    if (typeof updateTagsUI === "function") updateTagsUI();
    calculateRiskMath();
}

function calculateRiskMath() {
    let p = parseInt(g('f-prob')) || 3;
    let s = parseInt(g('f-sev')) || 3;
    const threat        = g('f-risk-category');
    const env           = g('f-environment');
    const currentPii    = g('f-pii');
    const currentSpi    = g('f-spi');
    const type          = g('f-type');
    const cVal          = parseInt(g('f-c')) || 0;
    const iVal          = parseInt(g('f-i')) || 0;
    const aVal          = parseInt(g('f-a')) || 0;
    const ciaScore      = cVal + iVal + aVal;

    // -----------------------------------------------------------
    // INHERENT-RISK ESCALATIONS (NIST SP 800-30 Rev.1 — adversarial
    // factors + ISO 27005 likelihood-impact adjustments)
    // -----------------------------------------------------------
    if (env === 'Internet Facing' && threat.startsWith('cyber_ext')) p = Math.min(5, p + 1);
    if ((currentPii === 'Y' || currentSpi === 'Y') && (threat === 'cyber_ext_leak' || threat === 'legal_dpa')) s = 5;
    // Restricted-class cyber/insider threats inherit max severity automatically.
    if (ciaScore >= 8 && (threat.startsWith('cyber_') || threat === 'hr_insider')) s = Math.max(s, 4);
    // PCI-DSS scoped assets always carry max severity for cyber threats (CHD breach is total loss).
    if (type === 'FA' && threat.startsWith('cyber_')) s = 5;
    // Internet-facing assets always face credible probability — never below 3 for cyber-external.
    if (env === 'Internet Facing' && threat.startsWith('cyber_ext')) p = Math.max(p, 3);

    const inherentRating = INHERIT[s + '-' + p] || 'Moderate';
    const probDisp = document.getElementById('f-prob-display');
    const sevDisp  = document.getElementById('f-sev-display');
    const probH    = document.getElementById('f-prob');
    const sevH     = document.getElementById('f-sev');
    if (probH)    probH.value = String(p);
    if (sevH)     sevH.value = String(s);
    if (probDisp) probDisp.value = String(p);
    if (sevDisp)  sevDisp.value = String(s);
    const rEl = document.getElementById('r-inherit');
    if (rEl) { rEl.textContent = inherentRating; rEl.style.color = riskColor(inherentRating); }

    // -----------------------------------------------------------
    // RESIDUAL REDUCTION (defense-in-depth, weighted, with diminishing
    // returns and synergy bonuses)
    // -----------------------------------------------------------
    const relevantSet = new Set(controlMap[threat] || [1,2,3,4,5,6,7,8,9,10,11,12,13]);
    const active = [];
    for (let i = 1; i <= 13; i++) {
        const cb = document.getElementById('ctrl' + i);
        if (cb && cb.checked && !cb.disabled) active.push(i);
    }
    const activeRelevant = active.filter(id => relevantSet.has(id));

    // Sum weighted reductions for relevant controls only.
    let pRedRaw = 0, sRedRaw = 0;
    activeRelevant.forEach(id => {
        const w = CONTROL_WEIGHTS[id] || { p: 0, s: 0 };
        pRedRaw += w.p;
        sRedRaw += w.s;
    });
    // Apply synergy bonuses where ALL ids of a synergy are active and relevant.
    const appliedSynergies = [];
    CONTROL_SYNERGIES.forEach(syn => {
        if (syn.ids.every(id => activeRelevant.includes(id))) {
            pRedRaw += syn.pBonus;
            sRedRaw += syn.sBonus;
            appliedSynergies.push(syn.label);
        }
    });
    // Diminishing returns: a single dimension can never drop more than (score − 1)
    // and the saturation curve plateaus around 70 % of the raw reduction once
    // beyond the score. This stops "10 controls = score of 1" gaming.
    const dimReturn = (raw, max) => {
        if (raw <= 0) return 0;
        const cap = Math.max(0, max - 1);
        // Saturating curve: r(x) = cap * (1 - exp(-x / k))   k tuned to 2.0
        const reduction = cap * (1 - Math.exp(-raw / 2.0));
        return Math.min(cap, reduction);
    };
    const pRed = dimReturn(pRedRaw, p);
    const sRed = dimReturn(sRedRaw, s);
    let resP = Math.max(1, Math.round(p - pRed));
    let resS = Math.max(1, Math.round(s - sRed));
    let residualRating = INHERIT[resS + '-' + resP] || 'Low';

    // -----------------------------------------------------------
    // MANDATORY-CONTROL FLOORS (cannot bypass minimum baselines)
    // -----------------------------------------------------------
    const mandatorySets = getApplicableMandatorySets({ type, c: cVal, i: iVal, a: aVal, pii: currentPii, spi: currentSpi, environment: env });
    const gaps = [];
    let highestFloor = 'Very Low';
    mandatorySets.forEach(set => {
        const missing = set.ids.filter(id => !active.includes(id));
        if (missing.length) {
            gaps.push({ key: set.key, missing, floor: set.floor, rationale: set.rationale });
            if (RESIDUAL_FLOOR_RANK[set.floor] > RESIDUAL_FLOOR_RANK[highestFloor]) {
                highestFloor = set.floor;
            }
        }
    });
    if (RESIDUAL_FLOOR_RANK[residualRating] < RESIDUAL_FLOOR_RANK[highestFloor]) {
        residualRating = highestFloor;
        // Reflect the floor on the residual P/S display so the math stays consistent.
        if (highestFloor === 'High')     { resP = Math.max(resP, 4); resS = Math.max(resS, 4); }
        else if (highestFloor === 'Moderate') { resP = Math.max(resP, 3); resS = Math.max(resS, 3); }
        else if (highestFloor === 'Low')      { resP = Math.max(resP, 2); resS = Math.max(resS, 2); }
    }

    const resEl = document.getElementById('r-residual');
    if (resEl) { resEl.textContent = residualRating; resEl.style.color = riskColor(residualRating); }
    const resProbDisp = document.getElementById('f-res-prob-display');
    const resSevDisp  = document.getElementById('f-res-sev-display');
    if (resProbDisp) resProbDisp.value = String(resP);
    if (resSevDisp)  resSevDisp.value = String(resS);

    const fbEl = document.getElementById('control-feedback');
    if (fbEl) {
        const synTxt = appliedSynergies.length ? ` · synergy: ${appliedSynergies.join(', ')}` : '';
        fbEl.textContent = `(${activeRelevant.length} of ${relevantSet.size} relevant mitigating controls applied${synTxt})`;
    }

    // -----------------------------------------------------------
    // RISK-APPETITE ENFORCEMENT (ISO 27001:2022 §6.1.3 d / §8.3 +
    // NIST RMF — risk acceptance authority by classification)
    // -----------------------------------------------------------
    const actTypeSelect = document.getElementById('f-action-type');
    const lockTreat     = document.getElementById('lock-treat');
    if (actTypeSelect) {
        // Reset the dropdown first.
        Array.from(actTypeSelect.options).forEach(opt => opt.disabled = false);
        let lockMsg = '';
        const optAccept = Array.from(actTypeSelect.options).find(o => o.value === 'Accept');

        if (residualRating === 'High') {
            if (optAccept) optAccept.disabled = true;
            if (actTypeSelect.value === 'Accept') actTypeSelect.value = 'Mitigate';
            lockMsg = 'Cannot Accept High residual (ISO 27001:2022 §6.1.3 — outside risk appetite)';
        } else if (type === 'FA' && residualRating !== 'Low' && residualRating !== 'Very Low') {
            if (optAccept) optAccept.disabled = true;
            if (actTypeSelect.value === 'Accept') actTypeSelect.value = 'Mitigate';
            lockMsg = 'PCI-DSS scoped (FA) — Accept blocked unless residual is Low';
        } else if (ciaScore >= 8 && residualRating === 'Moderate') {
            if (optAccept) optAccept.disabled = true;
            if (actTypeSelect.value === 'Accept') actTypeSelect.value = 'Mitigate';
            lockMsg = 'Restricted-class data — CISO sign-off needed; Accept blocked at Moderate';
        }
        if (lockTreat) lockTreat.textContent = lockMsg ? '🔒 ' + lockMsg : '';
    }

    const apSection = document.getElementById('action-plan-section');
    if (apSection && actTypeSelect) {
        apSection.style.display = (actTypeSelect.value === 'Accept' || residualRating === 'Very Low') ? 'none' : 'block';
    }

    renderComplianceMapping();
    renderControlGapAnalysis(gaps);
}

function applyRiskTemplate(skipEngineUpdate = false) {
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
        
        if(!skipEngineUpdate) notify("Risk template applied.");
    }
    if(!skipEngineUpdate) runEnforcementEngine();
}

function riskColor(r) { return { 'Very Low': 'var(--success)', 'Low': 'var(--accent2)', 'Moderate': 'var(--warn)', 'High': 'var(--danger)' }[r] || 'var(--text)'; }
function riskBadge(r) { const cls = { 'Very Low': 'badge-vl', 'Low': 'badge-lo', 'Moderate': 'badge-mo', 'High': 'badge-hi' }[r] || 'badge-lo'; return `<span class="badge ${cls}">${r||'—'}</span>`; }

// ==========================================
// 4. AUTH, RBAC & SUPABASE SYNC
// ==========================================

function resolveRoleFromEmail(email) {
    const e = (email || '').toLowerCase();
    if (e.includes('admin') || e.includes('ciso')) return 'admin';
    if (e.includes('infosec') || e.includes('security')) return 'infosec';
    return 'user';
}

function effectiveRole(profile) {
    if (!profile) return null;
    if (profile.account_status === 'active' && profile.approved_role) return profile.approved_role;
    return profile.requested_role || 'user';
}

function getActiveControlIds(assetId) {
    if (assetId) return globalControls.filter(c => c.asset_id === assetId).map(c => c.ctrl_id);
    const ids = [];
    for (let i = 1; i <= 13; i++) {
        const cb = document.getElementById('ctrl' + i);
        if (cb && cb.checked && !cb.disabled) ids.push(i);
    }
    return ids;
}

function getFrameworksForControls(ctrlIds, assetType) {
    const nist = new Set(), iso = new Set(), cis = new Set(), soc2 = new Set(), pci = new Set();
    ctrlIds.forEach(id => {
        const m = CONTROL_COMPLIANCE[id];
        if (!m) return;
        (m.nist || []).forEach(v => nist.add(v));
        (m.iso  || []).forEach(v => iso.add(v));
        (m.cis  || []).forEach(v => cis.add(v));
        (m.soc2 || []).forEach(v => soc2.add(v));
        if (assetType === 'FA') (m.pci || []).forEach(v => pci.add(v));
    });
    const sortIds = arr => arr.sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));
    return {
        nist: sortIds([...nist]).join(', ') || '—',
        iso: [...iso].join('; ') || '—',
        cis: [...cis].join('; ') || '—',
        soc2: [...soc2].join('; ') || '—',
        pci: assetType === 'FA' ? ([...pci].join('; ') || '—') : 'N/A (non-FA)'
    };
}

function renderComplianceMapping() {
    const panel = document.getElementById('compliance-mapping-panel');
    const tags = document.getElementById('compliance-tags');
    if (!panel || !tags) return;
    const show = currentRole === 'infosec' || currentRole === 'admin';
    panel.classList.toggle('hidden', !show);
    if (!show) return;
    const type = g('f-type');
    const fw = getFrameworksForControls(getActiveControlIds(), type);
    const items = [
        ['NIST CSF 2.0', fw.nist],
        ['ISO 27001:2022 / 27002', fw.iso],
        ['CIS Controls v8', fw.cis],
        ['SOC 2 (TSC)', fw.soc2],
        ['PCI-DSS v4.0', fw.pci]
    ];
    tags.innerHTML = items.map(([label, val]) =>
        `<span class="compliance-tag"><strong>${label}</strong> ${escapeHtmlSafe(val)}</span>`
    ).join('');
}

/**
 * Renders missing-mandatory-control panel under the controls section.
 * Each gap is annotated with the framework rationale (ISO / NIST / PCI / DPA)
 * so Info Sec sees exactly WHY a baseline is required, not just THAT it is.
 */
function renderControlGapAnalysis(gaps) {
    let panel = document.getElementById('control-gap-panel');
    if (!panel) {
        const compEl = document.getElementById('compliance-mapping-panel');
        if (!compEl || !compEl.parentNode) return;
        panel = document.createElement('div');
        panel.id = 'control-gap-panel';
        panel.className = 'compliance-panel control-gap-panel hidden';
        compEl.parentNode.insertBefore(panel, compEl);
    }
    const showRole = currentRole === 'infosec' || currentRole === 'admin';
    if (!showRole || !gaps || !gaps.length) {
        panel.classList.add('hidden');
        panel.innerHTML = '';
        return;
    }
    const labelByKey = {
        restrictedClass:   'Restricted Classification (CIA ≥ 8)',
        confidentialClass: 'Confidential Classification (CIA 6–7)',
        fa:                'PCI-DSS Scope (Financial Asset)',
        pii:               'Personal / Sensitive PI (RA 10173 DPA + GDPR)',
        internetFacing:    'Internet-Facing Exposure'
    };
    const fwLabel = { nist: 'NIST', iso: 'ISO 27001', cis: 'CIS', soc2: 'SOC 2', pci: 'PCI-DSS' };
    const html = gaps.map(g => {
        const ctrls = g.missing.map(id => {
            const cm = CONTROL_COMPLIANCE[id] || { name: 'Control ' + id };
            const fws = ['nist','iso','cis','soc2','pci']
                .filter(k => Array.isArray(cm[k]) && cm[k].length)
                .map(k => `<span class="gap-fw"><em>${fwLabel[k]}:</em> ${escapeHtmlSafe(cm[k].join(', '))}</span>`)
                .join('');
            return `<li><strong>C${id} — ${escapeHtmlSafe(cm.name || 'Control ' + id)}</strong>${fws ? `<div class="gap-fw-row">${fws}</div>` : ''}</li>`;
        }).join('');
        return `
          <div class="gap-block gap-floor-${g.floor.toLowerCase().replace(/\s/g,'-')}">
            <div class="gap-head">
              <span class="gap-label">${escapeHtmlSafe(labelByKey[g.key] || g.key)}</span>
              <span class="gap-floor">Residual floor: <strong>${escapeHtmlSafe(g.floor)}</strong></span>
            </div>
            <div class="gap-rationale">${escapeHtmlSafe(g.rationale)}</div>
            <ul class="gap-list">${ctrls}</ul>
          </div>`;
    }).join('');
    panel.innerHTML = `
      <label style="margin-top:16px;display:block;color:var(--danger);">⚠ Mandatory Control Gaps</label>
      <div class="gap-summary">Tick the controls below to lift the standards-based residual floor. Controls flagged <span class="ctrl-mandatory-pill">Compliance baseline</span> in the picker do NOT reduce P/S for the chosen threat — they exist solely to satisfy the framework requirement above. Until every gap closes, residual cannot drop below the indicated rating.</div>
      ${html}`;
    panel.classList.remove('hidden');
}

// Lightweight HTML escaper used by panels above (separate from export-side
// escapeHtml — that one is defined later in the file but only on export).
function escapeHtmlSafe(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function roleLabel(role) {
    return { user: 'Standard User', infosec: 'Info Sec', admin: 'Admin (CISO)' }[role] || role;
}

function showAuthScreen() {
    document.getElementById('auth-screen')?.classList.remove('hidden');
    document.getElementById('app-shell')?.classList.add('hidden');
    const trig = document.getElementById('notif-trigger');
    if (trig) trig.style.display = 'none';
    document.getElementById('notif-dropdown')?.classList.add('hidden');
    resetAuthSteps();
    // Lazily boot the background wave animation the first time we land here.
    initAuthWave();
}

function resetAuthSteps() {
    // Reset back to the role-selector stage (Stage 1)
    const stageRoles = document.getElementById('auth-stage-roles');
    const stageForm  = document.getElementById('auth-stage-form');
    const page       = document.getElementById('auth-page');
    if (page) page.classList.remove('out');
    if (stageRoles) stageRoles.classList.remove('hidden');
    if (stageForm)  stageForm.classList.add('hidden');

    // Reset inner form sub-steps to the credentials view
    document.getElementById('auth-step-credentials')?.classList.remove('hidden');
    document.getElementById('auth-step-verify')?.classList.add('hidden');
    document.getElementById('auth-step-pending')?.classList.add('hidden');
    showAuthTab('login');

    // Clear any stale error message
    clearAuthError();
    // Forget any half-typed password from the previous attempt
    const pw  = document.getElementById('login-password');
    const pw1 = document.getElementById('register-password');
    const pw2 = document.getElementById('register-password2');
    if (pw)  pw.value  = '';
    if (pw1) pw1.value = '';
    if (pw2) pw2.value = '';
}

function clearAuthError() {
    ['login-error', 'register-error'].forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.hidden = true; el.textContent = ''; }
    });
}

function showAuthError(text, opts = {}) {
    // Show on whichever tab is currently active; default to login-error.
    const onRegister = !document.getElementById('register-form')?.classList.contains('hidden');
    const elId = (opts.target === 'register' || (opts.target == null && onRegister))
        ? 'register-error' : 'login-error';
    const el = document.getElementById(elId);
    if (!el) return;
    el.textContent = text;
    el.hidden = false;
    // Re-trigger the shake animation
    el.style.animation = 'none';
    void el.offsetWidth;
    el.style.animation = '';
}

/* -----------------------------------------------------------
   Role selector → form transition (Stage 1 ↔ Stage 2)
   ----------------------------------------------------------- */
const AUTH_ROLE_LABELS = { user: 'Standard User', infosec: 'Info Sec', admin: 'Admin (CISO)' };

function _createAuthRipple(el, ev) {
    const rect = el.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const x = (ev?.clientX ?? rect.left + rect.width / 2) - rect.left;
    const y = (ev?.clientY ?? rect.top  + rect.height / 2) - rect.top;
    const ripple = document.createElement('span');
    ripple.className = 'ripple';
    ripple.style.cssText =
        `width:${size}px;height:${size}px;left:${x - size/2}px;top:${y - size/2}px;`;
    el.appendChild(ripple);
    setTimeout(() => ripple.remove(), 520);
}

function setAuthRole(role) {
    const safeRole = ['user', 'infosec', 'admin'].includes(role) ? role : 'user';
    const loginRoleEl = document.getElementById('login-role');
    const regRoleEl   = document.getElementById('register-role');
    if (loginRoleEl) loginRoleEl.value = safeRole;
    if (regRoleEl)   regRoleEl.value   = safeRole;
    const label = document.getElementById('auth-role-pill-label');
    if (label) label.textContent = AUTH_ROLE_LABELS[safeRole] || safeRole;
}

function selectAuthRole(el, role, ev) {
    if (ev) _createAuthRipple(el, ev);
    // Visually highlight the chosen card while the transition plays
    document.querySelectorAll('#auth-screen .auth-role-btn').forEach(b => {
        b.style.opacity = (b === el) ? '1' : '0.35';
        if (b !== el) b.style.transform = 'translateY(0)';
    });
    el.style.borderColor = 'rgba(200,255,0,0.55)';

    setAuthRole(role);
    clearAuthError();

    setTimeout(() => {
        const stageRoles = document.getElementById('auth-stage-roles');
        const stageForm  = document.getElementById('auth-stage-form');
        if (stageRoles) stageRoles.classList.add('hidden');
        if (stageForm)  stageForm.classList.remove('hidden');
        // Reset the cards for next time
        document.querySelectorAll('#auth-screen .auth-role-btn').forEach(b => {
            b.style.opacity = '';
            b.style.borderColor = '';
        });
        // Focus first input for keyboard users
        showAuthTab('login');
        document.getElementById('login-email')?.focus();
    }, 320);
}
window.selectAuthRole = selectAuthRole;

function backToRoleSelect() {
    clearAuthError();
    const stageRoles = document.getElementById('auth-stage-roles');
    const stageForm  = document.getElementById('auth-stage-form');
    if (stageRoles) stageRoles.classList.remove('hidden');
    if (stageForm)  stageForm.classList.add('hidden');
    // Reset any sub-step (verify/pending) so a returning user lands on creds next time
    document.getElementById('auth-step-credentials')?.classList.remove('hidden');
    document.getElementById('auth-step-verify')?.classList.add('hidden');
    document.getElementById('auth-step-pending')?.classList.add('hidden');
}
window.backToRoleSelect = backToRoleSelect;

/* -----------------------------------------------------------
   Background wave canvas — runs only while the auth screen is visible
   ----------------------------------------------------------- */
let _authWaveInited = false;
function initAuthWave() {
    if (_authWaveInited) return;
    const canvas = document.getElementById('auth-wave-canvas');
    if (!canvas || !canvas.getContext) return;
    _authWaveInited = true;
    const ctx = canvas.getContext('2d');
    let W = 0, H = 0, t = 0;

    function resize() {
        W = canvas.width  = window.innerWidth;
        H = canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    const waves = [
        { amp: 90,  freq: 0.0028, speed:  0.008, yBase: 0.40, color: 'rgba(200,255,0,0.28)', lw: 1.6 },
        { amp: 70,  freq: 0.0035, speed: -0.010, yBase: 0.55, color: 'rgba(200,255,0,0.18)', lw: 1.1 },
        { amp: 110, freq: 0.0022, speed:  0.006, yBase: 0.68, color: 'rgba(200,255,0,0.10)', lw: 0.8 }
    ];

    function authScreenVisible() {
        const s = document.getElementById('auth-screen');
        return s && !s.classList.contains('hidden');
    }

    function frame() {
        if (authScreenVisible()) {
            ctx.clearRect(0, 0, W, H);
            for (const w of waves) {
                ctx.beginPath();
                ctx.strokeStyle = w.color;
                ctx.lineWidth = w.lw;
                for (let x = 0; x <= W; x += 2) {
                    const y = H * w.yBase + Math.sin(x * w.freq + t * w.speed * 60) * w.amp;
                    if (x === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
                }
                ctx.stroke();
            }
            t += 0.016;
        }
        requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
}

function showVerificationStep(email) {
    pendingVerifyEmail = email;
    // Make sure we are on Stage 2 (the form card hosts the verify sub-step)
    document.getElementById('auth-stage-roles')?.classList.add('hidden');
    document.getElementById('auth-stage-form')?.classList.remove('hidden');
    document.getElementById('auth-step-credentials')?.classList.add('hidden');
    document.getElementById('auth-step-verify')?.classList.remove('hidden');
    document.getElementById('auth-step-pending')?.classList.add('hidden');
    const target = document.getElementById('verify-email-target');
    if (target) target.textContent = email;
}

async function resendVerificationEmail() {
    if (!supabaseClient || !pendingVerifyEmail) return notify('Enter your email and register again.', true);
    try {
        const { error } = await supabaseClient.auth.resend({ type: 'signup', email: pendingVerifyEmail });
        if (error) throw error;
        notify('Verification email resent.');
    } catch (err) {
        notify(formatAuthError(err), true);
    }
}

function showAuthTab(tab) {
    const loginForm = document.getElementById('login-form');
    const regForm = document.getElementById('register-form');
    document.getElementById('tab-login')?.classList.toggle('active', tab === 'login');
    document.getElementById('tab-register')?.classList.toggle('active', tab === 'register');
    loginForm?.classList.toggle('hidden', tab !== 'login');
    regForm?.classList.toggle('hidden', tab !== 'register');
    // Clear both error banners when switching tabs so the user sees a clean slate.
    clearAuthError();
}

function showPendingApproval(profile) {
    // Make sure we are on Stage 2 so the pending sub-step is visible
    document.getElementById('auth-stage-roles')?.classList.add('hidden');
    document.getElementById('auth-stage-form')?.classList.remove('hidden');
    document.getElementById('auth-step-credentials')?.classList.add('hidden');
    document.getElementById('auth-step-verify')?.classList.add('hidden');
    document.getElementById('auth-step-pending')?.classList.remove('hidden');
    const msg = document.getElementById('pending-approval-msg');
    const who = profile.requested_role === 'infosec' ? 'an Admin (CISO)' : 'Info Sec or Admin';
    if (msg) msg.textContent = `Your ${roleLabel(profile.requested_role)} account (${profile.email}) is pending approval by ${who}.`;
}

async function loadUserProfile(userId) {
    const { data, error } = await supabaseClient.from('user_profiles').select('*').eq('id', userId).maybeSingle();
    if (error) throw error;
    return data;
}

function showAppShell() {
    document.getElementById('auth-screen')?.classList.add('hidden');
    document.getElementById('app-shell')?.classList.remove('hidden');
    const trig = document.getElementById('notif-trigger');
    if (trig) trig.style.display = '';
}

function formatAuthError(err) {
    const msg = err?.message || String(err);
    if (/invalid login credentials/i.test(msg)) {
        return 'Invalid email or password. If you are using the demo accounts (user@plm.edu.ph / infosec@plm.edu.ph), make sure you have run supabase/hotfix_demo_accounts.sql in the Supabase SQL editor.';
    }
    if (/email not confirmed/i.test(msg)) {
        return 'Email not yet verified. Click the link Supabase sent to your inbox, then sign in again.';
    }
    if (/signup is disabled/i.test(msg)) {
        return 'Sign-up is disabled in Supabase. Enable Email provider under Authentication → Providers.';
    }
    if (/user already registered/i.test(msg)) {
        return 'An account already exists for this email. Try signing in or resend verification.';
    }
    if (/rate limit/i.test(msg)) {
        return 'Email rate limit hit. Wait a minute and try again.';
    }
    return msg;
}

async function handleRegister(event) {
    event.preventDefault();
    if (!supabaseClient) return notify('Supabase is not initialized.', true);
    const email = document.getElementById('register-email')?.value?.trim();
    const password = document.getElementById('register-password')?.value;
    const password2 = document.getElementById('register-password2')?.value;
    const role = document.getElementById('register-role')?.value || 'user';
    clearAuthError();
    if (!email || !password) {
        showAuthError('Please fill in every field before creating an account.', { target: 'register' });
        return;
    }
    if (password.length < 8) {
        showAuthError('Password must be at least 8 characters.', { target: 'register' });
        return;
    }
    if (password !== password2) {
        showAuthError('Passwords do not match.', { target: 'register' });
        return;
    }
    const btn = document.getElementById('register-btn');
    const originalLabel = btn ? btn.innerHTML : '';
    if (btn) { btn.disabled = true; btn.innerHTML = 'Creating account…'; }
    try {
        const { error } = await supabaseClient.auth.signUp({
            email,
            password,
            options: {
                data: { requested_role: role },
                emailRedirectTo: window.location.origin + window.location.pathname
            }
        });
        if (error) throw error;
        // Real Supabase email verification — user_profiles row will be inserted by
        // the on_auth_user_confirmed trigger only after the email is verified.
        showVerificationStep(email);
        notify('Verification email sent. Click the link in your inbox.');
    } catch (err) {
        showAuthError(formatAuthError(err), { target: 'register' });
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = originalLabel || 'Create Account <span aria-hidden="true">→</span>'; }
    }
}

async function handleLogin(event) {
    event.preventDefault();
    if (!supabaseClient) return notify('Supabase is not initialized. Refresh the page.', true);
    const email = document.getElementById('login-email')?.value?.trim();
    const password = document.getElementById('login-password')?.value;
    const selectedRole = document.getElementById('login-role')?.value || 'user';
    const btn = document.getElementById('login-btn');
    const originalLabel = btn ? btn.innerHTML : '';
    clearAuthError();
    if (!email || !password) {
        showAuthError('Enter your email and password to sign in.', { target: 'login' });
        return;
    }
    if (btn) { btn.disabled = true; btn.innerHTML = 'Authenticating…'; }
    try {
        const { data, error } = await supabaseClient.auth.signInWithPassword({ email, password });
        if (error) {
            // Supabase returns "Email not confirmed" — surface the verify step
            if (/email not confirmed/i.test(error.message || '')) {
                showVerificationStep(email);
            }
            throw error;
        }
        if (!data?.session) throw new Error('No session returned.');
        // enterAuthenticatedApp will either move us into the app shell OR keep
        // us on the auth screen with the appropriate error/pending message.
        await enterAuthenticatedApp(data.session, selectedRole);
    } catch (err) {
        const text = formatAuthError(err);
        showAuthError(text, { target: 'login' });
        notify(text, true);
        // Belt-and-suspenders: if anything went wrong, make sure we are NOT
        // showing the app shell. The error stays visible until next attempt.
        document.getElementById('app-shell')?.classList.add('hidden');
        document.getElementById('auth-screen')?.classList.remove('hidden');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalLabel || 'Authenticate <span aria-hidden="true">→</span>';
        }
    }
}

function handleLogout() {
    // Reset client state and flip the UI FIRST so the user is never trapped
    // waiting on the Supabase round-trip (which can hang on slow networks).
    currentUser = null;
    currentRole = null;
    currentProfile = null;
    currentAccessToken = null;
    pendingVerifyEmail = null;
    authUiReady = false;
    showAuthScreen();
    notify('Signed out.');
    // Best-effort revoke the cloud session in the background; ignore errors.
    if (supabaseClient) {
        try {
            supabaseClient.auth.signOut().catch(err => console.warn('signOut warning:', err));
        } catch (err) {
            console.warn('signOut threw:', err);
        }
    }
}

// Wipe any zombie Supabase token from a previously broken session and reload
// the page so the auth state machine starts clean.
function forceResetSession() {
    try {
        // Best-effort SDK signOut — don't await it.
        if (supabaseClient) supabaseClient.auth.signOut().catch(() => {});
    } catch (_) { /* noop */ }
    try {
        // Remove any keys Supabase JS may have left behind.
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            if (k && (k.startsWith('sb-') || k.startsWith('supabase.'))) keys.push(k);
        }
        keys.forEach(k => localStorage.removeItem(k));
        sessionStorage.clear();
    } catch (e) { console.warn('Storage clear failed:', e); }
    // Drop our app caches too so notifications don't replay.
    try { localStorage.removeItem('impactlens.notif.lastSeen'); } catch (_) {}
    location.reload();
}
window.forceResetSession = forceResetSession;

let authUiReady = false;
// Tells the global onAuthStateChange listener to skip its reset cycle when
// we intentionally trigger a signOut and want to keep the current error banner.
let suppressAuthReset = false;

async function enterAuthenticatedApp(session, requestedRole = null) {
    if (!session?.user) return;
    currentUser = session.user;
    currentAccessToken = session.access_token || null;
    // The trigger creates user_profiles on email confirmation. If we somehow get
    // here without a row, treat the account as pending until the DB catches up.
    currentProfile = await loadUserProfile(currentUser.id);
    if (!currentProfile) {
        showAuthScreen();
        showPendingApproval({ email: currentUser.email, requested_role: requestedRole || 'user' });
        return;
    }
    if (currentProfile.account_status !== 'active') {
        showAuthScreen();
        showPendingApproval(currentProfile);
        return;
    }
    if (requestedRole && currentProfile.approved_role !== requestedRole) {
        // Right credentials, wrong role — refuse entry, clear local session, and
        // surface the mismatch on the auth screen. NEVER fall through to the app shell.
        const approved = roleLabel(currentProfile.approved_role);
        const tried   = roleLabel(requestedRole);
        const text = `Access denied. These credentials are approved as "${approved}", not "${tried}". Pick the correct role and try again.`;
        // Tell the auth-state listener to skip its reset, otherwise the
        // SIGNED_OUT event would wipe the error we are about to display.
        suppressAuthReset = true;
        try { await supabaseClient.auth.signOut(); } catch (_) { /* noop */ }
        currentUser = null;
        currentRole = null;
        currentProfile = null;
        currentAccessToken = null;
        authUiReady = false;
        document.getElementById('app-shell')?.classList.add('hidden');
        document.getElementById('auth-screen')?.classList.remove('hidden');
        backToRoleSelect();
        showAuthError(text, { target: 'login' });
        notify(text, true);
        // Re-arm the listener after the SIGNED_OUT event has had a chance to fire.
        setTimeout(() => { suppressAuthReset = false; }, 800);
        return;
    }
    currentRole = currentProfile.approved_role;
    showAppShell();
    const roleEl = document.getElementById('hdr-role');
    const userEl = document.getElementById('hdr-user');
    if (roleEl) roleEl.textContent = roleLabel(currentRole);
    if (userEl) userEl.textContent = currentUser.email || '—';
    applyRoleUI();
    const landing = { user: 'add', infosec: 'draft-queue', admin: 'dashboard' }[currentRole] || 'add';
    showSection(landing);
    try {
        await syncFromCloud(true);
        await seedSupabaseIfEmpty();
        updateWorkflowBadges();
        renderSectionContent(document.querySelector('.section.active')?.id?.replace('sec-', '') || landing);
    } catch (err) {
        console.error('Post-login data sync:', err);
        notify('Signed in, but some data failed to load. Run supabase/master_setup.sql.', true);
    }
    authUiReady = true;
}

function applyRoleUI() {
    document.body.dataset.role = currentRole || '';
    document.querySelectorAll('.nav-admin-only, .nav-infosec-only, .nav-user-only, .nav-admin-users').forEach(el => {
        el.style.display = 'none';
    });
    document.querySelectorAll('.nav-export-only').forEach(el => el.classList.add('hidden'));
    if (currentRole === 'admin') {
        document.querySelectorAll('.nav-admin-only, .nav-admin-users').forEach(el => { el.style.display = ''; });
        document.querySelectorAll('.nav-export-only').forEach(el => el.classList.remove('hidden'));
    } else if (currentRole === 'infosec') {
        document.querySelectorAll('.nav-infosec-only, .nav-user-only, .nav-admin-users').forEach(el => { el.style.display = ''; });
        document.querySelectorAll('.nav-export-only').forEach(el => el.classList.remove('hidden'));
    } else {
        document.querySelectorAll('.nav-user-only').forEach(el => { el.style.display = ''; });
    }
    setFormSectionsLocked(currentRole === 'user');
    lockSystemDerivedRiskFields(currentRole !== 'user');
    const saveBtn = document.getElementById('btn-save-asset');
    if (saveBtn) {
        if (currentRole === 'user') saveBtn.textContent = 'Submit Draft →';
        else if (currentRole === 'infosec') saveBtn.textContent = 'Submit for Approval →';
        else saveBtn.textContent = 'Save Asset →';
    }
}

function setFormSectionsLocked(locked) {
    document.querySelectorAll('.role-locked-section').forEach(el => {
        el.classList.toggle('section-hidden', locked);
    });
}

function lockSystemDerivedRiskFields(lock) {
    ['f-prob-display', 'f-sev-display', 'f-res-prob-display', 'f-res-sev-display'].forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.readOnly = true; el.title = lock ? 'System Derived — cannot edit' : ''; }
    });
}

function assetsForCurrentRole(list = globalAssets) {
    if (currentRole === 'infosec') {
        return list.filter(a => a.status === ASSET_STATUS.DRAFT);
    }
    if (currentRole === 'admin') {
        return list.filter(a => a.status === ASSET_STATUS.APPROVED || a.status === ASSET_STATUS.PENDING);
    }
    return list;
}

function approvedAssetsOnly(list = globalAssets) {
    return list.filter(a => (a.status || ASSET_STATUS.APPROVED) === ASSET_STATUS.APPROVED);
}

async function logSystemEvent(action, details = '', assetId = null) {
    if (!currentUser) return;
    const row = {
        user_email: currentUser.email,
        user_role: currentRole,
        action,
        details,
        asset_id: assetId
    };
    try {
        await supabaseClient.from('SystemLogs').insert(row);
    } catch (e) { console.warn('SystemLogs insert:', e); }
    globalLogs.unshift({ ...row, created_at: new Date().toISOString() });
    if (globalLogs.length > 200) globalLogs.length = 200;
}

async function syncFromCloud(silent = false) {
    if (!supabaseClient) return;
    try {
        const { data: aData, error: aErr } = await supabaseClient.from('Assets').select('*');
        if (aErr) throw aErr;
        globalAssets = (aData || []).map(a => ({ ...a, status: a.status || ASSET_STATUS.APPROVED }));

        const { data: cData, error: cErr } = await supabaseClient.from('AssetControls').select('*');
        if (cErr) throw cErr;
        globalControls = cData || [];

        const { data: rData } = await supabaseClient.from('ReportData').select('*').eq('id', 1).single();
        globalReport = rData || {};

        const { data: lData } = await supabaseClient.from('SystemLogs').select('*').order('created_at', { ascending: false }).limit(200);
        globalLogs = lData || globalLogs;
        renderNotificationBadge();
    } catch (err) {
        console.error('Cloud Sync Error: ', err);
        const msg = err?.message || String(err);
        const hint = /relation.*does not exist|schema cache/i.test(msg)
            ? ' Database tables missing — run supabase/master_setup.sql in the Supabase SQL Editor.'
            : '';
        if (!silent) notify('Failed to connect to Supabase DB.' + hint, true);
    }
}

function refreshCloudInBackground() {
    if (syncInFlight) return syncInFlight;
    syncInFlight = syncFromCloud(true).finally(() => { syncInFlight = null; });
    return syncInFlight;
}

function updateWorkflowBadges() {
    const drafts = globalAssets.filter(a => a.status === ASSET_STATUS.DRAFT).length;
    const pending = globalAssets.filter(a => a.status === ASSET_STATUS.PENDING).length;
    const nd = document.getElementById('nav-drafts');
    const np = document.getElementById('nav-pending');
    if (nd) nd.textContent = drafts;
    if (np) np.textContent = pending;
}

async function seedSupabaseIfEmpty() {
    try {
        const { data, error } = await supabaseClient.from('Assets').select('id').limit(1);
        if (error) {
            console.error('Seed check failed:', error);
            if (/relation.*does not exist/i.test(error.message || '')) {
                notify('Run supabase/master_setup.sql in the Supabase SQL Editor.', true);
            }
            return;
        }
        if (data.length === 0) {
            notify('Database is empty. Re-run supabase/master_setup.sql to seed 57 PLM assets.', true);
        }
    } catch (e) { console.error('Seed check:', e); }
}

function renderSectionContent(name) {
  if (name === 'register') renderRegister();
  if (name === 'dashboard') renderDashboard();
  if (name === 'controls') renderControls();
  if (name === 'actions') renderActions();
  if (name === 'report') loadReportDataToUI();
  if (name === 'risk') { renderRiskRegister(); updateMatrixHeatmap(); }
  if (name === 'draft-queue') renderDraftQueue();
  if (name === 'pending-queue') renderPendingQueue();
  if (name === 'logs') renderSystemLogs();
  if (name === 'users') renderUserManagement();
  updateWorkflowBadges();
}

function showSection(name) {
  const allowed = {
    user: ['add', 'guidelines'],
    infosec: ['dashboard', 'add', 'draft-queue', 'pending-queue', 'register', 'risk', 'controls', 'actions', 'logs', 'users', 'guidelines'],
    admin: ['dashboard', 'add', 'draft-queue', 'pending-queue', 'register', 'risk', 'controls', 'actions', 'report', 'users', 'logs', 'guidelines']
  };
  if (currentRole && allowed[currentRole] && !allowed[currentRole].includes(name)) {
    notify('You do not have access to that section.', true);
    return;
  }

  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const sec = document.getElementById('sec-' + name);
  if (sec) sec.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n => {
    if (n.dataset.section === name) n.classList.add('active');
  });

  renderSectionContent(name);
  refreshCloudInBackground().then(() => renderSectionContent(name));
}

function notify(msg, isErr=false) {
  const el = document.getElementById('notification');
  if(!el) return;
  el.textContent = (isErr ? '⚠ ' : '✓ ') + msg; 
  el.className = 'notification' + (isErr ? ' error' : '') + ' show';
  setTimeout(() => el.classList.remove('show'), 3000);
}

// =====================================================================
// REASON-CAPTURE MODAL (used by Reject / Delete actions across roles)
// =====================================================================
// Standardised reason presets per action. Picking one of these counts as
// "generated"; the user can also (or instead) write a free-text "essay".
const REASON_PRESETS = {
  rejectAssetPending: [
    'Insufficient or weak controls — does not meet ISO 27001 Annex A baseline',
    'CIA values misaligned with asset profile (NIST SP 800-60 mismatch)',
    'Risk classification needs review — inherent escalation not justified',
    'Action plan unrealistic, missing owner, or beyond remediation window',
    'Compliance gap — PCI-DSS / RA 10173 / SOC 2 control still missing',
    'Duplicate of an existing approved asset',
    'Other (see notes)',
  ],
  rejectAssetDraft: [
    'Submission incomplete or missing required information',
    'Not a valid in-scope ISMS asset',
    'Duplicate of an existing draft or approved asset',
    'Asset profile mis-classified (wrong type / department)',
    'Sensitive data handling instructions not followed',
    'Other (see notes)',
  ],
  deleteAsset: [
    'Asset decommissioned or retired',
    'Out of scope for the ISMS register',
    'Duplicate / consolidated with another record',
    'Test or sample data — cleanup',
    'Owner request (with formal sign-off)',
    'Replaced by a new asset entry',
    'Other (see notes)',
  ],
  rejectUser: [
    'Email not affiliated with PLM / not a recognised tenant',
    'Requested role not appropriate for this user',
    'User already has an active account',
    'Awaiting background or HR verification',
    'Suspected automated / spam registration',
    'Other (see notes)',
  ],
};

function promptReason({
  title = 'Provide a reason',
  eyebrow = 'Action requires justification',
  description = 'Pick the closest reason from the list and add detail in the notes — both are stored in the System Logs and shared with the originator.',
  presets = [],
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  tone = 'danger',           // 'danger' | 'warn' | 'info'
  requireSomething = true,    // require either a preset or text
} = {}) {
  return new Promise((resolve) => {
    const prev = document.getElementById('il-reason-modal');
    if (prev) prev.remove();
    const overlay = document.createElement('div');
    overlay.className = 'il-modal-overlay';
    overlay.id = 'il-reason-modal';
    const optsHtml = ['<option value="">— Select a reason —</option>']
      .concat(presets.map(p => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`))
      .join('');
    overlay.innerHTML =
      '<div class="il-modal tone-' + tone + '" role="dialog" aria-modal="true">'
      + '<div class="il-modal-header">'
      + '<div class="il-eyebrow">' + escapeHtml(eyebrow) + '</div>'
      + '<h3>' + escapeHtml(title) + '</h3>'
      + '<p>' + escapeHtml(description) + '</p>'
      + '</div>'
      + '<div class="il-modal-body">'
      + '<div><label for="il-reason-preset">Pre-defined reason</label>'
      + '<select id="il-reason-preset">' + optsHtml + '</select></div>'
      + '<div><label for="il-reason-essay">Notes / additional detail (free text)</label>'
      + '<textarea id="il-reason-essay" placeholder="Add specifics — what changed, what is missing, or any compliance reference."></textarea></div>'
      + '<div id="il-reason-error" class="il-modal-error">A reason is required — pick one from the list or write notes.</div>'
      + '</div>'
      + '<div class="il-modal-footer">'
      + '<button type="button" class="btn btn-sm" id="il-reason-cancel">' + escapeHtml(cancelLabel) + '</button>'
      + '<button type="button" class="btn btn-sm btn-danger" id="il-reason-confirm">' + escapeHtml(confirmLabel) + '</button>'
      + '</div>'
      + '</div>';
    document.body.appendChild(overlay);

    const close = (val) => { overlay.remove(); document.removeEventListener('keydown', onKey); resolve(val); };
    const onKey = (e) => {
      if (e.key === 'Escape') close(null);
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) overlay.querySelector('#il-reason-confirm').click();
    };
    document.addEventListener('keydown', onKey);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(null); });
    overlay.querySelector('#il-reason-cancel').onclick = () => close(null);
    overlay.querySelector('#il-reason-confirm').onclick = () => {
      const preset = overlay.querySelector('#il-reason-preset').value.trim();
      const essay  = overlay.querySelector('#il-reason-essay').value.trim();
      if (requireSomething && !preset && !essay) {
        overlay.querySelector('#il-reason-error').classList.add('show');
        return;
      }
      const combined = [preset, essay].filter(Boolean).join(' — ');
      close(combined);
    };
    setTimeout(() => overlay.querySelector('#il-reason-preset').focus(), 30);
  });
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
    renderComplianceMapping();
}

function updateTags() { updateTagsUI(); runEnforcementEngine(); }

function removeTag(n, event) {
    event.stopPropagation();
    const cb = document.getElementById('ctrl'+n);
    if (cb) cb.checked = false;
    updateTags();
}

function updateActionBadge() {
    const actionsCount = approvedAssetsOnly().filter(a => ['High', 'Moderate'].includes(a.residual) && a.actionType !== 'Accept').length;
    const navActions = document.getElementById('nav-actions');
    if(navActions) navActions.textContent = actionsCount;
}

// ==========================================
// NOTIFICATIONS INBOX
// ==========================================
function notifLastSeenKey() {
    return `impactlens_notif_seen_${currentRole || 'anon'}_${(currentUser?.email || 'anon').toLowerCase()}`;
}
function getNotifLastSeen() {
    try { return parseInt(localStorage.getItem(notifLastSeenKey()) || '0', 10) || 0; }
    catch { return 0; }
}
function setNotifLastSeen(ts) {
    try { localStorage.setItem(notifLastSeenKey(), String(ts)); } catch {}
}

// Parse the "Reason: ... · originator=... · prior_status=..." log details
// into a structured object so notifications can render cleanly.
function parseLogDetails(details) {
    const out = { reason: '', originator: '', target: '', priorStatus: '', requestedRole: '' };
    if (!details) return out;
    const segs = String(details).split(/\s*·\s*/);
    for (const s of segs) {
        const seg = s.trim();
        if (!seg) continue;
        const m = seg.match(/^([a-z_]+)\s*[:=]\s*(.+)$/i);
        if (!m) continue;
        const key = m[1].toLowerCase();
        const val = m[2].trim();
        if (key === 'reason') out.reason = val;
        else if (key === 'originator') out.originator = val;
        else if (key === 'target') out.target = val;
        else if (key === 'prior_status') out.priorStatus = val;
        else if (key === 'requested_role') out.requestedRole = val;
    }
    return out;
}

function reasonHtml(reason, fallback = 'No reason recorded.') {
    const r = (reason || '').trim();
    if (!r) return `<div class="notif-reason notif-reason-none">${fallback}</div>`;
    return `<div class="notif-reason"><span class="notif-reason-label">Reason</span><span class="notif-reason-text">${escapeHtmlSafe(r)}</span></div>`;
}

function computeNotifications() {
    const items = [];
    if (!Array.isArray(globalLogs) || !currentRole || !currentUser?.email) return items;
    const me = currentUser.email.toLowerCase();
    for (const l of globalLogs) {
        const action  = l.action || '';
        const details = l.details || '';
        const aid     = l.asset_id || '';
        const actor   = (l.user_email || '').toLowerCase();
        const ts      = l.created_at ? new Date(l.created_at).getTime() : 0;
        const asset   = aid ? globalAssets.find(a => a.id === aid) : null;
        const aname   = asset ? asset.name : '';
        const orig    = (asset?.created_by || '').toLowerCase();
        const handled = (asset?.updated_by || '').toLowerCase();
        const parsed  = parseLogDetails(details);
        const meIsOriginator = parsed.originator
            ? parsed.originator.toLowerCase() === me
            : (orig === me);

        let msg = null, kind = 'info', target = null;
        const aLabel = aid && aname ? `<strong>${escapeHtmlSafe(aid)}</strong> (${escapeHtmlSafe(aname)})`
                     : aid          ? `<strong>${escapeHtmlSafe(aid)}</strong>`
                     :                 'an asset';

        if (currentRole === 'user') {
            if (action === 'ASSET_APPROVED' && meIsOriginator) {
                msg = `Your asset ${aLabel} was <strong>APPROVED</strong> by the CISO.`;
                kind = 'success';
            } else if (action === 'ASSET_REJECTED' && meIsOriginator) {
                msg = `Your asset ${aLabel} was <strong>REJECTED</strong> and returned to draft for revision.${reasonHtml(parsed.reason)}`;
                kind = 'warn';
            } else if (action === 'DRAFT_REJECTED' && meIsOriginator) {
                msg = `Your draft submission <strong>${escapeHtmlSafe(aid)}</strong> was <strong>REJECTED</strong> by Info Sec and removed from the queue.${reasonHtml(parsed.reason)}`;
                kind = 'warn';
            } else if (action === 'ASSET_DELETED' && meIsOriginator) {
                msg = `Your asset ${aLabel} was <strong>DELETED</strong> by ${escapeHtmlSafe(actor || 'an officer')} (prior status: ${escapeHtmlSafe(parsed.priorStatus || 'unknown')}).${reasonHtml(parsed.reason)}`;
                kind = 'warn';
            } else if (action === 'ASSET_SUBMITTED_FOR_APPROVAL' && meIsOriginator) {
                msg = `Your draft <strong>${escapeHtmlSafe(aid)}</strong> was picked up by Info Sec and forwarded to the CISO.`;
                kind = 'info';
            }
        } else if (currentRole === 'infosec') {
            if (action === 'ASSET_APPROVED' && handled === me) {
                msg = `Your submission ${aLabel} was <strong>APPROVED</strong> by the CISO.`;
                kind = 'success';
            } else if (action === 'ASSET_REJECTED' && handled === me) {
                msg = `Your submission ${aLabel} was <strong>REJECTED</strong> by the CISO and returned to drafts.${reasonHtml(parsed.reason)}`;
                kind = 'warn';
                target = 'draft-queue';
            } else if (action === 'ASSET_DELETED' && (handled === me || actor === me)) {
                msg = `Asset ${aLabel} was <strong>DELETED</strong> (prior status: ${escapeHtmlSafe(parsed.priorStatus || 'unknown')}) by ${escapeHtmlSafe(actor || 'an officer')}.${reasonHtml(parsed.reason)}`;
                kind = 'warn';
            } else if (action === 'ASSET_DRAFT_CREATED' && actor && actor !== me) {
                msg = `New draft <strong>${escapeHtmlSafe(aid)}</strong> (${escapeHtmlSafe(aname)}) submitted by ${escapeHtmlSafe(actor)} — needs profiling.`;
                kind = 'info';
                target = 'draft-queue';
            } else if (action === 'DRAFT_REJECTED' && actor !== me) {
                msg = `Draft <strong>${escapeHtmlSafe(aid)}</strong> was rejected by ${escapeHtmlSafe(actor || 'another officer')}.${reasonHtml(parsed.reason)}`;
                kind = 'info';
                target = 'draft-queue';
            }
        } else if (currentRole === 'admin') {
            if (action === 'ASSET_SUBMITTED_FOR_APPROVAL' && actor !== me) {
                msg = `Asset ${aLabel} is awaiting your approval.`;
                kind = 'warn';
                target = 'pending-queue';
            } else if (action === 'USER_REQUEST' || details.includes('account_status=pending')) {
                msg = `New user account pending approval: ${escapeHtmlSafe(details)}`;
                kind = 'info';
                target = 'users';
            } else if (action === 'USER_REJECTED' && actor !== me) {
                msg = `User account rejected by ${escapeHtmlSafe(actor || 'Info Sec')} — ${escapeHtmlSafe(parsed.target || 'unknown')}.${reasonHtml(parsed.reason)}`;
                kind = 'info';
                target = 'users';
            } else if (action === 'DRAFT_REJECTED' && actor !== me) {
                msg = `Draft ${aLabel} was rejected by ${escapeHtmlSafe(actor || 'Info Sec')}.${reasonHtml(parsed.reason)}`;
                kind = 'info';
                target = 'draft-queue';
            }
        }

        if (msg) items.push({ ts, action, aid, msg, kind, target });
    }
    items.sort((a,b) => b.ts - a.ts);
    return items.slice(0, 30);
}

function renderNotificationBadge() {
    const trigger = document.getElementById('notif-trigger');
    const countEl = document.getElementById('notif-count');
    if (!trigger || !countEl) return;
    if (currentRole === 'user' || currentRole === 'infosec' || currentRole === 'admin') {
        trigger.style.display = '';
    } else {
        trigger.style.display = 'none';
        return;
    }
    const items = computeNotifications();
    const lastSeen = getNotifLastSeen();
    const unread = items.filter(i => i.ts > lastSeen).length;
    if (unread > 0) {
        countEl.textContent = unread > 99 ? '99+' : String(unread);
        countEl.classList.remove('hidden');
    } else {
        countEl.classList.add('hidden');
    }
}

function renderNotificationList() {
    const list = document.getElementById('notif-list');
    if (!list) return;
    const items = computeNotifications();
    const lastSeen = getNotifLastSeen();
    if (!items.length) {
        list.innerHTML = '<div class="notif-empty">No notifications yet.</div>';
        return;
    }
    list.innerHTML = items.map(i => {
        const isUnread = i.ts > lastSeen;
        const ago = relativeTime(i.ts);
        const classes = ['notif-item', 'kind-' + i.kind];
        if (isUnread) classes.push('unread');
        const target = i.target ? `data-target="${i.target}"` : '';
        return `
            <div class="${classes.join(' ')}" ${target} onclick="onNotifClick(this)">
              <div class="notif-dot"></div>
              <div class="notif-body">
                ${i.msg}
                <div class="notif-meta">${i.action.replace(/_/g,' ')} · ${ago}</div>
              </div>
            </div>`;
    }).join('');
}

function relativeTime(ts) {
    if (!ts) return '';
    const diff = Date.now() - ts;
    const m = Math.floor(diff / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return m + 'm ago';
    const h = Math.floor(m / 60);
    if (h < 24) return h + 'h ago';
    const d = Math.floor(h / 24);
    if (d < 7) return d + 'd ago';
    return new Date(ts).toLocaleDateString();
}

function toggleNotifications(event) {
    if (event) event.stopPropagation();
    const dd = document.getElementById('notif-dropdown');
    if (!dd) return;
    const willShow = dd.classList.contains('hidden');
    dd.classList.toggle('hidden');
    if (willShow) {
        renderNotificationList();
        document.addEventListener('click', closeNotifOnOutside);
    } else {
        document.removeEventListener('click', closeNotifOnOutside);
    }
}
function closeNotifOnOutside(ev) {
    const dd = document.getElementById('notif-dropdown');
    const trig = document.getElementById('notif-trigger');
    if (!dd || dd.classList.contains('hidden')) return;
    if (dd.contains(ev.target) || trig?.contains(ev.target)) return;
    dd.classList.add('hidden');
    document.removeEventListener('click', closeNotifOnOutside);
}
function onNotifClick(el) {
    const target = el?.dataset?.target;
    markAllNotificationsRead(false);
    document.getElementById('notif-dropdown')?.classList.add('hidden');
    if (target) showSection(target);
}
function markAllNotificationsRead(rerender = true) {
    setNotifLastSeen(Date.now());
    if (rerender) renderNotificationList();
    renderNotificationBadge();
}
window.toggleNotifications = toggleNotifications;
window.onNotifClick = onNotifClick;
window.markAllNotificationsRead = markAllNotificationsRead;

function calculateDeadlines() {
    const today = new Date(); today.setHours(0,0,0,0);
    const limit = new Date(today); limit.setDate(today.getDate() + 14);
    let dCount = 0;
    
    approvedAssetsOnly().forEach(a => {
        if (a.actionDate && a.actionStatus !== 'Done' && a.actionType !== 'Accept') {
            const target = new Date(a.actionDate); target.setHours(0,0,0,0);
            if (target <= limit) dCount++;
        }
    });
    
    const hCount = approvedAssetsOnly().filter(a => a.residual === 'High').length;
    
    const highBadge = document.getElementById('hdr-high');
    if(highBadge) highBadge.textContent = hCount;

    const deadBadge = document.getElementById('hdr-deadlines');
    if(deadBadge) {
        deadBadge.textContent = dCount;
        deadBadge.style.color = dCount > 0 ? "var(--danger)" : "var(--warn)";
    }
    
    updateActionBadge();
}

// ==========================================
// 6. SUPABASE CRUD OPERATIONS
// ==========================================
function buildAssetPayloadFromForm() {
  const type = g('f-type');
  const name = g('f-name').trim();
  const id = editingId || g('f-id');
  const residual = document.getElementById('r-residual') ? document.getElementById('r-residual').textContent : 'Low';
  const inheritEl = document.getElementById('r-inherit');
  const inherit = inheritEl ? inheritEl.textContent : (INHERIT[(parseInt(g('f-sev')) || 3) + '-' + (parseInt(g('f-prob')) || 3)] || 'Moderate');
  const p = parseInt(g('f-prob')) || 3;
  const s = parseInt(g('f-sev')) || 3;
  const c = parseInt(document.getElementById('f-c').value) || 2;
  const ii = parseInt(document.getElementById('f-i').value) || 2;
  const a = parseInt(document.getElementById('f-a').value) || 2;
  return {
    id, type, name,
    group_name: g('f-group'),
    hostname: g('f-hostname'), server: g('f-server'), custodian: g('f-custodian'), description: g('f-desc'),
    ip_address: g('f-ip'), environment: g('f-environment'), department: g('f-department'),
    pii: document.getElementById('f-pii').value,
    spi: document.getElementById('f-spi').value,
    corp: document.getElementById('f-corp').value,
    ciaC: c, ciaI: ii, ciaA: a, ciaScore: c + ii + a,
    ciaClass: document.getElementById('cia-class').textContent,
    riskCategory: g('f-risk-category'), riskDesc: g('f-risk-desc'),
    prob: p, sev: s, inherit, residual,
    actionType: g('f-action-type'), actionStatus: g('f-action-status'),
    actionPlan: g('f-action-plan'), actionOwner: g('f-action-owner'), actionDate: g('f-action-date'),
    updated_by: currentUser?.email || null
  };
}

function draftDefaultsFromType(type) {
  const profile = ASSET_PROFILES[type];
  if (!profile) return {};
  const score = profile.c + profile.i + profile.a;
  return {
    pii: profile.pii, spi: profile.spi, corp: profile.corp,
    ciaC: profile.c, ciaI: profile.i, ciaA: profile.a,
    ciaScore: score, ciaClass: CIA_CLASS[score] || 'Internal Use',
    prob: 3, sev: 3, inherit: 'Moderate', residual: 'Moderate',
    riskCategory: '', riskDesc: '', actionType: 'Mitigate', actionStatus: 'Pending',
    actionPlan: '', actionOwner: '', actionDate: ''
  };
}

function setSaveStatus(state, html) {
  // Persistent banner above the Add form. state ∈ 'busy' | 'ok' | 'err' | 'idle'.
  const sec = document.getElementById('sec-add');
  if (!sec) return;
  let banner = document.getElementById('save-status-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'save-status-banner';
    banner.className = 'save-status-banner';
    sec.insertBefore(banner, sec.firstChild);
  }
  banner.dataset.state = state;
  banner.innerHTML = html || '';
  banner.style.display = state === 'idle' ? 'none' : '';
}

async function saveAssetToDB() {
  const saveBtn = document.getElementById('btn-save-asset');
  console.info('[saveAssetToDB] clicked', { role: currentRole, supabaseClient: !!supabaseClient, editingId });
  if (saveBtn) {
    if (saveBtn.dataset.busy === '1') return;
    saveBtn.dataset.busy = '1';
    saveBtn.disabled = true;
  }
  setSaveStatus('busy', '<span class="spinner"></span> Saving asset to Supabase…');

  try {
    if (!supabaseClient) {
      setSaveStatus('err', '<strong>✗ Cloud not connected.</strong> Please sign in again.');
      return;
    }

    // Validate session BEFORE the round-trip. We rely on our in-memory
    // `currentUser` (populated during enterAuthenticatedApp) instead of
    // calling `supabaseClient.auth.getSession()`, which can lock for 30s+ if the
    // SDK is stuck on a hung token-refresh.
    console.info('[saveAssetToDB] step=session-check', { hasUser: !!currentUser, role: currentRole, email: currentUser?.email });
    if (!currentUser || !currentRole) {
      setSaveStatus('err',
        '<strong>✗ Your session has expired or is invalid.</strong> '
        + '<div class="save-status-actions">'
        + '<button type="button" class="btn btn-sm" onclick="forceResetSession()">Reset session &amp; sign in again</button>'
        + '</div>');
      return;
    }
    const type = g('f-type');
    const name = (g('f-name') || '').trim();
    if (!type) { setSaveStatus('err', '<strong>✗ Asset Type is required.</strong> Pick one from the dropdown.'); return; }
    if (!name) { setSaveStatus('err', '<strong>✗ Asset Name is required.</strong>'); return; }

    let payload = buildAssetPayloadFromForm();
    const id = payload.id;
    if (!id) { setSaveStatus('err', '<strong>✗ Asset ID missing.</strong> Re-pick the Asset Type.'); return; }

    const wasEditing = !!editingId;
    let priorAsset = null;
    if (wasEditing) priorAsset = globalAssets.find(a => a.id === id) || null;

    if (currentRole === 'user') {
      Object.assign(payload, draftDefaultsFromType(type));
      payload.status = ASSET_STATUS.DRAFT;
      payload.created_by = currentUser?.email || null;
    } else if (currentRole === 'infosec') {
      if (!g('f-risk-category')) { setSaveStatus('err', '<strong>✗ Risk template / category required.</strong>'); return; }
      if (!(g('f-risk-desc') || '').trim()) { setSaveStatus('err', '<strong>✗ Risk description required.</strong>'); return; }
      payload.status = ASSET_STATUS.PENDING;
      calculateRiskMath();
      payload = { ...payload, ...buildAssetPayloadFromForm() };
      payload.status = ASSET_STATUS.PENDING;
      if (priorAsset?.created_by) payload.created_by = priorAsset.created_by;
    } else {
      payload.status = payload.status || ASSET_STATUS.APPROVED;
      if (!wasEditing && !payload.created_by) {
        payload.created_by = currentUser?.email || null;
      }
      payload.reviewed_at = new Date().toISOString();
    }

    const statusEl = document.getElementById('form-workflow-status');
    if (statusEl) statusEl.textContent = payload.status;

    console.info('[saveAssetToDB] step=upsert-start', { id: payload.id, status: payload.status });
    // Use raw fetch via directFetch — bypasses supabase-js's internal locks
    // and guarantees a real network error if Supabase / the network is down.
    try {
      await directFetch('Assets', {
        method: 'POST',
        body: payload,
        prefer: 'resolution=merge-duplicates,return=minimal',
        timeoutMs: 12000
      });
    } catch (assetErr) {
      console.error('[saveAssetToDB] upsert error:', assetErr, assetErr?.body || '');
      const stale = /timeout|fetch|network|jwt|expired|unauthor/i.test(assetErr?.message || '');
      setSaveStatus('err',
        `<strong>✗ Save failed.</strong> ${escapeHtml(assetErr.message || 'Unknown error')}`
        + (assetErr.status ? ` <span style="opacity:.7">(HTTP ${assetErr.status})</span>` : '')
        + '<div class="save-status-actions">'
        + (stale ? '<button type="button" class="btn btn-sm" onclick="forceResetSession()">Reset session &amp; sign in again</button>' : '')
        + '<button type="button" class="btn btn-sm" onclick="setSaveStatus(\'idle\')">Dismiss</button>'
        + '</div>');
      return;
    }
    console.info('[saveAssetToDB] step=upsert-done');

    if (currentRole !== 'user') {
      try {
        await directFetch('AssetControls', {
          method: 'DELETE',
          params: { asset_id: 'eq.' + id },
          prefer: 'return=minimal',
          timeoutMs: 8000
        });
      } catch (e) { console.warn('Ctrl cleanup:', e?.message || e); }
      const controls = [];
      for (let i = 1; i <= 13; i++) {
        const cb = document.getElementById('ctrl' + i);
        if (cb && cb.checked && !cb.disabled) controls.push({ asset_id: id, ctrl_id: i });
      }
      if (controls.length) {
        try {
          await directFetch('AssetControls', {
            method: 'POST',
            body: controls,
            prefer: 'return=minimal',
            timeoutMs: 8000
          });
        } catch (e) { console.warn('Ctrl insert:', e?.message || e); }
      }
    }

    let logAction, detailMsg;
    if (currentRole === 'user') {
      logAction = 'ASSET_DRAFT_CREATED';
      detailMsg = `Status: Draft · awaiting Info Sec profiling · originator=${currentUser?.email || 'unknown'}`;
    } else if (currentRole === 'infosec') {
      logAction = 'ASSET_SUBMITTED_FOR_APPROVAL';
      detailMsg = `Status: Pending · awaiting CISO approval · originator=${payload.created_by || currentUser?.email || 'unknown'}`;
    } else {
      logAction = wasEditing ? 'ASSET_UPDATED' : 'ASSET_CREATED';
      detailMsg = `Status: ${payload.status} · by Admin`;
    }
    // Fire log + cloud refresh in background; do NOT block the UI feedback.
    Promise.resolve(logSystemEvent(logAction, detailMsg, id))
      .then(() => syncFromCloud(true))
      .catch(err => console.warn('post-save background:', err));

    editingId = null;
    clearForm();

    let successMsg;
    if (currentRole === 'user') {
      successMsg = `Draft <strong>${id}</strong> saved.<br>Forwarded to <strong>Info Sec</strong> for cybersecurity profiling.`;
    } else if (currentRole === 'infosec') {
      successMsg = `Asset <strong>${id}</strong> submitted.<br>Forwarded to <strong>Admin (CISO)</strong> for approval.`;
    } else {
      successMsg = `Asset <strong>${id}</strong> saved (${payload.status}).`;
    }
    setSaveStatus('ok',
      `<strong>✓ Success.</strong> ${successMsg} `
      + '<div class="save-status-actions">'
      + '<button type="button" class="btn btn-sm" onclick="setSaveStatus(\'idle\')">Submit another</button>'
      + (currentRole === 'infosec'
          ? '<button type="button" class="btn btn-sm" onclick="showSection(\'draft-queue\')">Open Draft Queue</button>'
          : currentRole === 'admin'
          ? '<button type="button" class="btn btn-sm" onclick="showSection(\'register\')">Open Asset Table</button>'
          : '')
      + '</div>');
    notify('Asset saved.');
  } catch (err) {
    console.error('saveAssetToDB threw:', err);
    const msg = err?.message || String(err);
    const looksLikeStaleSession = /timed out|jwt|expired|fetch|network/i.test(msg);
    setSaveStatus('err',
      `<strong>✗ Could not save asset.</strong> ${escapeHtml(msg)}`
      + '<div class="save-status-actions">'
      + (looksLikeStaleSession
          ? '<button type="button" class="btn btn-sm" onclick="forceResetSession()">Reset session &amp; sign in again</button>'
          : '')
      + '<button type="button" class="btn btn-sm" onclick="setSaveStatus(\'idle\')">Dismiss</button>'
      + '</div>');
  } finally {
    if (saveBtn) {
      saveBtn.dataset.busy = '0';
      saveBtn.disabled = false;
    }
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function approveAsset(id) {
  if (currentRole !== 'admin') return;
  const asset = globalAssets.find(a => a.id === id);
  const originator = asset?.created_by || asset?.updated_by || 'unknown';
  const { error } = await supabaseClient.from('Assets').update({
    status: ASSET_STATUS.APPROVED,
    reviewed_at: new Date().toISOString(),
    updated_by: currentUser?.email
  }).eq('id', id);
  if (error) return notify(error.message, true);
  await logSystemEvent('ASSET_APPROVED', `CISO approved risk assessment · originator=${originator}`, id);
  await syncFromCloud(true);
  notify(`Asset ${id} approved. Originator (${originator}) will see the update on next sign-in.`);
  showSection('pending-queue');
}

async function rejectAsset(id) {
  if (currentRole !== 'admin') return;
  const asset = globalAssets.find(a => a.id === id);
  if (!asset) return notify('Asset not found.', true);
  const originator = asset.created_by || asset.updated_by || 'unknown';
  const reason = await promptReason({
    title: 'Reject submission for revision',
    eyebrow: 'CISO Review · Pending Approval',
    description: 'This asset will be returned to Draft status for the Info Sec officer to address. The reason is logged in System Logs and surfaced in the originator\'s notifications.',
    presets: REASON_PRESETS.rejectAssetPending,
    confirmLabel: 'Reject & return to draft',
    tone: 'warn',
  });
  if (reason === null) return;
  const { error } = await supabaseClient.from('Assets').update({
    status: ASSET_STATUS.DRAFT,
    reviewed_at: new Date().toISOString(),
    updated_by: currentUser?.email
  }).eq('id', id);
  if (error) return notify(error.message, true);
  await logSystemEvent('ASSET_REJECTED', `Reason: ${reason} · originator=${originator}`, id);
  await syncFromCloud(true);
  notify(`Asset ${id} returned to Info Sec for revision — reason logged and surfaced to ${originator}.`);
  showSection('pending-queue');
}

// Info Sec / Admin discard a Draft submitted by a Standard User. The
// asset row is deleted (no soft-state for "rejected draft") and the
// reason is logged so the originator sees why their submission was
// discarded the next time they sign in.
async function rejectDraftAsset(id) {
  if (currentRole !== 'admin' && currentRole !== 'infosec') return;
  const asset = globalAssets.find(a => a.id === id);
  if (!asset) return notify('Asset not found.', true);
  if (asset.status !== ASSET_STATUS.DRAFT) {
    return notify('Only Draft submissions can be rejected here.', true);
  }
  const originator = asset.created_by || asset.updated_by || 'unknown';
  const reason = await promptReason({
    title: `Reject draft submission ${id}`,
    eyebrow: 'Info Sec · Draft Queue',
    description: 'The draft will be removed from the queue and the originator will see your reason in their next sign-in. This cannot be undone.',
    presets: REASON_PRESETS.rejectAssetDraft,
    confirmLabel: 'Reject draft',
    tone: 'danger',
  });
  if (reason === null) return;
  try {
    const { error } = await supabaseClient.from('Assets').delete().eq('id', id);
    if (error) throw error;
    await logSystemEvent('DRAFT_REJECTED', `Reason: ${reason} · originator=${originator}`, id);
    await syncFromCloud(true);
    notify(`Draft ${id} rejected — reason recorded and surfaced to ${originator}.`);
    renderDraftQueue();
  } catch (err) {
    console.error('rejectDraftAsset:', err);
    notify('Failed to reject draft: ' + (err?.message || err), true);
  }
}

function editAsset(id) {
  try {
      const a = globalAssets.find(x => x.id === id);
      if (!a) return notify("Error finding asset.", true);
      if (currentRole === 'user') return notify('Standard users cannot edit existing assets.', true);

      editingId = id;
      const titleEl = document.getElementById('form-title');
      if(titleEl) titleEl.innerHTML = 'UPDATE <span>RECORD</span>';
      const statusEl = document.getElementById('form-workflow-status');
      if (statusEl) statusEl.textContent = a.status || ASSET_STATUS.DRAFT;
      setFormSectionsLocked(false);

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

      const ctrls = globalControls.filter(x => x.asset_id === id).map(r => r.ctrl_id);
      for(let i=1; i<=13; i++) { 
          const cb = document.getElementById('ctrl'+i); 
          if(cb) cb.checked = ctrls.includes(i); 
      }

      runEnforcementEngine(true); 
      setTimeout(updateTagsUI, 50); 

      updateReapprovalBanner(a);
      
      document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
      document.getElementById('sec-add').classList.add('active');
      window.scrollTo(0,0);
  } catch (err) {
      console.error("Edit Error:", err);
      notify("Failed to open asset for editing.", true);
  }
}

function updateReapprovalBanner(asset) {
    let banner = document.getElementById('reapproval-banner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'reapproval-banner';
        banner.className = 'reapproval-banner';
        const sec = document.getElementById('sec-add');
        if (sec) sec.insertBefore(banner, sec.firstChild);
    }
    const status = asset?.status || ASSET_STATUS.DRAFT;
    if (currentRole === 'infosec' && status === ASSET_STATUS.APPROVED) {
        banner.innerHTML = '<strong>Re-Approval Required</strong> — This asset is currently <span class="badge badge-type">Approved</span>. Saving any change will move it back to <span class="badge badge-mo">Pending Approval</span> until the CISO reviews it again.';
        banner.hidden = false;
    } else if (currentRole === 'infosec' && status === ASSET_STATUS.PENDING) {
        banner.innerHTML = '<strong>Awaiting CISO Review</strong> — This asset is in the approval queue. You can still update it; it will remain <span class="badge badge-mo">Pending Approval</span>.';
        banner.hidden = false;
    } else if (currentRole === 'admin' && status === ASSET_STATUS.PENDING) {
        banner.innerHTML = '<strong>CISO Review Mode</strong> — Use Approve/Reject in the Pending Approval queue to finalize this submission.';
        banner.hidden = false;
    } else {
        banner.hidden = true;
        banner.innerHTML = '';
    }
}

async function deleteAsset(id) {
  if (currentRole !== 'admin' && currentRole !== 'infosec') {
    return notify('Standard users cannot delete assets.', true);
  }
  const asset = globalAssets.find(a => a.id === id);
  if (!asset) return notify('Asset not found.', true);
  const originator = asset.created_by || asset.updated_by || 'unknown';
  const reason = await promptReason({
    title: `Permanently delete ${id}`,
    eyebrow: 'ISMS Register · Destructive action',
    description: `${escapeHtml(asset.name || id)} will be removed from the database along with its control mappings. This cannot be undone — the reason and your identity are written to System Logs.`,
    presets: REASON_PRESETS.deleteAsset,
    confirmLabel: 'Delete asset',
    tone: 'danger',
  });
  if (reason === null) return;
  try {
    const { error } = await supabaseClient.from('Assets').delete().eq('id', id);
    if (error) throw error;
    await logSystemEvent('ASSET_DELETED',
      `Reason: ${reason} · originator=${originator} · prior_status=${asset.status || 'Approved'}`, id);
    await syncFromCloud(true);
    notify(`Asset ${id} deleted — reason logged and surfaced to ${originator}.`);
    // Refresh whichever queue we were on
    const active = document.querySelector('.section.active')?.id;
    if (active === 'sec-draft-queue')   renderDraftQueue();
    else if (active === 'sec-pending-queue') renderPendingQueue();
    else if (active === 'sec-register') renderRegister();
    else if (active === 'sec-risk')     renderRiskRegister();
    else showSection('register');
  } catch (err) {
    console.error('Deletion Error:', err);
    notify('Failed to delete asset: ' + (err?.message || err), true);
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
  const statusEl = document.getElementById('form-workflow-status');
  if (statusEl) statusEl.textContent = ASSET_STATUS.DRAFT;
  setFormSectionsLocked(currentRole === 'user');
  const banner = document.getElementById('reapproval-banner');
  if (banner) { banner.hidden = true; banner.innerHTML = ''; }
  
  runEnforcementEngine(); 
  updateTagsUI();
}

async function saveReportData() {
    const payload = {
        id: 1, docDate: g('doc-date'), docVersion: g('doc-version'), docAuthor: g('doc-author'), docApproval: g('doc-approval'), docDesc: g('doc-desc'),
        revHigh: g('rep-rev-high'), initHigh: g('rep-init-high'),
        prepName: g('rep-prep-name'), prepTitle: g('rep-prep-title'), revName: g('rep-rev-name'), revTitle: g('rep-rev-title'), appName: g('rep-app-name'), appTitle: g('rep-app-title')
    };
    const { error } = await supabaseClient.from('ReportData').upsert(payload);
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
function statusBadge(status) {
  const map = {
    [ASSET_STATUS.DRAFT]: 'badge-type',
    [ASSET_STATUS.PENDING]: 'badge-mo',
    [ASSET_STATUS.APPROVED]: 'badge-lo',
    [ASSET_STATUS.REJECTED]: 'badge-hi'
  };
  const cls = map[status] || 'badge-type';
  return `<span class="badge ${cls}">${status || '—'}</span>`;
}

function renderDraftQueue() {
  const tbody = document.getElementById('draft-queue-body');
  if (!tbody) return;
  const items = globalAssets.filter(a => a.status === ASSET_STATUS.DRAFT);
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No draft assets in queue.</td></tr>';
    return;
  }
  const canActOnDraft = currentRole === 'admin' || currentRole === 'infosec';
  tbody.innerHTML = items.map(a => {
    const actions = [
      `<button class="btn btn-sm btn-primary" onclick="editAsset('${a.id}')">Assess →</button>`,
      canActOnDraft
        ? `<button class="btn btn-sm btn-danger" style="margin-left:4px" onclick="rejectDraftAsset('${a.id}')">Reject</button>`
        : '',
      canActOnDraft
        ? `<button class="btn btn-sm btn-danger" style="margin-left:4px;opacity:0.85" onclick="deleteAsset('${a.id}')">Delete</button>`
        : ''
    ].filter(Boolean).join('');
    return `
    <tr>
      <td><span class="badge badge-id">${a.id}</span> ${statusBadge(a.status)}</td>
      <td><strong>${a.name}</strong></td>
      <td><span class="badge badge-type">${a.type}</span></td>
      <td style="color:var(--text2)">${a.created_by || '—'}</td>
      <td style="white-space:nowrap">${actions}</td>
    </tr>`;
  }).join('');
}

function renderPendingQueue() {
  const el = document.getElementById('pending-queue-content');
  if (!el) return;
  const items = globalAssets.filter(a => a.status === ASSET_STATUS.PENDING);
  const D = ['d','i','v'].join('');
  if (!items.length) {
    el.innerHTML = '<' + D + ' class="empty-state"><' + D + ' class="icon">[✓]</' + D + '><' + D + '>No assets awaiting CISO approval.</' + D + '></' + D + '>';
    return;
  }
  const isAdmin   = currentRole === 'admin';
  const isInfoSec = currentRole === 'infosec';
  el.innerHTML = items.map(a => {
    const ctrls = globalControls.filter(c => c.asset_id === a.id).length;
    const reviewBtn = '<button class="btn btn-sm" onclick="editAsset(\'' + a.id + '\')">' + (isAdmin ? 'Review' : 'Open (read-only)') + '</button>';
    let adminActions;
    if (isAdmin) {
      adminActions =
        '<button class="btn btn-sm btn-danger" onclick="rejectAsset(\'' + a.id + '\')">Reject</button>'
        + '<button class="btn btn-sm btn-danger" style="opacity:0.85" onclick="deleteAsset(\'' + a.id + '\')">Delete</button>'
        + '<button class="btn btn-sm btn-success" onclick="approveAsset(\'' + a.id + '\')">Approve</button>';
    } else if (isInfoSec) {
      // Info Sec can withdraw their own pending submission with a logged reason.
      adminActions =
        '<span class="badge badge-mo" style="margin-left:8px">Awaiting CISO Review</span>'
        + '<button class="btn btn-sm btn-danger" style="margin-left:8px;opacity:0.9" onclick="deleteAsset(\'' + a.id + '\')">Withdraw</button>';
    } else {
      adminActions = '<span class="badge badge-mo" style="margin-left:8px">Awaiting CISO Review</span>';
    }
    return [
      '<' + D + ' class="card queue-card" style="border-left:3px solid var(--warn);margin-bottom:16px;padding:20px 24px">',
      '<' + D + ' style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;margin-bottom:12px">',
      '<' + D + '><span class="badge badge-id">' + a.id + '</span> <strong style="margin-left:8px">' + a.name + '</strong> <span class="badge badge-type" style="margin-left:8px">' + a.type + '</span></' + D + '>',
      riskBadge(a.residual),
      '</' + D + '>',
      '<p style="font-size:12px;color:var(--text2);margin-bottom:12px">' + (a.riskDesc || '—') + '</p>',
      '<' + D + ' style="font-family:var(--mono);font-size:10px;color:var(--text3);margin-bottom:12px">Inherent: ' + (a.inherit || '—') + ' · Controls: ' + ctrls + ' · Class: ' + (a.ciaClass || '—') + (a.updated_by ? ' · Submitted by: ' + a.updated_by : '') + '</' + D + '>',
      '<' + D + ' style="display:flex;gap:8px;justify-content:flex-end;align-items:center">',
      reviewBtn,
      adminActions,
      '</' + D + '></' + D + '>'
    ].join('');
  }).join('');
}

async function renderUserManagement() {
  const tbody = document.getElementById('users-body');
  if (!tbody || !supabaseClient) return;
  tbody.innerHTML = '<tr><td colspan="4">Loading…</td></tr>';
  const { data, error } = await supabaseClient.from('user_profiles').select('*').order('created_at', { ascending: false });
  if (error) {
    tbody.innerHTML = `<tr><td colspan="4">Error: ${error.message}. Run supabase/master_setup.sql.</td></tr>`;
    return;
  }
  const pending = (data || []).filter(p => p.account_status === 'pending');
  if (!pending.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">No pending account approvals.</td></tr>';
    return;
  }
  tbody.innerHTML = pending.map(p => {
    const canApprove =
      (currentRole === 'admin') ||
      (currentRole === 'infosec' && p.requested_role === 'user');
    const actions = canApprove
      ? `<button class="btn btn-sm btn-success" onclick="approveUserAccount('${p.id}')">Approve</button>
         <button class="btn btn-sm btn-danger" onclick="rejectUserAccount('${p.id}')">Reject</button>`
      : '<span style="color:var(--text3)">Awaiting Admin</span>';
    return `<tr>
      <td>${p.email}</td>
      <td>${roleLabel(p.requested_role)}</td>
      <td><span class="badge badge-mo">Pending</span></td>
      <td>${actions}</td>
    </tr>`;
  }).join('');
}

async function approveUserAccount(userId) {
  if (!currentUser) return;
  const { data: target } = await supabaseClient.from('user_profiles').select('*').eq('id', userId).single();
  if (!target) return notify('User not found.', true);
  if (currentRole === 'infosec' && target.requested_role !== 'user') {
    return notify('Info Sec can only approve Standard User accounts.', true);
  }
  const { error } = await supabaseClient.from('user_profiles').update({
    account_status: 'active',
    approved_role: target.requested_role,
    approved_by: currentUser.id,
    approved_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  }).eq('id', userId);
  if (error) return notify(error.message, true);
  await logSystemEvent('USER_APPROVED', `Approved ${target.email} as ${target.requested_role}`);
  notify(`Account ${target.email} approved.`);
  renderUserManagement();
}

async function rejectUserAccount(userId) {
  if (currentRole !== 'admin' && currentRole !== 'infosec') return;
  const { data: target } = await supabaseClient.from('user_profiles').select('*').eq('id', userId).single();
  if (!target) return notify('User profile not found.', true);
  if (currentRole === 'infosec' && target.requested_role !== 'user') {
    return notify('Info Sec can only reject Standard User account requests.', true);
  }
  const reason = await promptReason({
    title: `Reject account request — ${target.email}`,
    eyebrow: 'User Management · Pending approval',
    description: 'The applicant remains in Supabase Auth but their profile is marked rejected and they will not be able to sign in. The reason is recorded in System Logs.',
    presets: REASON_PRESETS.rejectUser,
    confirmLabel: 'Reject account',
    tone: 'danger',
  });
  if (reason === null) return;
  const { error } = await supabaseClient.from('user_profiles').update({
    account_status: 'rejected',
    rejection_reason: reason,
    updated_at: new Date().toISOString()
  }).eq('id', userId);
  if (error) {
    // rejection_reason column may not exist on legacy installs — retry without it.
    if (/rejection_reason/i.test(error.message)) {
      const retry = await supabaseClient.from('user_profiles').update({
        account_status: 'rejected',
        updated_at: new Date().toISOString()
      }).eq('id', userId);
      if (retry.error) return notify(retry.error.message, true);
    } else {
      return notify(error.message, true);
    }
  }
  await logSystemEvent('USER_REJECTED', `Reason: ${reason} · target=${target.email} · requested_role=${target.requested_role}`);
  notify(`Account ${target.email} rejected.`);
  renderUserManagement();
}

function renderSystemLogs() {
  const tbody = document.getElementById('logs-body');
  if (!tbody) return;
  if (!globalLogs.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">No log entries.</td></tr>';
    return;
  }
  tbody.innerHTML = globalLogs.map(l => `
    <tr>
      <td style="white-space:nowrap">${l.created_at ? new Date(l.created_at).toLocaleString() : '—'}</td>
      <td>${l.user_email || '—'}</td>
      <td>${roleLabel(l.user_role) || l.user_role || '—'}</td>
      <td><span class="badge badge-type">${l.action || '—'}</span></td>
      <td>${l.asset_id || '—'}</td>
      <td style="font-size:11px;color:var(--text2)">${l.details || '—'}</td>
    </tr>
  `).join('');
}

function renderRegister() {
  const tbody = document.getElementById('reg-body');
  if(!tbody) return;
  const data = approvedAssetsOnly();

  if (!data.length) { tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;">No approved records.</td></tr>`; return; }

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
  let data = [...approvedAssetsOnly()];
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
  approvedAssetsOnly().forEach(a => {
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
  const approved = approvedAssetsOnly();
  const approvedIds = new Set(approved.map(a => a.id));
  const total = approved.length || 1;
  const ctrlCounts = {};
  globalControls.filter(c => approvedIds.has(c.asset_id)).forEach(c => {
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
    const items = approvedAssetsOnly().filter(a => ['High', 'Moderate'].includes(a.residual) && a.actionType !== 'Accept')
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
  const approved = approvedAssetsOnly();
  const total = approved.length;

  /* -------- Risk posture KPIs (elevated = High + Moderate residual) -------- */
  const elevated = approved.filter(a => a.residual === 'High' || a.residual === 'Moderate');
  const elevatedN = elevated.length;
  const thresholdPct = total ? Math.round((elevatedN / total) * 1000) / 10 : 0;

  const inhMap = { High: 4, Moderate: 3, Low: 2, 'Very Low': 1 };
  const inhVals = approved.map(a => inhMap[a.inherit]).filter(v => v > 0);
  const avgInh = inhVals.length ? inhVals.reduce((x, y) => x + y, 0) / inhVals.length : 0;

  const assessed = approved.filter(a =>
    (a.riskDesc && String(a.riskDesc).trim().length > 0) && a.prob && a.sev
  ).length;
  const analysisPct = total ? Math.round((assessed / total) * 1000) / 10 : 0;

  const respEl = document.getElementById('dm-risk-response-detail');
  let responsePct = 100;
  if (elevatedN === 0) {
    responsePct = 100;
    if (respEl) respEl.textContent = 'No elevated residual risks in register';
  } else {
    const advancing = elevated.filter(a => a.actionStatus === 'Done' || a.actionStatus === 'In Progress').length;
    responsePct = Math.round((advancing / elevatedN) * 1000) / 10;
    if (respEl) respEl.textContent = `${advancing} of ${elevatedN} with treatment in flight or closed`;
  }

  const setTxt = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  setTxt('dm-risk-threshold-pct', `${thresholdPct}%`);
  setTxt('dm-risk-threshold-n', String(elevatedN));
  setTxt('dm-risk-avg-inherit', avgInh ? `Avg inherent tier: ${avgInh.toFixed(2)} (1=Very Low … 4=High)` : 'Avg inherent tier: —');
  setTxt('dm-risk-analysis-pct', `${analysisPct}%`);
  setTxt('dm-risk-response-pct', `${responsePct}%`);

  if(document.getElementById('hdr-total')) document.getElementById('hdr-total').textContent = total;
  if(document.getElementById('nav-total')) document.getElementById('nav-total').textContent = total;
  if(document.getElementById('dm-total')) document.getElementById('dm-total').textContent = total;
  
  const highRisk = approved.filter(a => a.residual === 'High').length;
  const modRisk = approved.filter(a => a.residual === 'Moderate').length;
  const piiCount = approved.filter(a => a.pii === 'Y' || a.spi === 'Y').length;
  
  if(document.getElementById('dm-high')) document.getElementById('dm-high').textContent = highRisk;
  if(document.getElementById('dm-mod')) document.getElementById('dm-mod').textContent = modRisk;
  if(document.getElementById('dm-pii')) document.getElementById('dm-pii').textContent = piiCount;

  const barHtml = (label, val, t, color) => {
    if(!val) return ''; 
    const pct = Math.round((val/t)*100);
    return `<div class="chart-bar-row"><div class="chart-bar-label">${label}</div><div class="chart-bar-track"><div class="chart-bar-fill" style="width:${pct}%;background:${color};color:#000">${pct>10?pct+'%':''}</div></div><div class="chart-bar-count" style="width:24px;text-align:right;">${val}</div></div>`;
  };

  const byType = {}; approved.forEach(a => byType[a.type] = (byType[a.type] || 0) + 1);
  const typeColors = {IA:'var(--accent)',PhA:'var(--accent2)',PA:'var(--success)',SA:'var(--warn)',SV:'var(--purple)', 'FA':'var(--info)'};
  const typeEl = document.getElementById('dash-types');
  if(typeEl) {
      if(Object.keys(byType).length === 0) typeEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else typeEl.innerHTML = Object.keys(byType).map(t => barHtml(t, byType[t], total || 1, typeColors[t])).join('');
  }

  const byRes = {}; approved.forEach(a => byRes[a.residual] = (byRes[a.residual] || 0) + 1);
  const rColors = {'High':'var(--danger)','Moderate':'var(--warn)','Low':'var(--accent2)','Very Low':'var(--success)'};
  const resEl = document.getElementById('dash-residual');
  if(resEl) {
      if(Object.keys(byRes).length === 0) resEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else resEl.innerHTML = Object.keys(byRes).map(r => barHtml(r, byRes[r], total || 1, rColors[r])).join('');
  }

  const byClass = {}; approved.forEach(a => byClass[a.ciaClass] = (byClass[a.ciaClass] || 0) + 1);
  const cColors = {'Public':'var(--success)','Internal Use':'var(--accent2)','Confidential':'var(--warn)','Restricted':'var(--danger)'};
  const classEl = document.getElementById('dash-class');
  if(classEl) {
      if(Object.keys(byClass).length === 0) classEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else classEl.innerHTML = Object.keys(byClass).map(c => barHtml(c, byClass[c], total || 1, cColors[c])).join('');
  }

  const trEl = document.getElementById('dash-top-risk');
  if(trEl) {
      const sevMap = { 'Critical': 1, 'High': 2, 'Moderate': 3, 'Low': 4, 'Very Low': 5 };
      const topRisks = [...approved].sort((a, b) => (sevMap[a.residual] || 6) - (sevMap[b.residual] || 6)).slice(0, 5);
      if(!topRisks.length) trEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else trEl.innerHTML = topRisks.map(a => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
          <div><span class="badge badge-id" style="margin-right:6px;font-size:9px">${a.id}</span><span style="font-size:12px;color:var(--text)">${a.name}</span></div>
          ${riskBadge(a.residual)}
        </div>
      `).join('');
  }

  /* -------- Donut charts -------- */
  renderDashboardDonut(document.getElementById('dash-risk-donut'), [
    { label: 'High', n: byRes.High || 0, hex: '#ff4444' },
    { label: 'Moderate', n: byRes.Moderate || 0, hex: '#ff9900' },
    { label: 'Low', n: byRes.Low || 0, hex: '#00d4ff' },
    { label: 'Very Low', n: byRes['Very Low'] || 0, hex: '#00cc77' }
  ]);

  const stDone = elevated.filter(a => a.actionStatus === 'Done').length;
  const stProg = elevated.filter(a => a.actionStatus === 'In Progress').length;
  const stPend = elevated.filter(a => a.actionStatus === 'Pending').length;
  const stSum = stDone + stProg + stPend;
  const stOther = Math.max(0, elevatedN - stSum);
  renderDashboardDonut(document.getElementById('dash-action-donut'), [
    { label: 'Done', n: stDone, hex: '#00cc77' },
    { label: 'In progress', n: stProg, hex: '#00d4ff' },
    { label: 'Pending', n: stPend, hex: '#ff9900' },
    { label: 'Other / unset', n: stOther, hex: '#6a6a78' }
  ]);

  /* -------- Compact inherent heatmap -------- */
  const hmEl = document.getElementById('dash-heatmap');
  if (hmEl) {
    hmEl.innerHTML = dashboardHeatmapShell();
    const riskCounts = {};
    approved.forEach(a => {
      if (a.prob && a.sev) {
        const key = `${a.prob}-${a.sev}`;
        riskCounts[key] = (riskCounts[key] || 0) + 1;
      }
    });
    Object.entries(riskCounts).forEach(([key, count]) => {
      const cell = document.getElementById(`dmx-${key}`);
      if (cell) {
        const badge = document.createElement('div');
        badge.className = 'mx-count active';
        badge.style.opacity = '1';
        badge.textContent = count;
        cell.appendChild(badge);
      }
    });
  }

  const topInhEl = document.getElementById('dash-top-inherent');
  if (topInhEl) {
    const scored = approved
      .filter(a => a.prob && a.sev)
      .map(a => ({ a, score: (+a.prob) * (+a.sev) }))
      .sort((x, y) => y.score - x.score)
      .slice(0, 5);
    const maxS = scored[0]?.score || 25;
    if (!scored.length) {
      topInhEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No probability × severity recorded</p>';
    } else {
      topInhEl.innerHTML = scored.map(({ a, score }) => {
        const w = Math.round((score / maxS) * 100);
        const nm = escapeHtmlSafe((a.name || '').slice(0, 32));
        return `<div class="chart-bar-row"><div class="chart-bar-label" style="width:150px;font-size:10px;">${nm}${(a.name || '').length > 32 ? '…' : ''}</div><div class="chart-bar-track"><div class="chart-bar-fill" style="width:${w}%;background:var(--accent);color:#0a0a0f">${score}</div></div><div class="chart-bar-count">${a.prob}×${a.sev}</div></div>`;
      }).join('');
    }
  }

  const stratEl = document.getElementById('dash-strategy-bars');
  if (stratEl) {
    if (!elevatedN) {
      stratEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No elevated risks — treatment mix empty</p>';
    } else {
      const smap = { Mitigate: 0, Transfer: 0, Avoid: 0, Accept: 0 };
      elevated.forEach(a => {
        const t = a.actionType;
        if (smap[t] !== undefined) smap[t]++;
      });
      const denom = elevatedN;
      const scolors = { Mitigate: 'var(--accent2)', Transfer: 'var(--purple)', Avoid: 'var(--warn)', Accept: 'var(--text3)' };
      stratEl.innerHTML = Object.keys(smap).map(k => {
        const v = smap[k];
        const pct = Math.round((v / denom) * 100);
        return `<div class="chart-bar-row"><div class="chart-bar-label">${k}</div><div class="chart-bar-track"><div class="chart-bar-fill" style="width:${pct}%;background:${scolors[k]};color:#0a0a0f">${pct > 8 ? pct + '%' : ''}</div></div><div class="chart-bar-count" style="width:28px;text-align:right;">${v}</div></div>`;
      }).join('');
    }
  }

  calculateDeadlines();
}

function dashboardHeatmapShell() {
  return `<div class="matrix matrix--dash">
<div class="mx-cell mx-hdr" style="grid-column:1;grid-row:1;">S↓/P→</div>
<div class="mx-cell mx-hdr" style="grid-column:2;grid-row:1;">1</div>
<div class="mx-cell mx-hdr" style="grid-column:3;grid-row:1;">2</div>
<div class="mx-cell mx-hdr" style="grid-column:4;grid-row:1;">3</div>
<div class="mx-cell mx-hdr" style="grid-column:5;grid-row:1;">4</div>
<div class="mx-cell mx-hdr" style="grid-column:6;grid-row:1;">5</div>
<div class="mx-cell mx-hdr" style="grid-row:2;grid-column:1;text-align:right;">5 H</div>
<div class="mx-cell mx-mo" id="dmx-1-5" style="grid-row:2;grid-column:2;"></div>
<div class="mx-cell mx-mo" id="dmx-2-5" style="grid-row:2;grid-column:3;"></div>
<div class="mx-cell mx-hi" id="dmx-3-5" style="grid-row:2;grid-column:4;"></div>
<div class="mx-cell mx-hi" id="dmx-4-5" style="grid-row:2;grid-column:5;"></div>
<div class="mx-cell mx-hi" id="dmx-5-5" style="grid-row:2;grid-column:6;"></div>
<div class="mx-cell mx-hdr" style="grid-row:3;grid-column:1;text-align:right;">4</div>
<div class="mx-cell mx-lo" id="dmx-1-4" style="grid-row:3;grid-column:2;"></div>
<div class="mx-cell mx-mo" id="dmx-2-4" style="grid-row:3;grid-column:3;"></div>
<div class="mx-cell mx-mo" id="dmx-3-4" style="grid-row:3;grid-column:4;"></div>
<div class="mx-cell mx-hi" id="dmx-4-4" style="grid-row:3;grid-column:5;"></div>
<div class="mx-cell mx-hi" id="dmx-5-4" style="grid-row:3;grid-column:6;"></div>
<div class="mx-cell mx-hdr" style="grid-row:4;grid-column:1;text-align:right;">3</div>
<div class="mx-cell mx-lo" id="dmx-1-3" style="grid-row:4;grid-column:2;"></div>
<div class="mx-cell mx-mo" id="dmx-2-3" style="grid-row:4;grid-column:3;"></div>
<div class="mx-cell mx-mo" id="dmx-3-3" style="grid-row:4;grid-column:4;"></div>
<div class="mx-cell mx-mo" id="dmx-4-3" style="grid-row:4;grid-column:5;"></div>
<div class="mx-cell mx-hi" id="dmx-5-3" style="grid-row:4;grid-column:6;"></div>
<div class="mx-cell mx-hdr" style="grid-row:5;grid-column:1;text-align:right;">2</div>
<div class="mx-cell mx-lo" id="dmx-1-2" style="grid-row:5;grid-column:2;"></div>
<div class="mx-cell mx-lo" id="dmx-2-2" style="grid-row:5;grid-column:3;"></div>
<div class="mx-cell mx-mo" id="dmx-3-2" style="grid-row:5;grid-column:4;"></div>
<div class="mx-cell mx-mo" id="dmx-4-2" style="grid-row:5;grid-column:5;"></div>
<div class="mx-cell mx-mo" id="dmx-5-2" style="grid-row:5;grid-column:6;"></div>
<div class="mx-cell mx-hdr" style="grid-row:6;grid-column:1;text-align:right;">1</div>
<div class="mx-cell mx-vl" id="dmx-1-1" style="grid-row:6;grid-column:2;"></div>
<div class="mx-cell mx-lo" id="dmx-2-1" style="grid-row:6;grid-column:3;"></div>
<div class="mx-cell mx-lo" id="dmx-3-1" style="grid-row:6;grid-column:4;"></div>
<div class="mx-cell mx-lo" id="dmx-4-1" style="grid-row:6;grid-column:5;"></div>
<div class="mx-cell mx-mo" id="dmx-5-1" style="grid-row:6;grid-column:6;"></div>
</div>`;
}

function renderDashboardDonut(container, segments) {
  if (!container) return;
  const total = segments.reduce((s, x) => s + x.n, 0);
  if (!total) {
    container.innerHTML = '<p style="color:var(--text3);text-align:center;padding:20px;">No data</p>';
    return;
  }
  let deg = 0;
  const parts = [];
  segments.forEach(seg => {
    if (!seg.n) return;
    const span = (seg.n / total) * 360;
    const end = deg + span;
    parts.push(`${seg.hex} ${deg}deg ${end}deg`);
    deg = end;
  });
  const grad = parts.length ? `conic-gradient(${parts.join(',')})` : 'conic-gradient(#2a2a35 0deg 360deg)';
  const legend = segments.filter(s => s.n > 0).map(s => {
    const pct = Math.round((s.n / total) * 1000) / 10;
    return `<li><span class="swatch" style="background:${s.hex}"></span>${escapeHtmlSafe(s.label)} <strong>${s.n}</strong> (${pct}%)</li>`;
  }).join('');
  container.innerHTML = `<div class="dash-donut-ring" style="background:${grad};"></div><ul class="dash-donut-legend">${legend}</ul>`;
}

function excelRiskFill(rating) {
    const r = (rating || '').toLowerCase();
    if (r === 'high') return { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFF4444' } };
    if (r === 'moderate') return { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFCC00' } };
    if (r === 'low') return { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF00D4FF' } };
    if (r.includes('very')) return { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF00CC77' } };
    return { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF2A2A35' } };
}

// Pick a high-contrast text color for the risk chip background returned by
// excelRiskFill. Red ('high') needs white; yellow / cyan / green need black.
// The dark fallback fill keeps white.
function excelRiskTextOn(rating) {
    const r = (rating || '').toLowerCase();
    if (r === 'high') return 'FFFFFFFF';
    if (r === 'moderate' || r === 'low' || r.includes('very')) return 'FF111111';
    return 'FFFFFFFF';
}

async function exportDataXLSX() {
    if (currentRole !== 'admin' && currentRole !== 'infosec') {
        return notify('Export is restricted to Info Sec and Admin roles.', true);
    }
    if (typeof ExcelJS === 'undefined') { notify('ExcelJS library not loaded.', true); return; }

    const rep = globalReport || {};
    const isAdmin = currentRole === 'admin';

    // Role-scoped data:
    //  - Admin   : Approved + Pending (full register including in-flight items)
    //  - InfoSec : Approved + Pending (their working set; same scope, no Sign-Off sheet)
    const assets = globalAssets.filter(a =>
        a.status === ASSET_STATUS.APPROVED || a.status === ASSET_STATUS.PENDING
    );

    const wb = new ExcelJS.Workbook();
    wb.creator  = 'ImpactLens';
    wb.created  = new Date();
    wb.company  = 'Pamantasan ng Lungsod ng Maynila — ISMS';

    // ---------- shared style helpers (admin PDF aesthetic) ----------
    // NOTE: COL_TITLE_FG is the BODY accent (readable on white). The neon
    // brand green is reserved for the dark title bar + header rows where
    // contrast is high enough to remain legible.
    const COL_TITLE_BG    = 'FF111118';
    const COL_TITLE_FG    = 'FF0E6E2C';   // deep forest green — readable on white
    const COL_TITLE_NEON  = 'FFC8FF00';   // brand neon — only on dark backgrounds
    const COL_HDR_BG      = 'FF1A1A22';
    const COL_HDR_FG      = 'FFC8FF00';
    const COL_SUB_BG      = 'FF2A2A35';
    const COL_BORDER      = 'FFC0C0CC';   // mid-grey borders — visible on white cells

    // ---- White-cell-safe ink palette ------------------------------------
    // Default Excel cell fill is white. Use these darker tones for any body
    // text that lands on an unfilled (white) cell so it remains legible when
    // the spreadsheet is opened, printed, or screenshot for evidence.
    const COL_INK_BODY    = 'FF1B1B22';   // primary body text on white
    const COL_INK_MUTED   = 'FF6A6A78';   // captions / labels on white (~4.6:1)
    const COL_INK_SOFT    = 'FF7A7A88';   // italic placeholders on white
    const COL_OK_DARK     = 'FF1F7A3A';   // "Approved" green on white
    const COL_BAD_DARK    = 'FFB02020';   // "Rejected" red   on white
    const COL_WARN_DARK   = 'FFB35A1A';   // "Deleted"  orange on white

    const styleTitle = (ws, row, text, cols) => {
        ws.mergeCells(row, 1, row, cols);
        const c = ws.getCell(row, 1);
        c.value = text;
        c.font  = { name: 'Calibri', size: 16, bold: true, color: { argb: COL_TITLE_NEON } };
        c.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: COL_TITLE_BG } };
        c.alignment = { vertical: 'middle', horizontal: 'left', indent: 1 };
        c.border = { bottom: { style: 'medium', color: { argb: COL_TITLE_NEON } } };
        ws.getRow(row).height = 30;
    };
    const styleSubtitle = (ws, row, text, cols) => {
        ws.mergeCells(row, 1, row, cols);
        const c = ws.getCell(row, 1);
        c.value = text;
        c.font  = { name: 'Calibri', size: 10, bold: true, italic: true, color: { argb: 'FFB5B5C5' } };
        c.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: COL_SUB_BG } };
        c.alignment = { vertical: 'middle', horizontal: 'left', indent: 1 };
        ws.getRow(row).height = 18;
    };
    const styleHeaderRow = (ws, rowNum, colCount) => {
        for (let col = 1; col <= colCount; col++) {
            const c = ws.getCell(rowNum, col);
            c.font = { bold: true, color: { argb: COL_HDR_FG }, size: 10 };
            c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: COL_HDR_BG } };
            c.border = {
                top:    { style: 'medium', color: { argb: COL_HDR_FG } },
                bottom: { style: 'medium', color: { argb: COL_HDR_FG } },
                left:   { style: 'thin',   color: { argb: COL_BORDER } },
                right:  { style: 'thin',   color: { argb: COL_BORDER } },
            };
            c.alignment = { vertical: 'middle', horizontal: 'center', wrapText: true };
        }
        ws.getRow(rowNum).height = 26;
    };
    const styleBodyCells = (ws, rowNum, colCount) => {
        for (let col = 1; col <= colCount; col++) {
            const c = ws.getCell(rowNum, col);
            c.border = {
                top:    { style: 'thin', color: { argb: COL_BORDER } },
                bottom: { style: 'thin', color: { argb: COL_BORDER } },
                left:   { style: 'thin', color: { argb: COL_BORDER } },
                right:  { style: 'thin', color: { argb: COL_BORDER } },
            };
            c.alignment = c.alignment || { vertical: 'middle', wrapText: true };
        }
    };
    const yn = v => (v === 'Y' ? 'Y' : 'N');
    const ynFill = v => v === 'Y'
        ? { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F3A1F' } }
        : { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1A1A22' } };
    const ynFont = v => v === 'Y'
        ? { bold: true, color: { argb: 'FF7CFF7C' } }
        : { color: { argb: 'FF6A6A78' } };
    const setCols = (ws, widths) => { ws.columns = widths.map(w => ({ width: w })); };
    const addBranding = (ws, cols) => {
        styleTitle(ws, 1, 'IMPACTLENS  ·  PLM ISMS  —  Information Asset Register', cols);
        styleSubtitle(ws, 2, 'Generated ' + new Date().toLocaleString() + '  ·  Role: ' + (isAdmin ? 'Admin (CISO)' : 'Information Security') + '  ·  Records: ' + assets.length, cols);
        ws.addRow([]);
    };

    // =====================================================
    // Sheet A — Asset Identification (PDF section 1+2)
    // =====================================================
    {
        const ws = wb.addWorksheet('1 — Asset Identification', { views: [{ state: 'frozen', ySplit: 4 }] });
        addBranding(ws, 11);
        const headers = ['Asset ID', 'Name of Asset', 'Description', 'Group', 'Hostname', 'Server', 'Custodian', 'IP Address', 'Environment', 'Department', 'Type'];
        const hdr = ws.addRow(headers);
        styleHeaderRow(ws, hdr.number, headers.length);
        assets.forEach(a => {
            const r = ws.addRow([a.id, a.name, a.description, a.group_name, a.hostname, a.server, a.custodian, a.ip_address, a.environment, a.department, a.type]);
            r.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            r.getCell(11).alignment = { horizontal: 'center' };
            styleBodyCells(ws, r.number, headers.length);
        });
        setCols(ws, [12, 38, 46, 18, 18, 22, 22, 16, 16, 22, 8]);
    }

    // =====================================================
    // Sheet B — Information Sensitivity & Valuation (PDF section 3)
    // =====================================================
    {
        const ws = wb.addWorksheet('2 — Sensitivity & Valuation', { views: [{ state: 'frozen', ySplit: 4 }] });
        addBranding(ws, 11);
        const headers = ['Asset ID', 'Name of Asset', 'PII', 'SPI', 'Corp Info', 'C', 'I', 'A', 'Valuation', 'Class', 'Type'];
        const hdr = ws.addRow(headers);
        styleHeaderRow(ws, hdr.number, headers.length);
        assets.forEach(a => {
            const r = ws.addRow([a.id, a.name, yn(a.pii), yn(a.spi), yn(a.corp), a.ciaC, a.ciaI, a.ciaA, a.ciaScore, a.ciaClass, a.type]);
            r.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            [3,4,5].forEach(idx => {
                r.getCell(idx).fill = ynFill(idx === 3 ? a.pii : idx === 4 ? a.spi : a.corp);
                r.getCell(idx).font = ynFont(idx === 3 ? a.pii : idx === 4 ? a.spi : a.corp);
                r.getCell(idx).alignment = { horizontal: 'center' };
            });
            [6,7,8,9].forEach(idx => { r.getCell(idx).alignment = { horizontal: 'center' }; });
            const classCell = r.getCell(10);
            const cls = (a.ciaClass || '').toLowerCase();
            let classRating = '';
            if (cls === 'restricted')      { classCell.fill = excelRiskFill('high');     classRating = 'high'; }
            else if (cls === 'confidential') { classCell.fill = excelRiskFill('moderate'); classRating = 'moderate'; }
            else if (cls === 'internal use') { classCell.fill = excelRiskFill('low');      classRating = 'low'; }
            else if (cls === 'public')       { classCell.fill = excelRiskFill('very');     classRating = 'very low'; }
            classCell.font = { bold: true, color: { argb: excelRiskTextOn(classRating) } };
            classCell.alignment = { horizontal: 'center' };
            styleBodyCells(ws, r.number, headers.length);
        });
        setCols(ws, [12, 38, 6, 6, 9, 5, 5, 5, 10, 16, 8]);
    }

    // =====================================================
    // Sheet C — Risk Assessment (PDF section 4 — IAR / Risk)
    // =====================================================
    {
        const ws = wb.addWorksheet('3 — Risk Assessment', { views: [{ state: 'frozen', ySplit: 4 }] });
        addBranding(ws, 7);
        const headers = ['Asset ID', 'Name of Asset', 'Risk / Threat Description', 'Probability', 'Severity', 'Inherent', 'Residual'];
        const hdr = ws.addRow(headers);
        styleHeaderRow(ws, hdr.number, headers.length);
        assets.forEach(a => {
            const r = ws.addRow([a.id, a.name, a.riskDesc || '', a.prob, a.sev, a.inherit, a.residual]);
            r.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            [4,5].forEach(i => { r.getCell(i).alignment = { horizontal: 'center' }; });
            const inh = r.getCell(6); inh.fill = excelRiskFill(a.inherit);  inh.font = { bold: true, color: { argb: excelRiskTextOn(a.inherit)  } }; inh.alignment = { horizontal: 'center' };
            const res = r.getCell(7); res.fill = excelRiskFill(a.residual); res.font = { bold: true, color: { argb: excelRiskTextOn(a.residual) } }; res.alignment = { horizontal: 'center' };
            styleBodyCells(ws, r.number, headers.length);
        });
        setCols(ws, [12, 38, 60, 12, 10, 12, 12]);
    }

    // =====================================================
    // Sheet D — Controls (PDF section 5 — C1..C13 + Strategy)
    // =====================================================
    {
        const ws = wb.addWorksheet('4 — Controls C1–C13', { views: [{ state: 'frozen', ySplit: 5, xSplit: 2 }] });
        addBranding(ws, 17);
        const headers = ['Asset ID', 'Name of Asset',
            'C1','C2','C3','C4','C5','C6','C7','C8','C9','C10','C11','C12','C13',
            'Residual', 'Strategy'];
        // legend row
        const legendRow = ws.addRow(['Legend',
            'C1 Documented Procedures · C2 SoD · C3 RBAC · C4 MFA · C5 Physical · C6 Backup · C7 Encryption · C8 Disposal · C9 EDR · C10 WAF · C11 Vuln/Patch · C12 VLAN · C13 IRP'
        ]);
        ws.mergeCells(legendRow.number, 2, legendRow.number, 17);
        legendRow.getCell(1).font = { bold: true, color: { argb: COL_INK_MUTED }, italic: true };
        legendRow.getCell(2).font = { italic: true, color: { argb: COL_INK_BODY }, size: 9 };
        legendRow.getCell(2).alignment = { horizontal: 'left', wrapText: true };
        legendRow.height = 22;
        const hdr = ws.addRow(headers);
        styleHeaderRow(ws, hdr.number, headers.length);
        assets.forEach(a => {
            const ctrlIds = new Set(globalControls.filter(c => c.asset_id === a.id).map(c => c.ctrl_id));
            const cells = [a.id, a.name];
            for (let i = 1; i <= 13; i++) cells.push(ctrlIds.has(i) ? 'Y' : 'N');
            cells.push(a.residual, a.actionType);
            const r = ws.addRow(cells);
            r.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            for (let i = 3; i <= 15; i++) {
                const v = r.getCell(i).value;
                r.getCell(i).fill = ynFill(v);
                r.getCell(i).font = ynFont(v);
                r.getCell(i).alignment = { horizontal: 'center' };
            }
            const res = r.getCell(16); res.fill = excelRiskFill(a.residual); res.font = { bold: true, color: { argb: excelRiskTextOn(a.residual) } }; res.alignment = { horizontal: 'center' };
            const strat = r.getCell(17);
            const map = { Mitigate: 'FF1A4D80', Transfer: 'FF6A4DBA', Avoid: 'FFB04A2E', Accept: 'FF2E7A4D' };
            strat.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: map[a.actionType] || 'FF2A2A35' } };
            strat.font = { bold: true, color: { argb: 'FFFFFFFF' } };
            strat.alignment = { horizontal: 'center' };
            styleBodyCells(ws, r.number, headers.length);
        });
        const widths = [12, 32]; for (let i = 0; i < 13; i++) widths.push(5);
        widths.push(12, 12);
        setCols(ws, widths);
    }

    // =====================================================
    // Sheet E — Residual & Treatment (PDF section 6)
    // =====================================================
    {
        const ws = wb.addWorksheet('5 — Residual & Treatment', { views: [{ state: 'frozen', ySplit: 4 }] });
        addBranding(ws, 7);
        const headers = ['Asset ID', 'Name of Asset', 'Residual', 'Strategy', 'Status', 'Action Plan', 'Action Owner', 'Target Date'];
        const hdr = ws.addRow(headers);
        styleHeaderRow(ws, hdr.number, headers.length);
        assets.forEach(a => {
            const r = ws.addRow([a.id, a.name, a.residual, a.actionType, a.actionStatus, a.actionPlan, a.actionOwner, a.actionDate]);
            r.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            const res = r.getCell(3); res.fill = excelRiskFill(a.residual); res.font = { bold: true, color: { argb: excelRiskTextOn(a.residual) } }; res.alignment = { horizontal: 'center' };
            const map = { Mitigate: 'FF1A4D80', Transfer: 'FF6A4DBA', Avoid: 'FFB04A2E', Accept: 'FF2E7A4D' };
            const strat = r.getCell(4);
            strat.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: map[a.actionType] || 'FF2A2A35' } };
            strat.font = { bold: true, color: { argb: 'FFFFFFFF' } };
            strat.alignment = { horizontal: 'center' };
            const stat = r.getCell(5);
            const sm = { Done: 'FF2E7A4D', 'In Progress': 'FF1A4D80', Pending: 'FFB04A2E' };
            stat.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: sm[a.actionStatus] || 'FF2A2A35' } };
            stat.font = { bold: true, color: { argb: 'FFFFFFFF' } };
            stat.alignment = { horizontal: 'center' };
            styleBodyCells(ws, r.number, headers.length);
        });
        setCols(ws, [12, 38, 12, 12, 14, 60, 24, 14]);
    }

    // =====================================================
    // Sheet F — Compliance Mapping (NIST / ISO / CIS / SOC 2 / PCI-DSS)
    // =====================================================
    {
        const ws = wb.addWorksheet('6 — Compliance Mapping', { views: [{ state: 'frozen', ySplit: 4 }] });
        addBranding(ws, 7);
        const headers = ['Asset ID', 'Name of Asset', 'NIST CSF', 'ISO 27001 / 27002', 'CIS Controls', 'SOC 2', 'PCI-DSS'];
        const hdr = ws.addRow(headers);
        styleHeaderRow(ws, hdr.number, headers.length);
        assets.forEach(a => {
            const ctrlIds = globalControls.filter(c => c.asset_id === a.id).map(c => c.ctrl_id);
            const fw = getFrameworksForControls(ctrlIds, a.type);
            const r = ws.addRow([a.id, a.name, fw.nist, fw.iso, fw.cis, fw.soc2, fw.pci]);
            r.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            styleBodyCells(ws, r.number, headers.length);
        });
        setCols(ws, [12, 38, 28, 32, 24, 22, 22]);
    }

    // -------- date helpers shared by both role exports below --------
    const fmtDate = (d) => {
        if (!d) return '';
        const dt = new Date(d);
        if (isNaN(dt.getTime())) return String(d);
        return dt.toISOString().slice(0, 10);
    };
    const fmtDateTime = (d) => {
        if (!d) return '';
        const dt = new Date(d);
        if (isNaN(dt.getTime())) return String(d);
        return dt.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
    };
    const todayISO = fmtDate(new Date());
    const reviewerEmail = currentUser?.email || 'admin@plm.edu.ph';

    // =====================================================
    // Sheet 7 — Rejected & Deleted (BOTH roles).
    //   Single audit view of every Reject (Pending → Draft), Draft Reject,
    //   Asset Delete, and User Reject with the captured reason in its own
    //   column. Available to both Info Sec and Admin so each role can
    //   produce evidence of due process for their scope of work.
    // =====================================================
    {
        const wsRD = wb.addWorksheet('7 — Rejected & Deleted', { views: [{ state: 'frozen', ySplit: 4 }] });
        addBranding(wsRD, 7);
        const rdHdr = wsRD.addRow(['Date / Time', 'Action', 'Subject', 'Reason', 'Originator / Target', 'Acted By', 'Prior Status']);
        styleHeaderRow(wsRD, rdHdr.number, 7);

        const rejectActions = new Set(['ASSET_REJECTED', 'DRAFT_REJECTED', 'ASSET_DELETED', 'USER_REJECTED']);
        const rdLogs = (globalLogs || []).filter(l => rejectActions.has(l.action));
        const actionLabel = {
            ASSET_REJECTED:  'Asset Rejected (returned to Draft)',
            DRAFT_REJECTED:  'Draft Rejected (discarded)',
            ASSET_DELETED:   'Asset Deleted (permanent)',
            USER_REJECTED:   'User Account Rejected',
        };
        const actionFill = {
            ASSET_REJECTED:  'FF3A2E15',
            DRAFT_REJECTED:  'FF3A1F1F',
            ASSET_DELETED:   'FF2E1A2E',
            USER_REJECTED:   'FF1A1A2E',
        };
        const actionFg = {
            ASSET_REJECTED:  'FFFFC966',
            DRAFT_REJECTED:  'FFFF8C8C',
            ASSET_DELETED:   'FFFF8C42',
            USER_REJECTED:   'FFA0A0FF',
        };

        if (!rdLogs.length) {
            const rNone = wsRD.addRow([
                todayISO, '— none —', 'No rejections or deletions recorded',
                'This audit period contains no negative actions. Every submission has been approved or is still in flight.',
                '—', '—', '—'
            ]);
            rNone.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            rNone.getCell(2).font = { italic: true, color: { argb: COL_INK_SOFT } };
            rNone.getCell(4).font = { italic: true, color: { argb: COL_INK_SOFT } };
            styleBodyCells(wsRD, rNone.number, 7);
            rNone.height = 24;
        } else {
            rdLogs.forEach(l => {
                const parsed = parseLogDetails(l.details);
                const subject = l.action === 'USER_REJECTED'
                    ? (parsed.target || 'Unknown user')
                    : (l.asset_id || '—');
                const counterParty = l.action === 'USER_REJECTED'
                    ? (`${parsed.target || '—'} (requested ${parsed.requestedRole || 'role'})`)
                    : (parsed.originator || '—');
                const r = wsRD.addRow([
                    fmtDateTime(l.created_at),
                    actionLabel[l.action] || l.action,
                    subject,
                    parsed.reason || '— no reason recorded —',
                    counterParty,
                    l.user_email || '—',
                    parsed.priorStatus || (l.action === 'ASSET_DELETED' ? 'unknown' : '—')
                ]);
                r.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
                r.getCell(2).font = { bold: true, color: { argb: actionFg[l.action] || 'FFFFFFFF' } };
                r.getCell(2).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: actionFill[l.action] || 'FF1A1A22' } };
                r.getCell(2).alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
                r.getCell(3).font = { bold: true };
                if (parsed.reason) {
                    r.getCell(4).font = { color: { argb: COL_INK_BODY } };
                } else {
                    r.getCell(4).font = { italic: true, color: { argb: COL_INK_SOFT } };
                }
                r.getCell(4).alignment = { wrapText: true, vertical: 'top' };
                r.getCell(7).alignment = { horizontal: 'center', vertical: 'middle' };
                styleBodyCells(wsRD, r.number, 7);
                r.height = Math.min(56, 22 + Math.ceil((parsed.reason || '').length / 60) * 12);
            });

            wsRD.addRow([]);
            const sumHdr = wsRD.addRow(['Summary by action', '', '', '', '', '', '']);
            styleHeaderRow(wsRD, sumHdr.number, 7);
            const counts = {};
            rdLogs.forEach(l => { counts[l.action] = (counts[l.action] || 0) + 1; });
            Object.keys(actionLabel).forEach(act => {
                if (!counts[act]) return;
                const sr = wsRD.addRow([
                    actionLabel[act], `${counts[act]} record${counts[act] === 1 ? '' : 's'}`,
                    '', '', '', '', ''
                ]);
                sr.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
                sr.getCell(2).font = { bold: true };
                styleBodyCells(wsRD, sr.number, 7);
            });
        }
        setCols(wsRD, [22, 32, 22, 56, 32, 28, 16]);
    }

    // =====================================================
    // Admin-only sheets — auto-populate from logs + stats so they
    // are never blank, while still honoring manual ReportData entries.
    // =====================================================
    if (isAdmin) {

        // Asset activity stats — used in Highlights aggregations.
        const total       = globalAssets.length;
        const exported    = assets.length;
        const approved    = globalAssets.filter(a => a.status === ASSET_STATUS.APPROVED).length;
        const pending     = globalAssets.filter(a => a.status === ASSET_STATUS.PENDING).length;
        const draft       = globalAssets.filter(a => a.status === ASSET_STATUS.DRAFT).length;
        const high        = globalAssets.filter(a => (a.residual || '').toLowerCase() === 'high').length;
        const moderate    = globalAssets.filter(a => (a.residual || '').toLowerCase() === 'moderate').length;
        const pii         = globalAssets.filter(a => a.pii === 'Y').length;
        const internet    = globalAssets.filter(a => a.environment === 'Internet Facing').length;
        const dueIn14     = globalAssets.filter(a => {
            if (!a.actionDate) return false;
            const t = new Date(a.actionDate).getTime();
            const now = Date.now();
            return t >= now && t - now <= 14 * 24 * 3600 * 1000;
        }).length;
        // Negative-action audit stats (drive sheet 8 + KPI block on Highlights)
        const cntAssetRejected = (globalLogs || []).filter(l => l.action === 'ASSET_REJECTED').length;
        const cntDraftRejected = (globalLogs || []).filter(l => l.action === 'DRAFT_REJECTED').length;
        const cntAssetDeleted  = (globalLogs || []).filter(l => l.action === 'ASSET_DELETED').length;
        const cntUserRejected  = (globalLogs || []).filter(l => l.action === 'USER_REJECTED').length;
        const negativeTotal    = cntAssetRejected + cntDraftRejected + cntAssetDeleted + cntUserRejected;

        // -----------------------------------------------------------
        // Sheet 8 — Document History (real audit trail from SystemLogs)
        // -----------------------------------------------------------
        const wsH = wb.addWorksheet('8 — Document History');
        addBranding(wsH, 5);
        const histHdr = wsH.addRow(['Date', 'Version', 'Description', 'Author', 'Approval']);
        styleHeaderRow(wsH, histHdr.number, 5);

        // 1) Manual ReportData entry (master row) if any field is filled.
        if (rep.docDate || rep.docVersion || rep.docDesc || rep.docAuthor || rep.docApproval) {
            const rManual = wsH.addRow([
                fmtDate(rep.docDate) || todayISO,
                rep.docVersion || 'v1.0.0',
                rep.docDesc    || 'Master ImpactLens Information Asset Register — current revision.',
                rep.docAuthor  || 'Information Security Office, ICTO',
                rep.docApproval|| 'CISO Approved'
            ]);
            rManual.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            rManual.getCell(2).font = { bold: true };
            styleBodyCells(wsH, rManual.number, 5);
            rManual.height = 22;
        }

        // 2) Auto-derived rows from SystemLogs (newest first).
        const trackedActions = ['ASSET_APPROVED','ASSET_REJECTED','DRAFT_REJECTED','ASSET_DELETED',
                                'ASSET_SUBMITTED_FOR_APPROVAL','ASSET_DRAFT_CREATED','ASSET_UPDATED','ASSET_CREATED',
                                'USER_APPROVED','USER_REJECTED','EXPORT_XLSX'];
        const histLogs = (globalLogs || [])
            .filter(l => trackedActions.includes(l.action))
            .slice(0, 80);
        let revCounter = histLogs.length;
        if (!histLogs.length) {
            const rEmpty = wsH.addRow([
                todayISO,
                'v1.0.0',
                'Initial issuance of the ImpactLens Information Asset Register. ' +
                `${exported} of ${total} asset records included in this export.`,
                'Information Security Office, ICTO',
                'CISO Approved'
            ]);
            rEmpty.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            styleBodyCells(wsH, rEmpty.number, 5);
            rEmpty.height = 22;
        } else {
            histLogs.forEach((l) => {
                const version = `v1.${Math.max(1, Math.floor(revCounter / 10))}.${(revCounter % 10)}`;
                revCounter--;
                let approval = 'Logged';
                if (l.action === 'ASSET_APPROVED' || l.action === 'USER_APPROVED') approval = 'Approved';
                else if (l.action === 'ASSET_REJECTED' || l.action === 'USER_REJECTED' || l.action === 'DRAFT_REJECTED') approval = 'Rejected';
                else if (l.action === 'ASSET_DELETED') approval = 'Deleted';
                else if (l.action === 'ASSET_SUBMITTED_FOR_APPROVAL') approval = 'Submitted for CISO Approval';
                else if (l.action === 'ASSET_DRAFT_CREATED') approval = 'Draft (awaiting Info Sec)';
                else if (l.action === 'EXPORT_XLSX') approval = 'Exported';
                const desc = `${l.action.replace(/_/g, ' ')}` +
                             (l.asset_id ? ` · Asset ${l.asset_id}` : '') +
                             (l.details  ? ` — ${l.details}` : '');
                const r3 = wsH.addRow([
                    fmtDateTime(l.created_at),
                    version,
                    desc,
                    l.user_email || '—',
                    approval
                ]);
                r3.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
                if (approval === 'Approved') r3.getCell(5).font = { bold: true, color: { argb: COL_OK_DARK   } };
                if (approval === 'Rejected') r3.getCell(5).font = { bold: true, color: { argb: COL_BAD_DARK  } };
                if (approval === 'Deleted')  r3.getCell(5).font = { bold: true, color: { argb: COL_WARN_DARK } };
                styleBodyCells(wsH, r3.number, 5);
            });
        }
        setCols(wsH, [22, 12, 60, 32, 30]);

        // -----------------------------------------------------------
        // Sheet 9 — Highlights (revision narrative + aggregate stats)
        // -----------------------------------------------------------
        const wsX = wb.addWorksheet('9 — Highlights');
        addBranding(wsX, 2);
        setCols(wsX, [32, 92]);

        // Revision Highlights
        const a1 = wsX.addRow(['Revision Highlights', '']); styleHeaderRow(wsX, a1.number, 2);
        const recentApproved = (globalLogs || [])
            .filter(l => l.action === 'ASSET_APPROVED')
            .slice(0, 10)
            .map(l => `• ${fmtDate(l.created_at)} — Asset ${l.asset_id || ''} approved by ${l.user_email || 'CISO'}`);
        const recentRejected = (globalLogs || [])
            .filter(l => l.action === 'ASSET_REJECTED' || l.action === 'DRAFT_REJECTED')
            .slice(0, 8)
            .map(l => {
                const p = parseLogDetails(l.details);
                const verb = l.action === 'DRAFT_REJECTED' ? 'draft rejected' : 'returned to Info Sec';
                const reasonTxt = p.reason ? ` — ${p.reason}` : ' — no reason recorded';
                return `• ${fmtDate(l.created_at)} — Asset ${l.asset_id || ''} ${verb} by ${l.user_email || 'CISO'}${reasonTxt}`;
            });
        const recentDeleted = (globalLogs || [])
            .filter(l => l.action === 'ASSET_DELETED')
            .slice(0, 6)
            .map(l => {
                const p = parseLogDetails(l.details);
                const reasonTxt = p.reason ? ` — ${p.reason}` : ' — no reason recorded';
                const prior = p.priorStatus ? ` (was ${p.priorStatus})` : '';
                return `• ${fmtDate(l.created_at)} — Asset ${l.asset_id || ''} deleted by ${l.user_email || '—'}${prior}${reasonTxt}`;
            });
        const recentSubmitted = (globalLogs || [])
            .filter(l => l.action === 'ASSET_SUBMITTED_FOR_APPROVAL')
            .slice(0, 5)
            .map(l => `• ${fmtDate(l.created_at)} — Asset ${l.asset_id || ''} submitted by ${l.user_email || 'Info Sec'}`);
        const revText = [
            rep.revHigh ? rep.revHigh.trim() : '',
            recentApproved.length ? 'Recently Approved Assets:\n' + recentApproved.join('\n') : '',
            recentSubmitted.length ? '\nRecently Submitted for Approval:\n' + recentSubmitted.join('\n') : '',
            recentRejected.length ? '\nRecently Rejected:\n' + recentRejected.join('\n') : '',
            recentDeleted.length ? '\nRecently Deleted:\n' + recentDeleted.join('\n') : ''
        ].filter(Boolean).join('\n\n') ||
            'No revisions recorded yet. This is the initial issuance of the Information Asset Register.';
        const b1 = wsX.addRow(['Narrative', revText]);
        b1.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
        b1.getCell(2).alignment = { wrapText: true, vertical: 'top' };
        styleBodyCells(wsX, b1.number, 2);
        b1.height = Math.min(220, 30 + revText.split('\n').length * 14);

        wsX.addRow([]);

        // Initial Overall Highlights — aggregate KPI snapshot
        const a2 = wsX.addRow(['Initial Overall Highlights', '']); styleHeaderRow(wsX, a2.number, 2);
        const summaryRows = [
            ['Total Asset Records',           `${total}`],
            ['Exported in This Workbook',     `${exported} (Approved + Pending Approval)`],
            ['Approved (CISO Signed)',        `${approved}`],
            ['Pending CISO Approval',         `${pending}`],
            ['In Draft (Info Sec Profiling)', `${draft}`],
            ['High Residual Risk',            `${high}`],
            ['Moderate Residual Risk',        `${moderate}`],
            ['Assets Holding PII / SPI',      `${pii}`],
            ['Internet-Facing Assets',        `${internet}`],
            ['Action Plans Due ≤ 14 Days',    `${dueIn14}`],
            ['Rejections & Deletions (audit)', `${negativeTotal} total — ${cntAssetRejected} returned, ${cntDraftRejected} draft-rejected, ${cntAssetDeleted} deleted, ${cntUserRejected} user-rejected (see sheet 7)`],
            ['Report Generated',              `${fmtDateTime(new Date())} by ${reviewerEmail}`]
        ];
        if (rep.initHigh && rep.initHigh.trim()) {
            const intro = wsX.addRow(['Executive Summary', rep.initHigh.trim()]);
            intro.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            intro.getCell(2).alignment = { wrapText: true, vertical: 'top' };
            styleBodyCells(wsX, intro.number, 2);
            intro.height = Math.min(180, 28 + rep.initHigh.split('\n').length * 14);
        }
        summaryRows.forEach(([label, value]) => {
            const r4 = wsX.addRow([label, value]);
            r4.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            r4.getCell(2).font = { bold: true };
            styleBodyCells(wsX, r4.number, 2);
            r4.height = 22;
        });

        // -----------------------------------------------------------
        // Sheet 10 — Sign Off (always populated with realistic defaults)
        // -----------------------------------------------------------
        const wsS = wb.addWorksheet('10 — Sign Off');
        addBranding(wsS, 4);
        const sHdr = wsS.addRow(['Role', 'Name', 'Title / Office', 'Date Signed']);
        styleHeaderRow(wsS, sHdr.number, 4);

        const signRows = [
            [
                'Prepared By',
                rep.prepName  || 'Information Security Officer',
                rep.prepTitle || 'Information Security Office, ICTO — Pamantasan ng Lungsod ng Maynila',
                rep.docDate ? fmtDate(rep.docDate) : todayISO
            ],
            [
                'Reviewed By',
                rep.revName  || 'Risk Management Committee Chair',
                rep.revTitle || 'Office of the Vice President for Administration',
                rep.docDate ? fmtDate(rep.docDate) : todayISO
            ],
            [
                'Approved By',
                rep.appName  || (isAdmin ? reviewerEmail : 'Chief Information Security Officer'),
                rep.appTitle || 'Chief Information Security Officer (CISO) — Pamantasan ng Lungsod ng Maynila',
                rep.docDate ? fmtDate(rep.docDate) : todayISO
            ]
        ];
        signRows.forEach(rowVals => {
            const r2 = wsS.addRow(rowVals);
            r2.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            r2.getCell(2).font = { bold: true };
            r2.getCell(4).alignment = { horizontal: 'center', vertical: 'middle' };
            styleBodyCells(wsS, r2.number, 4);
            r2.height = 28;
        });

        // Signature block — visible "X______" placeholder lines underneath.
        wsS.addRow([]);
        const sigHdr = wsS.addRow(['Signatures', '', '', '']);
        styleHeaderRow(wsS, sigHdr.number, 4);
        signRows.forEach(([role, name]) => {
            const blank = wsS.addRow([role, '_______________________________', name, '_____________']);
            blank.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            blank.getCell(2).alignment = { vertical: 'middle' };
            blank.getCell(4).alignment = { horizontal: 'center', vertical: 'middle' };
            styleBodyCells(wsS, blank.number, 4);
            blank.height = 32;
        });

        wsS.addRow([]);
        const noteRow = wsS.addRow(['Note', 'Manual entries on the ImpactLens Reporting & Sign-offs page override these defaults at the next export.', '', '']);
        wsS.mergeCells(noteRow.number, 2, noteRow.number, 4);
        noteRow.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
        noteRow.getCell(2).font = { italic: true, color: { argb: COL_INK_SOFT } };
        styleBodyCells(wsS, noteRow.number, 4);

        setCols(wsS, [16, 36, 52, 18]);
    }

    // ---------- write ----------
    const buffer = await wb.xlsx.writeBuffer();
    const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    const stamp = new Date().toISOString().slice(0,10);
    const roleSlug = isAdmin ? 'Admin-CISO' : 'InfoSec';
    link.download = `ImpactLens_IAR_${roleSlug}_${stamp}.xlsx`;
    link.click();
    URL.revokeObjectURL(url);
    await logSystemEvent('EXPORT_XLSX', `Exported ${assets.length} assets (${roleSlug} template)`);
    notify(`Exported ${assets.length} assets — ${isAdmin ? 'Admin (full audit)' : 'Info Sec (audit + working set)'} template.`);
}

// ==========================================
// 8. INITIALIZATION
// ==========================================
(async function initApp() {
    if (!supabaseClient) {
        showAuthScreen();
        return;
    }

    const { data: { session } } = await supabaseClient.auth.getSession();
    if (session) await enterAuthenticatedApp(session);
    else showAuthScreen();

    supabaseClient.auth.onAuthStateChange(async (event, session) => {
        if (event === 'INITIAL_SESSION') return;
        if (event === 'SIGNED_IN' && session) {
            await enterAuthenticatedApp(session);
            return;
        }
        if (event === 'TOKEN_REFRESHED' && session?.access_token) {
            currentAccessToken = session.access_token;
            return;
        }
        if (event === 'SIGNED_OUT' || (event === 'TOKEN_REFRESHED' && !session)) {
            currentUser = null;
            currentRole = null;
            currentAccessToken = null;
            authUiReady = false;
            if (suppressAuthReset) {
                // The auth screen / error banner is already being managed by the
                // caller (e.g. role-mismatch path in enterAuthenticatedApp).
                document.getElementById('app-shell')?.classList.add('hidden');
                document.getElementById('auth-screen')?.classList.remove('hidden');
                return;
            }
            showAuthScreen();
        }
    });
})();

window.handleLogin = handleLogin;
window.handleLogout = handleLogout;
window.handleRegister = handleRegister;
window.showAuthTab = showAuthTab;
window.resendVerificationEmail = resendVerificationEmail;
window.resetAuthSteps = resetAuthSteps;

// Inline-handler exports (defensive — also auto-bound by browsers, but explicit avoids edge cases)
window.saveAssetToDB        = saveAssetToDB;
window.editAsset            = editAsset;
window.deleteAsset          = deleteAsset;
window.approveAsset         = approveAsset;
window.rejectAsset          = rejectAsset;
window.rejectDraftAsset     = rejectDraftAsset;
window.promptReason         = promptReason;
window.showSection          = showSection;
window.runEnforcementEngine = runEnforcementEngine;
window.applyRiskTemplate    = applyRiskTemplate;
window.updateTags           = updateTags;
window.removeTag            = removeTag;
window.clearForm            = clearForm;
window.exportDataXLSX       = exportDataXLSX;
window.setSaveStatus        = setSaveStatus;

function togglePassword(btn) {
    const id = btn?.dataset?.target;
    if (!id) return;
    const input = document.getElementById(id);
    if (!input) return;
    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';
    btn.textContent = isHidden ? 'Hide' : 'Show';
    btn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
    btn.setAttribute('aria-pressed', String(isHidden));
}
window.togglePassword = togglePassword;
window.approveUserAccount = approveUserAccount;
window.rejectUserAccount = rejectUserAccount;