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

/** Redirect URL after email verification — must be listed in Supabase Auth → URL Configuration. */
function getAuthRedirectUrl() {
    const { origin } = window.location;
    return origin.replace(/\/$/, '') + '/';
}

/** Remove Supabase auth blobs from localStorage — local session only; keeps unrelated keys. */
function clearSupabasePersistedSession() {
    try {
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            if (k && (k.startsWith('sb-') || k.startsWith('supabase.'))) keys.push(k);
        }
        keys.forEach(k => localStorage.removeItem(k));
    } catch (e) { console.warn('clearSupabasePersistedSession:', e); }
}

/** True when this document load was reached via browser Back/Forward (history). */
function wasHistoryNavigation() {
    try {
        const n = performance.getEntriesByType?.('navigation')?.[0];
        return !!(n && (n.type === 'back_forward'));
    } catch (_) { return false; }
}

/** OTP / magic-link / hash-token flows — do not purge session on history navigation. */
function urlHasAuthHandshakeParams() {
    try {
        const q = window.location.search || '';
        const h = window.location.hash || '';
        return /(?:^|[?&#])(?:token_hash|access_token|refresh_token|code)=/i.test(q + h);
    } catch (_) { return false; }
}

const IMPACTLENS_HISTORY_SIGNOUT_NOTICE_KEY = 'impactlens_notice_history_return';
/** Toast after session was cleared because the document was reached via browser history (Back/Forward). */
const HISTORY_RETURN_SECURITY_SIGNOUT_MSG =
    'You were signed out automatically for security after using the browser Back button. Sign in again to continue.';

function stripAuthParamsFromUrl() {
    try {
        const url = new URL(window.location.href);
        ['token_hash', 'type', 'access_token', 'refresh_token', 'expires_in', 'token_type'].forEach(k => {
            url.searchParams.delete(k);
        });
        const hash = url.hash.replace(/^#/, '');
        if (hash) {
            const hp = new URLSearchParams(hash);
            ['access_token', 'refresh_token', 'type', 'token_hash', 'expires_in', 'token_type'].forEach(k => hp.delete(k));
            url.hash = hp.toString() ? '#' + hp.toString() : '';
        }
        window.history.replaceState({}, document.title, url.pathname + url.search + url.hash);
    } catch (_) { /* noop */ }
}

/** Completes PKCE email-confirmation links (?token_hash=…&type=signup). */
async function handleAuthCallbackFromUrl() {
    if (!supabaseClient) return false;
    const params = new URLSearchParams(window.location.search);
    const token_hash = params.get('token_hash');
    const type = params.get('type');
    if (!token_hash || !type) return false;

    const allowed = new Set(['signup', 'email', 'recovery', 'invite', 'magiclink', 'email_change']);
    const otpType = allowed.has(type) ? type : 'email';

    const { data, error } = await supabaseClient.auth.verifyOtp({ token_hash, type: otpType });
    stripAuthParamsFromUrl();
    if (error) {
        notify(formatAuthError(error), true);
        showAuthScreen();
        return false;
    }
    if (data?.session) {
        notify('Email verified — welcome to ImpactLens.');
        await enterAuthenticatedApp(data.session);
        return true;
    }
    notify('Email verified. Sign in with your password.');
    showAuthScreen();
    showAuthTab('login');
    return true;
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
let globalUserProfiles = [];
let usersActiveTab = 'pending';
let editingId = null;
/** @type {Array<object>} Persisted scenarios (see migrateLegacyToRiskScenarios). */
let assetRiskScenarios = [];
let currentRiskScenarioIx = 0;
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

/** CIA dimensions use ISO 27005 / NIST SP 800-60 style 1–5 impact scale (not 1–3). */
const CIA_SCALE_MAX = 5;

function clampCia(v) {
    const n = parseInt(String(v), 10);
    return Math.max(1, Math.min(CIA_SCALE_MAX, isNaN(n) ? 3 : n));
}

/** Spread legacy 1–3 stored values onto 1–5 when loading older records. */
function normalizeCiaStored(v) {
    const n = parseInt(String(v), 10);
    if (isNaN(n)) return 3;
    if (n <= 3) return [2, 3, 5][Math.max(0, n - 1)];
    return clampCia(n);
}

function ciaMax(c, i, a) {
    return Math.max(clampCia(c), clampCia(i), clampCia(a));
}

function ciaSum(c, i, a) {
    return clampCia(c) + clampCia(i) + clampCia(a);
}

/** Classification label from highest CIA dimension (avoids sum-only mis-tiering, e.g. all 2s). */
function ciaClassFromValues(c, i, a) {
    const m = ciaMax(c, i, a);
    if (m <= 1) return 'Public';
    if (m <= 2) return 'Internal Use';
    if (m <= 3) return 'Confidential';
    return 'Restricted';
}

/** Back-compat for CSV paths that still pass a legacy sum score. */
function ciaClassFromLegacyScore(score) {
    const s = parseInt(String(score), 10);
    if (isNaN(s)) return 'Internal Use';
    if (s <= 3) return 'Public';
    if (s <= 5) return 'Internal Use';
    if (s <= 7) return 'Confidential';
    return 'Restricted';
}

function band15(v) {
    return Math.max(1, Math.min(5, parseInt(String(v), 10) || 3));
}

/** Map legacy 1–3 hostility / exposure bands to 1–5. */
function normalizeBand15(v) {
    const n = parseInt(String(v), 10);
    if (isNaN(n)) return 3;
    if (n <= 3) return [2, 3, 4][Math.max(0, n - 1)];
    return band15(n);
}

function bandDeltaFromCenter(band, center = 3) {
    return band15(band) - center;
}

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

function rollupWorstResidualRating(vals) {
  const arr = vals && vals.length ? vals : ['Moderate'];
  return arr.reduce((w, x) =>
    RESIDUAL_FLOOR_RANK[x || 'Very Low'] > RESIDUAL_FLOOR_RANK[w] ? (x || 'Very Low') : w
    , 'Very Low');
}

function rollupWorstInherentRatings(vals) {
  const arr = vals && vals.length ? vals : ['Moderate'];
  return arr.reduce((w, x) =>
    RESIDUAL_FLOOR_RANK[x || 'Very Low'] > RESIDUAL_FLOOR_RANK[w] ? (x || 'Very Low') : w
    , 'Very Low');
}

function worstScenarioForReporting(scenarios) {
  if (!scenarios.length) return null;
  let w = scenarios[0];
  let rk = RESIDUAL_FLOOR_RANK[w.residual || 'Very Low'];
  scenarios.forEach(sc => {
    const r = RESIDUAL_FLOOR_RANK[sc.residual || 'Very Low'];
    const inhCmp = RESIDUAL_FLOOR_RANK[sc.inherit || 'Very Low'] - RESIDUAL_FLOOR_RANK[w.inherit || 'Very Low'];
    if (r > rk || (r === rk && inhCmp > 0)) {
      w = sc;
      rk = r;
    }
  });
  return w;
}

function rollupScenarioWorstHeatmapAxes(scenarios) {
  if (!scenarios || !scenarios.length) return null;
  let w = scenarios[0];
  let wr = RESIDUAL_FLOOR_RANK[w.inherit || 'Very Low'];
  scenarios.forEach(sc => {
    const r = RESIDUAL_FLOOR_RANK[sc.inherit || 'Very Low'];
    const prod = (Number(sc.prob) || 3) * (Number(sc.sev) || 3);
    const wp = (Number(w.prob) || 3) * (Number(w.sev) || 3);
    if (r > wr || (r === wr && prod > wp)) {
      w = sc;
      wr = r;
    }
  });
  return w;
}

/** PCI-DSS v4 floor applies only to FA assets that process CHD or are cyber/payment-exposed — not petty-cash ledgers. */
function isPciInScopeFaAsset(ctx, threatKey) {
    const t = String(threatKey || '').trim().toLowerCase();
    if (ctx.environment === 'Internet Facing') return true;
    if (t.startsWith('cyber_')) return true;
    if (/pay|bank|gateway|card|pci|unauth|supply|leak|ddos|vuln|legal_dpa/.test(t)) return true;
    return false;
}

/** Resolve which mandatory baselines apply to the current asset state. */
function getApplicableMandatorySets(ctx, threatKey) {
    const sets = [];
    const ciaMaxVal = ciaMax(parseInt(ctx.c) || 0, parseInt(ctx.i) || 0, parseInt(ctx.a) || 0);
    const digitalTypes = new Set(['IA', 'SA', 'SV', 'FA']);
    if (digitalTypes.has(ctx.type)) {
        if (ciaMaxVal >= 4)            sets.push({ key: 'restrictedClass', ...MANDATORY_CONTROLS.restrictedClass });
        else if (ciaMaxVal >= 3)       sets.push({ key: 'confidentialClass', ...MANDATORY_CONTROLS.confidentialClass });
    }
    if (ctx.type === 'FA' && isPciInScopeFaAsset(ctx, threatKey)) {
        sets.push({ key: 'fa', ...MANDATORY_CONTROLS.fa });
    }
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

/** Valid register types (profiles no longer dictate CIA — assessors justify ratings in §02). */
const ALLOWED_ASSET_TYPES = new Set(['IA', 'PhA', 'PA', 'SA', 'SV', 'FA']);

/** Initial qualitative anchors when a threat taxonomy row is picked (editable; feeds likelihood/impact before escalations). */
const RISK_QUALITATIVE_DEFAULTS = {
    phys_theft:       { likelihood_qual: 3, impact_qual: 4 },
    phys_destruct:    { likelihood_qual: 2, impact_qual: 5 },
    hr_insider:       { likelihood_qual: 3, impact_qual: 4 },
    hr_accidental:    { likelihood_qual: 4, impact_qual: 3 },
    cyber_ext_ransomware: { likelihood_qual: 4, impact_qual: 5 },
    cyber_ext_leak:   { likelihood_qual: 3, impact_qual: 5 },
    cyber_ext_ddos:   { likelihood_qual: 3, impact_qual: 3 },
    cyber_ext_supply: { likelihood_qual: 2, impact_qual: 4 },
    cyber_int_unauth: { likelihood_qual: 3, impact_qual: 5 },
    cyber_int_vuln:   { likelihood_qual: 4, impact_qual: 4 },
    legal_dpa:        { likelihood_qual: 3, impact_qual: 5 }
};

/** Quick-select phrases for Info Sec / Admin ISRA narrative guides (UI-only; persisted text stays in risk_basis). */
const ISRA_GUIDE_PHRASES = {
    threat_actor: {
        external: 'An external threat actor may target this asset through opportunistic or targeted means',
        insider: 'An insider with legitimate access could misuse privileges or exfiltrate data',
        supplier: 'A third-party supplier or integrated SaaS provider could be compromised and affect this asset',
        user_error: 'User error or social engineering could lead to unintended disclosure or modification',
        physical: 'Physical theft, tampering, or facility disruption could affect this asset',
    },
    threat_path: {
        network: 'via exposed network services, weak perimeter controls, or internet-facing interfaces',
        credential: 'via stolen credentials, weak authentication, or shared administrative accounts',
        misconfig: 'by exploiting misconfiguration, excessive permissions, or missing hardening baselines',
        endpoint: 'through compromised endpoints, malware, or unpatched server/workstation vulnerabilities',
        process: 'through process gaps such as weak change control, incomplete offboarding, or manual workarounds',
    },
    vuln_gap: {
        patch: 'Patch and vulnerability management gaps leave known weaknesses unaddressed beyond agreed SLA',
        access: 'Access-control weaknesses include broad RBAC, stale accounts, or missing MFA on privileged use',
        logging: 'Insufficient logging, monitoring, or detection reduces visibility of abuse or exfiltration',
        encrypt: 'Encryption or data-protection controls are incomplete for data at rest or in transit',
        backup: 'Backup, recovery, or resilience testing gaps increase impact if compromise or loss occurs',
    },
    vuln_scope: {
        localized: 'The gap appears localized to this asset or workload rather than enterprise-wide',
        systemic: 'Similar gaps were noted across comparable systems or peer reviews flagged recurring exposure',
        remediating: 'Remediation is in progress; residual weakness remains until verification closes the finding',
    },
    occ_signal: {
        rare: 'No known organizational incidents for this scenario; likelihood is anchored conservatively from peer-sector trends',
        peer: 'Comparable higher-ed or sector incidents suggest this scenario is plausible within twelve months',
        tested: 'Recent assurance activity (vulnerability scan, audit, or tabletop) found conditions that increase likelihood',
        seasonal: 'Seasonal peaks such as enrollment, payroll, or exams increase transaction volume and exposure',
        trending: 'Threat intelligence or regulatory enforcement trends elevate the expected frequency of this scenario',
    },
    occ_prior: {
        N: 'Internal incident register shows no matching prior event for this scenario',
        Y: 'A prior incident or near-miss was recorded for this or a comparable system',
        U: 'Incident tracking is incomplete; occurrence is treated as uncertain pending register review',
    },
};

/** Suggested guide picks + bands when a risk taxonomy row is chosen. */
const ISRA_GUIDE_DEFAULTS = {
    phys_theft:       { actor: 'physical', path: 'process', gap: 'access', scope: 'localized', signal: 'rare', prior: 'N', threat_band: 3, vuln_band: 3 },
    phys_destruct:    { actor: 'physical', path: 'process', gap: 'backup', scope: 'localized', signal: 'rare', prior: 'N', threat_band: 2, vuln_band: 3 },
    hr_insider:       { actor: 'insider', path: 'credential', gap: 'access', scope: 'systemic', signal: 'peer', prior: 'N', threat_band: 4, vuln_band: 3 },
    hr_accidental:    { actor: 'user_error', path: 'process', gap: 'backup', scope: 'localized', signal: 'tested', prior: 'N', threat_band: 3, vuln_band: 3 },
    cyber_ext_ransomware: { actor: 'external', path: 'endpoint', gap: 'patch', scope: 'systemic', signal: 'trending', prior: 'N', threat_band: 4, vuln_band: 4 },
    cyber_ext_leak:   { actor: 'external', path: 'network', gap: 'encrypt', scope: 'systemic', signal: 'peer', prior: 'N', threat_band: 4, vuln_band: 4 },
    cyber_ext_ddos:   { actor: 'external', path: 'network', gap: 'logging', scope: 'localized', signal: 'trending', prior: 'N', threat_band: 4, vuln_band: 3 },
    cyber_ext_supply: { actor: 'supplier', path: 'process', gap: 'access', scope: 'systemic', signal: 'peer', prior: 'U', threat_band: 3, vuln_band: 3 },
    cyber_int_unauth: { actor: 'external', path: 'credential', gap: 'access', scope: 'localized', signal: 'tested', prior: 'N', threat_band: 4, vuln_band: 4 },
    cyber_int_vuln:   { actor: 'external', path: 'misconfig', gap: 'patch', scope: 'systemic', signal: 'tested', prior: 'N', threat_band: 4, vuln_band: 4 },
    legal_dpa:        { actor: 'external', path: 'process', gap: 'encrypt', scope: 'systemic', signal: 'trending', prior: 'N', threat_band: 3, vuln_band: 4 },
};

const ISRA_GUIDE_SELECT_IDS = [
    'f-guide-occ-signal', 'f-guide-occ-prior',
];

function resetIsraGuideSelects() {
    ISRA_GUIDE_SELECT_IDS.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
}

function setIsraGuideSelect(id, value) {
    const el = document.getElementById(id);
    if (!el || value == null || value === '') return;
    if ([...el.options].some(o => o.value === value)) el.value = value;
}

function applyIsraGuideDefaultsForCategory(categoryKey) {
    const defs = ISRA_GUIDE_DEFAULTS[categoryKey];
    if (!defs) return;
    setIsraGuideSelect('f-guide-occ-signal', defs.signal);
    setIsraGuideSelect('f-guide-occ-prior', defs.prior);
    syncPriorIncidentsFromGuide();
    israPendingTemplateGuides = {
        actor: defs.actor,
        path: defs.path,
        gap: defs.gap,
        scope: defs.scope,
        signal: defs.signal,
        prior: defs.prior,
        threat_band: defs.threat_band ?? 3,
        vuln_band: defs.vuln_band ?? 3,
    };
}

function markIsraNarrativeManual(textareaId) {
    const el = document.getElementById(textareaId);
    if (el) el.dataset.israGuided = '';
}

function setGuidedTextarea(id, text) {
    const el = document.getElementById(id);
    if (!el) return;
    const trimmed = String(text || '').trim();
    if (!trimmed) return;
    if (el.dataset.israGuided === '1' || !String(el.value || '').trim()) {
        el.value = trimmed;
        el.dataset.israGuided = '1';
    }
}

function setGuidedRowStatement(row, text) {
    if (!row) return;
    const ta = row.querySelector('[data-field="statement"]');
    if (!ta) return;
    const trimmed = String(text || '').trim();
    if (!trimmed) return;
    if (ta.dataset.israGuided === '1' || !String(ta.value || '').trim()) {
        ta.value = trimmed;
        ta.dataset.israGuided = '1';
    }
}

function syncPriorIncidentsFromGuide() {
    const priorGuide = document.getElementById('f-guide-occ-prior')?.value || '';
    const priorEl = document.getElementById('f-prior-incidents');
    if (!priorEl || !priorGuide) return;
    if (['N', 'Y', 'U'].includes(priorGuide)) priorEl.value = priorGuide;
}

function applyIsraNarrativeGuides() {
    syncPriorIncidentsFromGuide();
    const threatRow = document.querySelector('#isra-threats-list .isra-multi-row');
    const vulnRow = document.querySelector('#isra-vulns-list .isra-multi-row');
    if (threatRow) composeIsraRowFromGuides('threat', parseInt(threatRow.dataset.rowIx || '0', 10));
    if (vulnRow) composeIsraRowFromGuides('vuln', parseInt(vulnRow.dataset.rowIx || '0', 10));

    const signalKey = document.getElementById('f-guide-occ-signal')?.value || '';
    const priorKey = document.getElementById('f-guide-occ-prior')?.value || '';
    if (signalKey || priorKey) {
        const signal = ISRA_GUIDE_PHRASES.occ_signal[signalKey] || '';
        const prior = ISRA_GUIDE_PHRASES.occ_prior[priorKey] || '';
        const occParts = [signal, prior].filter(Boolean);
        if (occParts.length) {
            setGuidedTextarea('f-occurrence-justification', `${occParts.join('; ')}.`);
        }
    }

    updateIsraBandSummary();
    runEnforcementEngine(true);
}

function updateIsraBandSummary() {
    const el = document.getElementById('isra-band-summary');
    if (!el) return;
    const threats = collectThreatsFromDom();
    const vulns = collectVulnsFromDom();
    const tb = threats.length ? Math.max(...threats.map(t => band15(t.band))) : 3;
    const vb = vulns.length ? Math.max(...vulns.map(v => band15(v.band))) : 3;
    el.textContent = `Worst threat band ${tb} and weakness band ${vb} (1–5, ISO 27005-aligned) feed inherent P/S — add rows as needed.`;
}

let israPendingTemplateGuides = null;

function defaultThreatEntry() {
    return { band: 3, actor: '', path: '', statement: '' };
}

function defaultVulnEntry() {
    return { band: 3, gap: '', scope: '', statement: '' };
}

function normalizeThreatsArray(basis) {
    basis = basis && typeof basis === 'object' ? basis : {};
    if (Array.isArray(basis.threats) && basis.threats.length) {
        return basis.threats.map(t => ({
            band: normalizeBand15(t.band ?? t.threat_choice ?? basis.threat_choice ?? 3),
            actor: t.actor || '',
            path: t.path || '',
            statement: String(t.statement || '').trim(),
        }));
    }
    const stmt = String(basis.threat_statement || '').trim();
    if (stmt || basis.threat_choice != null) {
        return [{ band: normalizeBand15(basis.threat_choice ?? 3), actor: '', path: '', statement: stmt }];
    }
    return [defaultThreatEntry()];
}

function normalizeVulnsArray(basis) {
    basis = basis && typeof basis === 'object' ? basis : {};
    if (Array.isArray(basis.vulnerabilities) && basis.vulnerabilities.length) {
        return basis.vulnerabilities.map(v => ({
            band: normalizeBand15(v.band ?? v.vulnerability_choice ?? basis.vulnerability_choice ?? 3),
            gap: v.gap || '',
            scope: v.scope || '',
            statement: String(v.statement || '').trim(),
        }));
    }
    const stmt = String(basis.vulnerability_statement || '').trim();
    if (stmt || basis.vulnerability_choice != null) {
        return [{ band: normalizeBand15(basis.vulnerability_choice ?? 3), gap: '', scope: '', statement: stmt }];
    }
    return [defaultVulnEntry()];
}

function joinThreatStatements(threats) {
    return (threats || []).map(t => String(t.statement || '').trim()).filter(Boolean).join(' | ');
}

function joinVulnStatements(vulns) {
    return (vulns || []).map(v => String(v.statement || '').trim()).filter(Boolean).join(' | ');
}

function maxThreatBand(threats) {
    const arr = threats && threats.length ? threats : [defaultThreatEntry()];
    return Math.max(...arr.map(t => band15(t.band)));
}

function maxVulnBand(vulns) {
    const arr = vulns && vulns.length ? vulns : [defaultVulnEntry()];
    return Math.max(...arr.map(v => band15(v.band)));
}

function israActorOptions(selected) {
    const opts = [
        ['', 'Guide — threat actor…'],
        ['external', 'External attacker'],
        ['insider', 'Insider with access'],
        ['supplier', 'Third-party / supplier'],
        ['user_error', 'User error / social engineering'],
        ['physical', 'Physical / facility'],
    ];
    return opts.map(([v, l]) => `<option value="${escapeHtmlSafe(v)}"${v === selected ? ' selected' : ''}>${escapeHtmlSafe(l)}</option>`).join('');
}

function israPathOptions(selected) {
    const opts = [
        ['', 'Guide — attack path…'],
        ['network', 'Exposed services / perimeter'],
        ['credential', 'Stolen creds / weak auth'],
        ['misconfig', 'Misconfiguration / excess permissions'],
        ['endpoint', 'Endpoint malware / unpatched host'],
        ['process', 'Process / change-control gap'],
    ];
    return opts.map(([v, l]) => `<option value="${escapeHtmlSafe(v)}"${v === selected ? ' selected' : ''}>${escapeHtmlSafe(l)}</option>`).join('');
}

function israGapOptions(selected) {
    const opts = [
        ['', 'Guide — weakness…'],
        ['patch', 'Patch / vuln management gap'],
        ['access', 'RBAC / MFA / stale accounts'],
        ['logging', 'Logging / monitoring gap'],
        ['encrypt', 'Encryption / DLP gap'],
        ['backup', 'Backup / recovery gap'],
    ];
    return opts.map(([v, l]) => `<option value="${escapeHtmlSafe(v)}"${v === selected ? ' selected' : ''}>${escapeHtmlSafe(l)}</option>`).join('');
}

function israScopeOptions(selected) {
    const opts = [
        ['', 'Guide — scope…'],
        ['localized', 'Localized to this asset'],
        ['systemic', 'Across comparable systems'],
        ['remediating', 'Fix in progress'],
    ];
    return opts.map(([v, l]) => `<option value="${escapeHtmlSafe(v)}"${v === selected ? ' selected' : ''}>${escapeHtmlSafe(l)}</option>`).join('');
}

function israThreatBandOptions(selected) {
    const labels = {
        1: '1 — Rare / no credible adversary',
        2: '2 — Unlikely targeted interest',
        3: '3 — Moderate (generic abuse)',
        4: '4 — High (capable adversary)',
        5: '5 — Critical (targeted / insider abuse)',
    };
    return [1, 2, 3, 4, 5].map(v => `<option value="${v}"${String(v) === String(selected) ? ' selected' : ''}>${labels[v]}</option>`).join('');
}

function israVulnBandOptions(selected) {
    const labels = {
        1: '1 — Hardened / minimal gaps',
        2: '2 — Low residual exposure',
        3: '3 — Moderate weaknesses',
        4: '4 — Material control gaps',
        5: '5 — Critical exposure',
    };
    return [1, 2, 3, 4, 5].map(v => `<option value="${v}"${String(v) === String(selected) ? ' selected' : ''}>${labels[v]}</option>`).join('');
}

function renderIsraThreatRow(entry, ix) {
    return `<div class="isra-multi-row" data-row-ix="${ix}">
    <div class="isra-multi-row-head">
      <span class="isra-multi-row-label">Threat #${ix + 1}</span>
      <button type="button" class="btn btn-sm isra-row-remove" onclick="removeIsraThreatRow(${ix})" title="Remove threat">Remove</button>
    </div>
    <div class="isra-guide-row grid-3">
      <select data-field="band" class="isra-guide-select" onchange="updateIsraBandSummary(); runEnforcementEngine(true);">${israThreatBandOptions(entry.band)}</select>
      <select data-field="actor" class="isra-guide-select" onchange="composeIsraRowFromGuides('threat', ${ix})">${israActorOptions(entry.actor)}</select>
      <select data-field="path" class="isra-guide-select" onchange="composeIsraRowFromGuides('threat', ${ix})">${israPathOptions(entry.path)}</select>
    </div>
    <textarea data-field="statement" rows="2" class="isra-row-statement" placeholder="Threat narrative (guides draft this row)." data-isra-guided="" oninput="this.dataset.israGuided=''; runEnforcementEngine(true);">${escapeHtmlSafe(entry.statement || '')}</textarea>
  </div>`;
}

function renderIsraVulnRow(entry, ix) {
    return `<div class="isra-multi-row" data-row-ix="${ix}">
    <div class="isra-multi-row-head">
      <span class="isra-multi-row-label">Weakness #${ix + 1}</span>
      <button type="button" class="btn btn-sm isra-row-remove" onclick="removeIsraVulnRow(${ix})" title="Remove weakness">Remove</button>
    </div>
    <div class="isra-guide-row grid-3">
      <select data-field="band" class="isra-guide-select" onchange="updateIsraBandSummary(); runEnforcementEngine(true);">${israVulnBandOptions(entry.band)}</select>
      <select data-field="gap" class="isra-guide-select" onchange="composeIsraRowFromGuides('vuln', ${ix})">${israGapOptions(entry.gap)}</select>
      <select data-field="scope" class="isra-guide-select" onchange="composeIsraRowFromGuides('vuln', ${ix})">${israScopeOptions(entry.scope)}</select>
    </div>
    <textarea data-field="statement" rows="2" class="isra-row-statement" placeholder="Weakness narrative (guides draft this row)." data-isra-guided="" oninput="this.dataset.israGuided=''; runEnforcementEngine(true);">${escapeHtmlSafe(entry.statement || '')}</textarea>
  </div>`;
}

function renderIsraThreatVulnPanels(basis) {
    const threats = normalizeThreatsArray(basis);
    const vulns = normalizeVulnsArray(basis);
    const tList = document.getElementById('isra-threats-list');
    const vList = document.getElementById('isra-vulns-list');
    if (tList) tList.innerHTML = threats.map((t, i) => renderIsraThreatRow(t, i)).join('');
    if (vList) vList.innerHTML = vulns.map((v, i) => renderIsraVulnRow(v, i)).join('');
    if (israPendingTemplateGuides) {
        const g = israPendingTemplateGuides;
        const tRow = document.querySelector('#isra-threats-list .isra-multi-row');
        const vRow = document.querySelector('#isra-vulns-list .isra-multi-row');
        if (tRow) {
            const bandEl = tRow.querySelector('[data-field="band"]');
            if (bandEl) bandEl.value = String(g.threat_band ?? 3);
            const aEl = tRow.querySelector('[data-field="actor"]');
            const pEl = tRow.querySelector('[data-field="path"]');
            if (aEl && g.actor) aEl.value = g.actor;
            if (pEl && g.path) pEl.value = g.path;
        }
        if (vRow) {
            const bandEl = vRow.querySelector('[data-field="band"]');
            if (bandEl) bandEl.value = String(g.vuln_band ?? 3);
            const gEl = vRow.querySelector('[data-field="gap"]');
            const sEl = vRow.querySelector('[data-field="scope"]');
            if (gEl && g.gap) gEl.value = g.gap;
            if (sEl && g.scope) sEl.value = g.scope;
        }
        setIsraGuideSelect('f-guide-occ-signal', g.signal);
        setIsraGuideSelect('f-guide-occ-prior', g.prior);
        israPendingTemplateGuides = null;
        composeIsraRowFromGuides('threat', 0);
        composeIsraRowFromGuides('vuln', 0);
        applyIsraNarrativeGuides();
    }
    updateIsraBandSummary();
}

function collectThreatsFromDom() {
    const rows = document.querySelectorAll('#isra-threats-list .isra-multi-row');
    const out = [];
    rows.forEach(row => {
        out.push({
            band: band15(row.querySelector('[data-field="band"]')?.value),
            actor: row.querySelector('[data-field="actor"]')?.value || '',
            path: row.querySelector('[data-field="path"]')?.value || '',
            statement: (row.querySelector('[data-field="statement"]')?.value || '').trim(),
        });
    });
    return out.length ? out : [defaultThreatEntry()];
}

function collectVulnsFromDom() {
    const rows = document.querySelectorAll('#isra-vulns-list .isra-multi-row');
    const out = [];
    rows.forEach(row => {
        out.push({
            band: band15(row.querySelector('[data-field="band"]')?.value),
            gap: row.querySelector('[data-field="gap"]')?.value || '',
            scope: row.querySelector('[data-field="scope"]')?.value || '',
            statement: (row.querySelector('[data-field="statement"]')?.value || '').trim(),
        });
    });
    return out.length ? out : [defaultVulnEntry()];
}

function composeIsraRowFromGuides(kind, ix) {
    const listId = kind === 'threat' ? 'isra-threats-list' : 'isra-vulns-list';
    const row = document.querySelector(`#${listId} .isra-multi-row[data-row-ix="${ix}"]`);
    if (!row) return;
    const desc = (document.getElementById('f-risk-desc')?.value || '').trim()
        || (RISK_TEMPLATES[g('f-risk-category')]?.desc || 'this asset');
    if (kind === 'threat') {
        const actorKey = row.querySelector('[data-field="actor"]')?.value || '';
        const pathKey = row.querySelector('[data-field="path"]')?.value || '';
        const actor = ISRA_GUIDE_PHRASES.threat_actor[actorKey] || '';
        const path = ISRA_GUIDE_PHRASES.threat_path[pathKey] || '';
        const parts = [actor, path].filter(Boolean);
        if (parts.length) setGuidedRowStatement(row, `${parts.join(' ')} for ${desc}.`);
    } else {
        const gapKey = row.querySelector('[data-field="gap"]')?.value || '';
        const scopeKey = row.querySelector('[data-field="scope"]')?.value || '';
        const gap = ISRA_GUIDE_PHRASES.vuln_gap[gapKey] || '';
        const scope = ISRA_GUIDE_PHRASES.vuln_scope[scopeKey] || '';
        const parts = [gap, scope].filter(Boolean);
        if (parts.length) setGuidedRowStatement(row, `${parts.join('; ')}.`);
    }
    runEnforcementEngine(true);
}

function addIsraThreatRow() {
    const threats = collectThreatsFromDom();
    threats.push(defaultThreatEntry());
    renderIsraThreatVulnPanels({ threats, vulnerabilities: collectVulnsFromDom() });
    runEnforcementEngine(true);
}

function removeIsraThreatRow(ix) {
    const threats = collectThreatsFromDom();
    if (threats.length <= 1) return notify('At least one threat row is required.', true);
    threats.splice(ix, 1);
    renderIsraThreatVulnPanels({ threats, vulnerabilities: collectVulnsFromDom() });
    runEnforcementEngine(true);
}

function addIsraVulnRow() {
    const vulns = collectVulnsFromDom();
    vulns.push(defaultVulnEntry());
    renderIsraThreatVulnPanels({ threats: collectThreatsFromDom(), vulnerabilities: vulns });
    runEnforcementEngine(true);
}

function removeIsraVulnRow(ix) {
    const vulns = collectVulnsFromDom();
    if (vulns.length <= 1) return notify('At least one weakness row is required.', true);
    vulns.splice(ix, 1);
    renderIsraThreatVulnPanels({ threats: collectThreatsFromDom(), vulnerabilities: vulns });
    runEnforcementEngine(true);
}

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
    // GUARDRAIL 1: CLASSIFICATION — assessor-led (ISO / RA 10173 / internal policy).
    // Standard Users do not edit §02; neutral defaults persist until Info Sec validates.
    // ---------------------------------------------------------
    const lockC = document.getElementById('lock-c');
    const lockI = document.getElementById('lock-i');
    const lockA = document.getElementById('lock-a');
    const elevate = currentRole === 'infosec' || currentRole === 'admin';

    ['f-pii', 'f-spi', 'f-corp', 'f-c', 'f-i', 'f-a'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.disabled = !elevate || !type;
    });
    ['f-q-disclosure-impact', 'f-q-integrity-impact', 'f-q-availability-impact', 'f-q-personal-scope', 'f-q-corp-strategic'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.disabled = !elevate || !type;
    });

    if (env === 'Internet Facing') {
        const elA = document.getElementById('f-a');
        if (elA && elevate) {
            elA.value = String(Math.max(4, parseInt(elA.value, 10) || 4));
        }
    }

    if (lockC) lockC.textContent = elevate ? 'Assessor' : '';
    if (lockI) lockI.textContent = elevate ? 'Assessor' : '';
    if (lockA) {
        lockA.textContent = !elevate
            ? ''
            : env === 'Internet Facing'
                ? 'Min. 4 — Internet-facing floor'
                : 'Assessor';
    }

    const c = clampCia(g('f-c'));
    const i = clampCia(g('f-i'));
    const a = clampCia(g('f-a'));
    const cMax = ciaMax(c, i, a);
    const cSum = c + i + a;
    const classEl = document.getElementById('cia-class');
    if (classEl) classEl.textContent = `${ciaClassFromValues(c, i, a)} (max ${cMax} · sum ${cSum})`;

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
    const relevantUnion = relevanceUnionForConfiguredScenarios();
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
    getApplicableMandatorySets(mandatoryCtx, g('f-risk-category') || '').forEach(set => set.ids.forEach(id => mandatoryIds.add(id)));

    for (let i = 1; i <= 13; i++) {
        const cb = document.getElementById('ctrl' + i);
        const label = cb ? cb.parentElement : null;
        if (!cb || !label) continue;
        const isRelevant  = relevantUnion.has(i);
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

/** MBSS + perimeter form fields for evidence linkage (operational alignment with C1–C13). */
function readMbssFirewallEvidenceFromForm() {
    const yn = id => {
        const el = document.getElementById(id);
        if (!el) return 'N';
        return (el.value || '').trim() === 'Y' ? 'Y' : 'N';
    };
    return {
        edr_epp: yn('f-mbss-edr'),
        patch_current: yn('f-mbss-patch'),
        disk_encryption: yn('f-mbss-disk'),
        host_firewall: yn('f-mbss-hostfw'),
        admin_priv_review: yn('f-mbss-admin'),
        fw_scope: (document.getElementById('f-fw-scope')?.value || '').trim(),
        fw_default_deny: yn('f-fw-defaultdeny'),
        fw_change: yn('f-fw-change'),
        fw_logging: yn('f-fw-logging'),
        fw_permissive: yn('f-fw-permissive'),
    };
}

/**
 * Evidence multiplier for *checked* controls only — strengthens P/S reduction when MBSS / perimeter
 * answers support the same control family (no extra reduction for evidence alone).
 */
function mbssFwEvidenceMultiplierForControl(ctrlId, ev) {
    const y = x => x === 'Y';
    let m = 1;
    switch (ctrlId) {
        case 9:
            if (y(ev.edr_epp)) m = 1.18;
            break;
        case 11:
            if (y(ev.patch_current)) m = 1.15;
            break;
        case 7:
            if (y(ev.disk_encryption)) m = 1.12;
            break;
        case 10: {
            let bonus = 0;
            if (y(ev.host_firewall)) bonus += 0.07;
            if (y(ev.fw_default_deny) && y(ev.fw_logging) && !y(ev.fw_permissive)) bonus += 0.12;
            else if (y(ev.fw_default_deny) || y(ev.fw_logging)) bonus += 0.05;
            if (ev.fw_scope && ev.fw_scope !== 'None documented') bonus += 0.04;
            m = 1 + Math.min(bonus, 0.2);
            if (y(ev.fw_permissive)) m *= 0.9;
            break;
        }
        case 3:
            if (y(ev.admin_priv_review)) m = 1.1;
            break;
        default:
            break;
    }
    return m;
}

/** Surface mismatches between operational evidence and implemented-control checkboxes. */
function collectMbssFwAlignmentMessages(active, ev) {
    const activeSet = new Set(active);
    const y = x => x === 'Y';
    const out = [];
    if (y(ev.edr_epp) && !activeSet.has(9)) out.push('MBSS: EDR/EPP = Y but Control 9 (EDR) is not selected — tick C9 or correct MBSS.');
    if (activeSet.has(9) && !y(ev.edr_epp)) out.push('Control 9 (EDR) is selected but MBSS EDR/EPP = N — align evidence or clear C9.');

    if (y(ev.patch_current) && !activeSet.has(11)) out.push('MBSS: Patch current = Y but Control 11 (Vulnerability management) is not selected — align or correct MBSS.');
    if (activeSet.has(11) && !y(ev.patch_current)) out.push('Control 11 is selected but MBSS Patch current = N — align evidence or clear C11.');

    if (y(ev.disk_encryption) && !activeSet.has(7)) out.push('MBSS: Disk encryption = Y but Control 7 (Encryption) is not selected — align or correct MBSS.');
    if (activeSet.has(7) && !y(ev.disk_encryption)) out.push('Control 7 is selected but MBSS Disk encryption = N — align evidence or clear C7.');

    if (y(ev.host_firewall) && !activeSet.has(10)) out.push('MBSS: Host firewall = Y but Control 10 (Firewall/WAF) is not selected — align or correct MBSS.');
    const fwPerimeterSignal = y(ev.fw_default_deny) || y(ev.fw_logging) || !!(ev.fw_scope && ev.fw_scope !== 'None documented');
    if (activeSet.has(10) && !y(ev.host_firewall) && !fwPerimeterSignal) {
        out.push('Control 10 is on but MBSS host firewall = N and perimeter review lacks default deny, logging, or documented scope — complete evidence or adjust C10.');
    }

    if (y(ev.admin_priv_review) && !activeSet.has(3)) out.push('MBSS: Admin privilege review = Y but Control 3 (RBAC) is not selected — align or correct MBSS.');
    if (activeSet.has(3) && !y(ev.admin_priv_review)) out.push('Control 3 (RBAC) is selected but MBSS Admin review = N — align evidence or clear C3.');

    if (y(ev.fw_permissive) && activeSet.has(10)) {
        out.push('Perimeter review: Overly permissive rules = Y while Control 10 is on — evidence multiplier is reduced; remediate rule hygiene.');
    }
    return out;
}

function renderMbssFirewallAlignmentPanel(messages) {
    let panel = document.getElementById('mbss-fw-align-panel');
    if (!panel) {
        const compEl = document.getElementById('compliance-mapping-panel');
        if (!compEl || !compEl.parentNode) return;
        panel = document.createElement('div');
        panel.id = 'mbss-fw-align-panel';
        panel.className = 'compliance-panel mbss-fw-align-panel hidden';
        compEl.parentNode.insertBefore(panel, compEl);
    }
    const showRole = currentRole === 'infosec' || currentRole === 'admin';
    if (!showRole || !messages || !messages.length) {
        panel.classList.add('hidden');
        panel.innerHTML = '';
        return;
    }
    panel.innerHTML = `
      <label style="margin-top:12px;display:block;color:var(--accent2);">MBSS / firewall ↔ implemented controls</label>
      <div class="gap-summary">Evidence <strong>amplifies</strong> P/S reduction only for controls you already selected when MBSS and perimeter fields support them. Use the list below to keep the narrative and the math consistent.</div>
      <ul class="gap-list">${messages.map(m => `<li>${escapeHtmlSafe(m)}</li>`).join('')}</ul>`;
    panel.classList.remove('hidden');
}

function controlIdsForThreatKey(threat) {
    const ids = controlMap[threat] || [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    return new Set(ids);
}

/** Union relevance across all drafted scenarios so implemented controls persist when profiling several risks per asset. */
function relevanceUnionForConfiguredScenarios() {
    const catsAll = [];
    if (assetRiskScenarios.length) assetRiskScenarios.forEach(sc => catsAll.push(String(sc.riskCategory || '').trim()));
    const uniq = [...new Set(catsAll.filter(Boolean))];
    const cats = uniq.length ? uniq : [String(g('f-risk-category') || '').trim()];
    const u = new Set();
    cats.forEach(t => controlIdsForThreatKey(t || '').forEach(id => u.add(id)));
    if (!u.size) [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13].forEach(i => u.add(i));
    return u;
}

function anchorsFromRiskBasisPayload(basis) {
    basis = basis && typeof basis === 'object' ? basis : {};
    const threats = normalizeThreatsArray(basis);
    const vulns = normalizeVulnsArray(basis);
    const lk = Math.max(1, Math.min(5, parseInt(basis.likelihood_qual ?? 3, 10)));
    const iq = Math.max(1, Math.min(5, parseInt(basis.impact_qual ?? 3, 10)));
    let p = lk;
    const prior = String(basis.prior_incidents || 'N').trim().toUpperCase();
    if (prior === 'Y') p = Math.min(5, p + 1);
    const thr = joinThreatStatements(threats);
    const vul = joinVulnStatements(vulns);
    const occ = String(basis.occurrence_justification || '').trim();
    let s = iq;
    if (thr.length < 24 || vul.length < 24) {
        if (thr.length >= 24) p = Math.max(p, 2);
        if (vul.length >= 24) s = Math.max(s, 2);
    } else {
        if (vul.length >= 180) s = Math.min(5, s + 1);
        if (thr.length >= 140) p = Math.min(5, Math.max(p, 3));
        if ((occ.includes('historic') || occ.includes('prior') || occ.includes('happened')) && prior !== 'Y')
            p = Math.min(5, p + 1);
        if (/annual|regular|recent incident|past breach/i.test(occ)) p = Math.min(5, p + 1);
    }

    const tband = maxThreatBand(threats);
    const vband = maxVulnBand(vulns);
    p = Math.max(1, Math.min(5, p + bandDeltaFromCenter(tband, 3)));
    s = Math.max(1, Math.min(5, s + bandDeltaFromCenter(vband, 3)));

    return { p: Math.max(1, Math.min(5, p)), s: Math.max(1, Math.min(5, s)) };
}

function defaultRiskBasisObject() {
    return {
        threats: [defaultThreatEntry()],
        vulnerabilities: [defaultVulnEntry()],
        threat_statement: '',
        vulnerability_statement: '',
        occurrence_justification: '',
        likelihood_qual: 3,
        impact_qual: 3,
        prior_incidents: 'N',
        threat_choice: 3,
        vulnerability_choice: 3,
    };
}

function blankRiskScenario() {
    return {
        id: 'rs-' + Math.random().toString(36).slice(2, 11),
        riskCategory: '',
        riskDesc: '',
        risk_basis: defaultRiskBasisObject(),
        prob: 3,
        sev: 3,
        inherit: 'Moderate',
        residual: 'Moderate',
        resProb: 3,
        resSev: 3,
        actionType: 'Mitigate',
        actionStatus: 'Pending',
        actionPlan: '',
        actionOwner: '',
        actionDate: '',
    };
}

function parseAssetRiskScenariosArray(rawJson) {
    try {
        const v = typeof rawJson === 'string' ? JSON.parse(rawJson || 'null') : rawJson;
        if (Array.isArray(v) && v.length) return v;
    } catch (_) { /* noop */ }
    return null;
}

/** Worst residual across roll-up column and per-scenario JSON (matches save-time rollup). */
function effectiveAssetResidual(asset) {
    const sc = parseAssetRiskScenariosArray(asset?.asset_risks_json);
    if (sc && sc.length) {
        const repr = worstScenarioForReporting(sc);
        return repr?.residual || asset?.residual || 'Moderate';
    }
    return rollupWorstResidualRating([asset?.residual].filter(Boolean));
}

function effectiveAssetInherent(asset) {
    const sc = parseAssetRiskScenariosArray(asset?.asset_risks_json);
    if (sc && sc.length) {
        const repr = worstScenarioForReporting(sc);
        return repr?.inherit || asset?.inherit || 'Moderate';
    }
    return rollupWorstInherentRatings([asset?.inherit].filter(Boolean));
}

/** Single paired scenario for register / export (inherent + residual + P×S stay aligned). */
function effectiveAssetReportingScenario(asset) {
    const sc = parseAssetRiskScenariosArray(asset?.asset_risks_json);
    if (sc && sc.length) {
        const repr = worstScenarioForReporting(sc);
        if (repr) return repr;
    }
    return {
        prob: asset?.prob,
        sev: asset?.sev,
        inherit: asset?.inherit,
        residual: asset?.residual,
        resProb: asset?.resProb,
        resSev: asset?.resSev,
    };
}

function parsedRiskScenarioCountForAsset(asset) {
    const p = parseAssetRiskScenariosArray(asset?.asset_risks_json);
    return p ? p.length : 1;
}

function normalizeImportedRiskScenarioRow(row) {
    const sc = blankRiskScenario();
    if (row && typeof row === 'object') {
        if (row.id) sc.id = String(row.id);
        sc.riskCategory = row.riskCategory ?? row.risk_category ?? '';
        sc.riskDesc = row.riskDesc ?? row.risk_desc ?? '';
        const rbIn = row.risk_basis && typeof row.risk_basis === 'object' ? row.risk_basis : {};
        sc.risk_basis = { ...defaultRiskBasisObject(), ...rbIn };
        sc.risk_basis.threats = normalizeThreatsArray(sc.risk_basis);
        sc.risk_basis.vulnerabilities = normalizeVulnsArray(sc.risk_basis);
        sc.risk_basis.threat_statement = joinThreatStatements(sc.risk_basis.threats);
        sc.risk_basis.vulnerability_statement = joinVulnStatements(sc.risk_basis.vulnerabilities);
        sc.risk_basis.threat_choice = maxThreatBand(sc.risk_basis.threats);
        sc.risk_basis.vulnerability_choice = maxVulnBand(sc.risk_basis.vulnerabilities);
        sc.actionType = row.actionType ?? row.action_type ?? 'Mitigate';
        sc.actionStatus = row.actionStatus ?? row.action_status ?? 'Pending';
        sc.actionPlan = row.actionPlan ?? row.action_plan ?? '';
        sc.actionOwner = row.actionOwner ?? row.action_owner ?? '';
        sc.actionDate = row.actionDate ?? row.action_date ?? '';
        if (row.prob != null) sc.prob = row.prob;
        if (row.sev != null) sc.sev = row.sev;
        if (row.inherit) sc.inherit = row.inherit;
        if (row.residual) sc.residual = row.residual;
        if (row.resProb != null) sc.resProb = row.resProb;
        if (row.resSev != null) sc.resSev = row.resSev;
    }
    return sc;
}

function migrateLegacyToRiskScenarios(asset) {
    const parsed = parseAssetRiskScenariosArray(asset.asset_risks_json);
    if (parsed) return parsed.map(normalizeImportedRiskScenarioRow);
    const legacyBasis = parseJsonSafe(asset.risk_basis_json || '{}', {});
    const rb = typeof legacyBasis === 'object' && legacyBasis !== null ? { ...defaultRiskBasisObject(), ...legacyBasis } : defaultRiskBasisObject();
    rb.threats = normalizeThreatsArray(rb);
    rb.vulnerabilities = normalizeVulnsArray(rb);
    rb.threat_statement = joinThreatStatements(rb.threats);
    rb.vulnerability_statement = joinVulnStatements(rb.vulnerabilities);
    rb.threat_choice = maxThreatBand(rb.threats);
    rb.vulnerability_choice = maxVulnBand(rb.vulnerabilities);
    const sc = blankRiskScenario();
    sc.id = 'rs-legacy';
    sc.riskCategory = asset.riskCategory ?? '';
    sc.riskDesc = asset.riskDesc ?? '';
    sc.risk_basis = rb;
    sc.actionType = asset.actionType ?? 'Mitigate';
    sc.actionStatus = asset.actionStatus ?? 'Pending';
    sc.actionPlan = asset.actionPlan ?? '';
    sc.actionOwner = asset.actionOwner ?? '';
    sc.actionDate = asset.actionDate ?? '';
    if (asset.prob != null) sc.prob = asset.prob;
    if (asset.sev != null) sc.sev = asset.sev;
    if (asset.inherit) sc.inherit = asset.inherit;
    if (asset.residual) sc.residual = asset.residual;
    return [sc];
}

function getActiveCheckboxCtrlIdsFromForm() {
    const active = [];
    for (let i = 1; i <= 13; i++) {
        const cb = document.getElementById('ctrl' + i);
        if (cb && cb.checked && !cb.disabled) active.push(i);
    }
    return active;
}

function gatherAssetResidualCtxFromStored(asset) {
    const active = globalControls.filter(c => c.asset_id === asset.id).map(c => c.ctrl_id);
    let mbss = {};
    let fw = {};
    try { mbss = parseJsonSafe(asset.mbss_json, {}) || {}; } catch (_) { /* noop */ }
    try { fw = parseJsonSafe(asset.firewall_json, {}) || {}; } catch (_) { /* noop */ }
    return {
        env: asset.environment,
        currentPii: asset.pii,
        currentSpi: asset.spi,
        type: asset.type,
        cVal: normalizeCiaStored(asset.ciaC),
        iVal: normalizeCiaStored(asset.ciaI),
        aVal: normalizeCiaStored(asset.ciaA),
        active,
        mbssFwEv: { mbss, fw },
    };
}

/** Live engine pass for register rows — uses actual controls, not stale DB columns. */
function liveRegisterMetricsForAsset(asset) {
    const ctx = gatherAssetResidualCtxFromStored(asset);
    let scenarios = parseAssetRiskScenariosArray(asset.asset_risks_json);
    if (!scenarios || !scenarios.length) {
        const rb = { ...defaultRiskBasisObject(), ...parseJsonSafe(asset.risk_basis_json, {}) };
        scenarios = [{
            riskCategory: (asset.riskCategory || '').split('|')[0].trim(),
            riskDesc: asset.riskDesc || '',
            risk_basis: rb,
            prob: parseInt(asset.prob, 10) || 3,
            sev: parseInt(asset.sev, 10) || 3,
        }];
    }
    const computed = scenarios.map(sc => {
        const row = {
            ...sc,
            risk_basis: { ...defaultRiskBasisObject(), ...(sc.risk_basis && typeof sc.risk_basis === 'object' ? sc.risk_basis : {}) },
        };
        const bundle = computeResidualBundleForScenario(row, ctx);
        return {
            ...row,
            prob: bundle.p,
            sev: bundle.s,
            inherit: bundle.inherentRating,
            residual: bundle.residualRating,
            resProb: bundle.resP,
            resSev: bundle.resSev,
            controlGaps: bundle.gaps || [],
        };
    });
    return worstScenarioForReporting(computed) || computed[0];
}

function isElevatedResidualTier(tier) {
    return tier === 'High' || tier === 'Moderate';
}

function liveAssetResidualTier(asset) {
    return liveRegisterMetricsForAsset(asset).residual || effectiveAssetResidual(asset);
}

function liveAssetInherentTier(asset) {
    return liveRegisterMetricsForAsset(asset).inherit || effectiveAssetInherent(asset);
}

function assetRequiresActionPlan(asset) {
    return isElevatedResidualTier(liveAssetResidualTier(asset)) && asset.actionType !== 'Accept';
}

function approvedElevatedAssets() {
    return approvedAssetsOnly().filter(a => isElevatedResidualTier(liveAssetResidualTier(a)));
}

function approvedAssetsRequiringActionPlan() {
    return approvedAssetsOnly().filter(assetRequiresActionPlan);
}

function gatherAssetResidualCtxFromDom() {
    const env = g('f-environment');
    const currentPii = g('f-pii');
    const currentSpi = g('f-spi');
    const type = g('f-type');
    const cVal = parseInt(g('f-c')) || 0;
    const iVal = parseInt(g('f-i')) || 0;
    const aVal = parseInt(g('f-a')) || 0;
    const active = getActiveCheckboxCtrlIdsFromForm();
    const mbssFwEv = readMbssFirewallEvidenceFromForm();
    return { env, currentPii, currentSpi, type, cVal, iVal, aVal, active, mbssFwEv };
}

function flushCurrentRiskScenarioSnapshot() {
    if (!assetRiskScenarios.length) assetRiskScenarios.push(blankRiskScenario());
    if (currentRiskScenarioIx < 0 || currentRiskScenarioIx >= assetRiskScenarios.length) currentRiskScenarioIx = 0;
    const ix = currentRiskScenarioIx;
    const cur = { ...assetRiskScenarios[ix] };
    cur.riskCategory = g('f-risk-category');
    cur.riskDesc = g('f-risk-desc');
    cur.risk_basis = normalizeRiskBasisForPersist();
    cur.actionType = g('f-action-type');
    cur.actionStatus = g('f-action-status');
    cur.actionPlan = g('f-action-plan');
    cur.actionOwner = g('f-action-owner');
    cur.actionDate = g('f-action-date');
    assetRiskScenarios[ix] = cur;
}

/** Load one scenario's structured fields onto the DOM (scenario switch). */
function applyRiskScenarioToForm(sc) {
    if (!sc) return;
    const setSel = (id, v) => { const el = document.getElementById(id); if (el !== null && v !== undefined && v !== null) el.value = v; };
    setSel('f-risk-category', sc.riskCategory || '');
    setSel('f-risk-desc', sc.riskDesc || '');
    const rb = { ...defaultRiskBasisObject(), ...(sc.risk_basis && typeof sc.risk_basis === 'object' ? sc.risk_basis : {}) };
    loadRiskBasisToForm(rb);
    setSel('f-action-type', sc.actionType || 'Mitigate');
    setSel('f-action-status', sc.actionStatus || 'Pending');
    setSel('f-action-plan', sc.actionPlan || '');
    setSel('f-action-owner', sc.actionOwner || '');
    setSel('f-action-date', sc.actionDate || '');
}

function assignResidualMetricsOntoScenario(scenario, bundle) {
    scenario.prob = bundle.p;
    scenario.sev = bundle.s;
    scenario.inherit = bundle.inherentRating;
    scenario.residual = bundle.residualRating;
    scenario.resProb = bundle.resP;
    scenario.resSev = bundle.resSev;
}

function computeResidualBundleForScenario(scenario, assetCtx) {
    const anch = anchorsFromRiskBasisPayload(scenario.risk_basis);
    let p = anch.p;
    let s = anch.s;
    const threat = String(scenario.riskCategory || '').trim();
    const { env, currentPii, currentSpi, type, cVal, iVal, aVal, active, mbssFwEv } = assetCtx;
    const ciaScore = ciaMax(cVal, iVal, aVal);

    if (env === 'Internet Facing' && threat.startsWith('cyber_ext')) p = Math.min(5, p + 1);
    if ((currentPii === 'Y' || currentSpi === 'Y') && (threat === 'cyber_ext_leak' || threat === 'legal_dpa')) s = 5;
    if (ciaScore >= 4 && (threat.startsWith('cyber_') || threat === 'hr_insider')) s = Math.max(s, 4);
    if (type === 'FA' && threat.startsWith('cyber_')) s = 5;
    if (env === 'Internet Facing' && threat.startsWith('cyber_ext')) p = Math.max(p, 3);

    const inherentRating = INHERIT[s + '-' + p] || 'Moderate';

    const relevantSet = controlIdsForThreatKey(threat);
    const activeRelevant = active.filter(id => relevantSet.has(id));

    let pRedRaw = 0, sRedRaw = 0, evidenceBoostedCtrlCount = 0;
    activeRelevant.forEach(id => {
        const wgt = CONTROL_WEIGHTS[id] || { p: 0, s: 0 };
        const evMult = mbssFwEvidenceMultiplierForControl(id, mbssFwEv);
        if (evMult > 1.001) evidenceBoostedCtrlCount++;
        pRedRaw += wgt.p * evMult;
        sRedRaw += wgt.s * evMult;
    });
    const appliedSynergies = [];
    CONTROL_SYNERGIES.forEach(syn => {
        if (syn.ids.every(id => activeRelevant.includes(id))) {
            pRedRaw += syn.pBonus;
            sRedRaw += syn.sBonus;
            appliedSynergies.push(syn.label);
        }
    });
    const dimReturn = (raw, max) => {
        if (raw <= 0) return 0;
        const cap = Math.max(0, max - 1);
        const reduction = cap * (1 - Math.exp(-raw / 2.0));
        return Math.min(cap, reduction);
    };
    const pRed = dimReturn(pRedRaw, p);
    const sRed = dimReturn(sRedRaw, s);
    let resP = Math.max(1, Math.round(p - pRed));
    let resS = Math.max(1, Math.round(s - sRed));
    let residualRating = INHERIT[resS + '-' + resP] || 'Low';

    const mandatorySets = getApplicableMandatorySets(
        { type, c: cVal, i: iVal, a: aVal, pii: currentPii, spi: currentSpi, environment: env },
        threat
    );
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
        if (highestFloor === 'High') { resP = Math.max(resP, 4); resS = Math.max(resS, 4); }
        else if (highestFloor === 'Moderate') { resP = Math.max(resP, 3); resS = Math.max(resS, 3); }
        else if (highestFloor === 'Low') { resP = Math.max(resP, 2); resS = Math.max(resS, 2); }
    }
    if (!gaps.length && RESIDUAL_FLOOR_RANK[residualRating] > RESIDUAL_FLOOR_RANK[inherentRating]) {
        residualRating = inherentRating;
    }

    return {
        p,
        s,
        inherentRating,
        resP,
        resS,
        residualRating,
        appliedSynergies,
        evidenceBoostedCtrlCount,
        gaps,
        mandatorySets,
        activeRelevant,
        relevantSetSize: relevantSet.size,
        threat,
    };
}

/** Snapshot current textarea → scenarios[], compute metrics for all scenarios sharing the asset control profile. */
function ensureScenarioResidualsPersistedAndComputed() {
    flushCurrentRiskScenarioSnapshot();
    const ctx = gatherAssetResidualCtxFromDom();
    let currentBundle = null;
    assetRiskScenarios.forEach((sc, i) => {
        const b = computeResidualBundleForScenario(sc, ctx);
        assignResidualMetricsOntoScenario(sc, b);
        if (i === currentRiskScenarioIx) currentBundle = b;
    });
    const fallbackBundle = computeResidualBundleForScenario(assetRiskScenarios[0], ctx);
    return { bundle: currentBundle || fallbackBundle, ctx };
}

function updateRiskScenarioToolbarLabels() {
    const sumEl = document.getElementById('risk-scenario-summary');
    const rollEl = document.getElementById('risk-rollup-residual');
    if (sumEl && assetRiskScenarios.length) {
        sumEl.textContent = `${assetRiskScenarios.length} scenario${assetRiskScenarios.length === 1 ? '' : 's'} · viewing #${currentRiskScenarioIx + 1}`;
    }
    if (rollEl) {
        const wr = rollupWorstResidualRating(assetRiskScenarios.map(sc => sc.residual));
        const wi = rollupWorstInherentRatings(assetRiskScenarios.map(sc => sc.inherit));
        rollEl.textContent = `${wi} inherent (worst) · ${wr} residual (worst) · ${assetRiskScenarios.length} scenario(s)`;
    }
}

function renderRiskScenarioTabsUi() {
    const host = document.getElementById('risk-scenario-tabs');
    if (!host || !assetRiskScenarios.length) return;
    host.innerHTML = assetRiskScenarios.map((_, i) =>
        `<button type="button" class="risk-sc-tab${i === currentRiskScenarioIx ? ' risk-sc-tab--active' : ''}" data-rs-ix="${i}" onclick="switchRiskScenarioIndex(${i})">#${i + 1}</button>`
    ).join('');
}

function switchRiskScenarioIndex(ix) {
    if (typeof ix !== 'number' || ix === currentRiskScenarioIx) return;
    if (ix < 0 || ix >= assetRiskScenarios.length) return;
    flushCurrentRiskScenarioSnapshot();
    currentRiskScenarioIx = ix;
    applyRiskScenarioToForm(assetRiskScenarios[ix]);
    renderRiskScenarioTabsUi();
    updateRiskScenarioToolbarLabels();
    runEnforcementEngine(false);
}

function addRiskScenario() {
    flushCurrentRiskScenarioSnapshot();
    assetRiskScenarios.push(blankRiskScenario());
    currentRiskScenarioIx = assetRiskScenarios.length - 1;
    applyRiskScenarioToForm(assetRiskScenarios[currentRiskScenarioIx]);
    renderRiskScenarioTabsUi();
    updateRiskScenarioToolbarLabels();
    notify('Additional risk scenario — select category + ISRA narratives for each scenario.');
    runEnforcementEngine(false);
}

function removeCurrentRiskScenario() {
    if (assetRiskScenarios.length <= 1) {
        notify('Each asset keeps at least one risk scenario.', true);
        return;
    }
    flushCurrentRiskScenarioSnapshot();
    assetRiskScenarios.splice(currentRiskScenarioIx, 1);
    if (currentRiskScenarioIx >= assetRiskScenarios.length) currentRiskScenarioIx = assetRiskScenarios.length - 1;
    applyRiskScenarioToForm(assetRiskScenarios[currentRiskScenarioIx]);
    renderRiskScenarioTabsUi();
    updateRiskScenarioToolbarLabels();
    runEnforcementEngine(false);
}

function calculateRiskMath() {
    syncInherentAnchorsFromRiskBasis();

    let { bundle, ctx } = ensureScenarioResidualsPersistedAndComputed();

    let p = bundle.p;
    let s = bundle.s;
    const inherentRating = bundle.inherentRating;
    const probDisp = document.getElementById('f-prob-display');
    const sevDisp = document.getElementById('f-sev-display');
    const probH = document.getElementById('f-prob');
    const sevH = document.getElementById('f-sev');
    if (probH) probH.value = String(p);
    if (sevH) sevH.value = String(s);
    if (probDisp) probDisp.value = String(p);
    if (sevDisp) sevDisp.value = String(s);
    const rEl = document.getElementById('r-inherit');
    if (rEl) { rEl.textContent = inherentRating; rEl.style.color = riskColor(inherentRating); }

    let resP = bundle.resP;
    let resS = bundle.resS;
    const residualRating = bundle.residualRating;
    let appliedSynergies = bundle.appliedSynergies;
    let evidenceBoostedCtrlCount = bundle.evidenceBoostedCtrlCount;
    const gaps = bundle.gaps;
    const mandatorySets = bundle.mandatorySets;
    const activeRelevant = bundle.activeRelevant;
    const relevantSetSize = bundle.relevantSetSize;
    const active = ctx.active;
    const mbssFwEv = ctx.mbssFwEv;

    const worstResidualOverall = rollupWorstResidualRating(assetRiskScenarios.map(sc => sc.residual));

    const resEl = document.getElementById('r-residual');
    if (resEl) {
        resEl.textContent = residualRating;
        resEl.style.color = riskColor(residualRating);
    }

    const resProbDisp = document.getElementById('f-res-prob-display');
    const resSevDisp = document.getElementById('f-res-sev-display');
    if (resProbDisp) resProbDisp.value = String(resP);
    if (resSevDisp) resSevDisp.value = String(resS);

    const fbEl = document.getElementById('control-feedback');
    if (fbEl) {
        const synTxt = appliedSynergies.length ? ` · synergy: ${appliedSynergies.join(', ')}` : '';
        const evTxt = evidenceBoostedCtrlCount ? ` · MBSS/perimeter evidence reinforces ${evidenceBoostedCtrlCount} applied control(s)` : '';
        const rollHint = assetRiskScenarios.length > 1 ? ` · rollup worst residual: ${worstResidualOverall}` : '';
        fbEl.textContent = `Scenario #${currentRiskScenarioIx + 1}: (${activeRelevant.length} of ${relevantSetSize} mitigating controls for this scenario${synTxt})${evTxt}${rollHint}`;
    }

    renderRiskScenarioTabsUi();
    updateRiskScenarioToolbarLabels();

    const type = ctx.type;
    const actTypeSelect = document.getElementById('f-action-type');
    const lockTreat = document.getElementById('lock-treat');

    if (actTypeSelect) {
        Array.from(actTypeSelect.options).forEach(opt => opt.disabled = false);
        let lockMsg = '';
        const optAccept = Array.from(actTypeSelect.options).find(o => o.value === 'Accept');

        if (worstResidualOverall === 'High') {
            if (optAccept) optAccept.disabled = true;
            if (actTypeSelect.value === 'Accept') actTypeSelect.value = 'Mitigate';
            lockMsg = 'Cannot Accept while any scenario remains High residual (outside appetite)';
        } else if (type === 'FA' && worstResidualOverall !== 'Low' && worstResidualOverall !== 'Very Low') {
            if (optAccept) optAccept.disabled = true;
            if (actTypeSelect.value === 'Accept') actTypeSelect.value = 'Mitigate';
            lockMsg = 'PCI-DSS scoped (FA) — Accept blocked unless every scenario is Low / Very Low residual';
        } else if (ciaMax(ctx.cVal, ctx.iVal, ctx.aVal) >= 4 && worstResidualOverall === 'Moderate') {
            if (optAccept) optAccept.disabled = true;
            if (actTypeSelect.value === 'Accept') actTypeSelect.value = 'Mitigate';
            lockMsg = 'Restricted-class asset — Accept blocked while any Moderate scenario remains';
        }
        if (lockTreat) lockTreat.textContent = lockMsg ? '🔒 ' + lockMsg : '';
    }

    const apSection = document.getElementById('action-plan-section');
    const rollResidual = rollupWorstResidualRating(assetRiskScenarios.map(rs => rs.residual));
    if (apSection && actTypeSelect) {
        const hidePrimary = actTypeSelect.value === 'Accept' || rollResidual === 'Very Low';
        apSection.style.display = hidePrimary ? 'none' : 'block';
    }

    renderComplianceMapping();
    renderControlGapAnalysis(gaps, mandatorySets);
    renderMbssFirewallAlignmentPanel(collectMbssFwAlignmentMessages(active, mbssFwEv));
    syncMbssFirewallScoreMirrors();
    syncMbssFirewallSectionState();
    updateIsraBandSummary();
}

function applyRiskTemplate(skipEngineUpdate = false) {
    const key = g('f-risk-category');
    if (RISK_TEMPLATES[key]) {
        const descEl = document.getElementById('f-risk-desc');
        const apEl = document.getElementById('f-action-plan');
        if (descEl) descEl.value = RISK_TEMPLATES[key].desc;
        const defQ = RISK_QUALITATIVE_DEFAULTS[key];
        if (defQ) {
            const lq = document.getElementById('f-likelihood-qual');
            const iq = document.getElementById('f-impact-qual');
            if (lq) lq.value = String(Math.max(1, Math.min(5, defQ.likelihood_qual)));
            if (iq) iq.value = String(Math.max(1, Math.min(5, defQ.impact_qual)));
        }
        if (apEl && !apEl.value) apEl.value = RISK_TEMPLATES[key].action;
        applyIsraGuideDefaultsForCategory(key);
        renderIsraThreatVulnPanels({
            threats: [defaultThreatEntry()],
            vulnerabilities: [defaultVulnEntry()],
        });
        applyIsraNarrativeGuides();

        if(!skipEngineUpdate) notify("Template applied — review threat / weakness rows and narratives.");
    } else {
        resetIsraGuideSelects();
    }
    updateIsraBandSummary();
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
 *
 * `#control-gap-panel` is a static node in index.html so the panel cannot “disappear”
 * when insertBefore targets the wrong parent or runs before DOM is ready.
 */
function renderControlGapAnalysis(gaps, mandatorySets) {
    const panel = document.getElementById('control-gap-panel');
    if (!panel) return;
    const showRole = currentRole === 'infosec' || currentRole === 'admin';
    panel.classList.remove('gap-panel--clear');
    if (!showRole) {
        panel.classList.add('hidden');
        panel.innerHTML = '';
        return;
    }
    if (!mandatorySets || !mandatorySets.length) {
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
    const headerBlock = `
      <label class="gap-panel-title">⚠️ MANDATORY CONTROL GAPS</label>
      <div class="gap-summary">Tick the controls below to lift the standards-based residual floor. Controls flagged <span class="ctrl-mandatory-pill">Compliance baseline</span> in the picker do NOT reduce P/S for the chosen threat — they exist solely to satisfy the framework requirement above. Until every gap closes, residual cannot drop below the indicated rating.</div>`;

    if (!gaps || !gaps.length) {
        panel.innerHTML = `
      <label class="gap-panel-title gap-panel-title--ok">Mandatory control baselines</label>
      <p class="gap-summary">When classification, PII, internet exposure, or FA scope applies, required controls raise the <strong>residual floor</strong> until every applicable ID is implemented. Controls flagged <span class="ctrl-mandatory-pill">Compliance baseline</span> satisfy the framework even when they do not reduce P/S for the current threat.</p>
      <div class="gap-block gap-panel-all-clear">
        <div class="gap-head"><span class="gap-label gap-label--ok">Status</span></div>
        <p class="gap-all-clear-msg">All applicable mandatory controls are selected — no standards-based gap is driving the residual floor.</p>
      </div>`;
        panel.classList.add('gap-panel--clear');
        panel.classList.remove('hidden');
        return;
    }
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
    panel.innerHTML = headerBlock + html;
    panel.classList.remove('hidden', 'gap-panel--clear');
}

// Lightweight HTML escaper for UI panels, modals, and dynamic tables.
function escapeHtmlSafe(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
// Alias used by reason modal, save errors, and exports (must exist before promptReason).
const escapeHtml = escapeHtmlSafe;

function workflowActionBtn(action, assetId, label, className = 'btn btn-sm', extraStyle = '') {
  const safeId = escapeHtmlSafe(assetId);
  const safeAction = escapeHtmlSafe(action);
  const safeLabel = escapeHtmlSafe(label);
  const styleAttr = extraStyle ? ` style="${escapeHtmlSafe(extraStyle)}"` : '';
  return `<button type="button" class="${className}" data-action="${safeAction}" data-asset-id="${safeId}"${styleAttr}>${safeLabel}</button>`;
}

function bindWorkflowActionClicks() {
  if (document.body?.dataset?.workflowActionsBound === '1') return;
  if (!document.body) return;
  document.body.dataset.workflowActionsBound = '1';
  document.body.addEventListener('click', async (ev) => {
    const btn = ev.target.closest('button[data-action][data-asset-id]');
    if (!btn) return;
    const action = btn.getAttribute('data-action');
    const id = btn.getAttribute('data-asset-id');
    if (!action || !id) return;
    try {
      switch (action) {
        case 'approve-asset': await approveAsset(id); break;
        case 'reject-pending': await rejectAsset(id); break;
        case 'reject-draft': await rejectDraftAsset(id); break;
        case 'delete-asset': await deleteAsset(id); break;
        case 'edit-asset': editAsset(id); break;
        default: return;
      }
    } catch (err) {
      console.error('[workflow]', action, id, err);
      notify(err?.message || String(err), true);
    }
  });
}
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bindWorkflowActionClicks);
} else {
  bindWorkflowActionClicks();
}

function roleLabel(role) {
    return { user: 'Standard User', infosec: 'Info Sec', admin: 'Admin (CISO)' }[role] || role;
}

function showAuthScreen() {
    document.body.dataset.role = '';
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

    clearAuthError();
    clearAuthRejectionBanner();
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
    setVerifyEmailWarning('');
    document.getElementById('auth-stage-roles')?.classList.add('hidden');
    document.getElementById('auth-stage-form')?.classList.remove('hidden');
    document.getElementById('auth-step-credentials')?.classList.add('hidden');
    document.getElementById('auth-step-verify')?.classList.remove('hidden');
    document.getElementById('auth-step-pending')?.classList.add('hidden');
    const target = document.getElementById('verify-email-target');
    if (target) target.textContent = email;
}

function setVerifyEmailWarning(text) {
    const el = document.getElementById('verify-email-warning');
    if (!el) return;
    if (text) {
        el.textContent = text;
        el.hidden = false;
    } else {
        el.hidden = true;
        el.textContent = '';
    }
}

async function resendVerificationEmail() {
    if (!supabaseClient || !pendingVerifyEmail) return notify('Enter your email and register again.', true);
    try {
        const { error } = await supabaseClient.auth.resend({
            type: 'signup',
            email: pendingVerifyEmail,
            options: { emailRedirectTo: getAuthRedirectUrl() }
        });
        if (error) throw error;
        setVerifyEmailWarning('');
        notify('Verification email resent. Check your inbox and spam folder.');
    } catch (err) {
        const text = formatAuthError(err);
        setVerifyEmailWarning(text);
        notify(text, true);
    }
}

function showAuthTab(tab) {
    const loginForm = document.getElementById('login-form');
    const regForm = document.getElementById('register-form');
    document.getElementById('tab-login')?.classList.toggle('active', tab === 'login');
    document.getElementById('tab-register')?.classList.toggle('active', tab === 'register');
    loginForm?.classList.toggle('hidden', tab !== 'login');
    regForm?.classList.toggle('hidden', tab !== 'register');
    clearAuthError();
    if (tab === 'register') clearAuthRejectionBanner();
}

function clearAuthRejectionBanner() {
    const el = document.getElementById('auth-rejection-banner');
    if (!el) return;
    el.hidden = true;
    el.innerHTML = '';
}

function showAuthCredentialsView({ email = '', role = null } = {}) {
    document.body.dataset.role = '';
    document.getElementById('auth-screen')?.classList.remove('hidden');
    document.getElementById('app-shell')?.classList.add('hidden');
    const trig = document.getElementById('notif-trigger');
    if (trig) trig.style.display = 'none';
    document.getElementById('auth-stage-roles')?.classList.add('hidden');
    document.getElementById('auth-stage-form')?.classList.remove('hidden');
    document.getElementById('auth-step-credentials')?.classList.remove('hidden');
    document.getElementById('auth-step-verify')?.classList.add('hidden');
    document.getElementById('auth-step-pending')?.classList.add('hidden');
    if (role) setAuthRole(role);
    showAuthTab('login');
    clearAuthError();
    const emailEl = document.getElementById('login-email');
    if (emailEl && email) emailEl.value = email;
}

function showRejectedAccount(profile) {
    const reason = (profile?.rejection_reason || '').trim() || 'No reason was recorded.';
    const email = profile?.email || '';
    const role = profile?.requested_role || 'user';

    suppressAuthReset = true;
    document.body.dataset.role = '';
    if (supabaseClient) supabaseClient.auth.signOut().catch(() => {});
    currentUser = null;
    currentRole = null;
    currentProfile = null;
    currentAccessToken = null;
    authUiReady = false;

    showAuthCredentialsView({ email, role });
    const banner = document.getElementById('auth-rejection-banner');
    if (banner) {
        banner.innerHTML =
            `<strong>Account rejected.</strong> Your ${escapeHtmlSafe(roleLabel(role))} request `
            + `(<span class="auth-rejection-email">${escapeHtmlSafe(email)}</span>) was not approved. `
            + `<span class="auth-rejection-reason">Reason: ${escapeHtmlSafe(reason)}</span>`;
        banner.hidden = false;
    }
    notify('This account was rejected. You may register again with a different email or contact your administrator.', true);
    setTimeout(() => { suppressAuthReset = false; }, 800);
}

function showPendingApproval(profile) {
    clearAuthRejectionBanner();
    document.body.dataset.role = '';
    document.getElementById('auth-screen')?.classList.remove('hidden');
    document.getElementById('app-shell')?.classList.add('hidden');
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

/** Normalise DB role so CSV toolbar + RLS-aligned UI match ('infosec' not 'Infosec', etc.). */
function normalizeApprovedRole(role) {
    if (role == null || role === '') return 'user';
    const s = String(role).trim().toLowerCase();
    if (['user', 'infosec', 'admin'].includes(s)) return s;
    return 'user';
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
        return 'Invalid email or password. If you are using demo accounts, ensure they exist in Supabase Auth (see supabase/hotfix_demo_accounts.sql).';
    }
    if (/email not confirmed/i.test(msg)) {
        return 'Email not yet verified. Click the link Supabase sent to your inbox, then sign in again.';
    }
    if (/error sending confirmation email|unexpected_failure/i.test(msg)) {
        return 'Supabase could not send the verification email. In the Dashboard: turn OFF custom SMTP (Authentication → SMTP) to use built-in mail, enable Confirm email (Providers → Email), and add http://localhost:8000 to URL Configuration. If you enabled custom SMTP before with wrong credentials, disable it and try again. Test: npm run test:auth-email -- your@email.com';
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
        const { data, error } = await supabaseClient.auth.signUp({
            email,
            password,
            options: {
                data: { requested_role: role },
                emailRedirectTo: getAuthRedirectUrl()
            }
        });
        if (error) throw error;
        if (data?.session) {
            pendingLoginRole = role;
            await enterAuthenticatedApp(data.session, role);
            notify('Account created — you are signed in.');
            return;
        }
        showVerificationStep(email);
        notify('Verification email sent. Open the link in your inbox (check spam), then sign in here.');
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
    pendingLoginRole = selectedRole;
    try {
        const { data, error } = await supabaseClient.auth.signInWithPassword({ email, password });
        if (error) {
            pendingLoginRole = null;
            // Supabase returns "Email not confirmed" — surface the verify step
            if (/email not confirmed/i.test(error.message || '')) {
                showVerificationStep(email);
            }
            throw error;
        }
        if (!data?.session) {
            pendingLoginRole = null;
            throw new Error('No session returned.');
        }
        // onAuthStateChange(SIGNED_IN) normally drives enterAuthenticatedApp.
        // Yield once so that listener runs first; fall back if it did not (edge builds).
        await new Promise(r => setTimeout(r, 0));
        if (!authUiReady) {
            const role = pendingLoginRole;
            pendingLoginRole = null;
            await enterAuthenticatedApp(data.session, role ?? selectedRole);
        }
    } catch (err) {
        pendingLoginRole = null;
        const text = formatAuthError(err);
        showAuthError(text, { target: 'login' });
        notify(text, true);
        if (!authUiReady) {
            document.getElementById('app-shell')?.classList.add('hidden');
            document.getElementById('auth-screen')?.classList.remove('hidden');
        }
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalLabel || 'Authenticate <span aria-hidden="true">→</span>';
        }
    }
}

function handleLogout(signOutMessage = 'Signed out.') {
    // Reset client state and flip the UI FIRST so the user is never trapped
    // waiting on the Supabase round-trip (which can hang on slow networks).
    document.body.dataset.role = '';
    currentUser = null;
    currentRole = null;
    currentProfile = null;
    currentAccessToken = null;
    pendingVerifyEmail = null;
    authUiReady = false;
    showAuthScreen();
    notify(signOutMessage, signOutMessage !== 'Signed out.');
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
        clearSupabasePersistedSession();
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
// Role chosen on the login form; consumed by the SIGNED_IN handler so we do not
// run enterAuthenticatedApp twice (handleLogin + onAuthStateChange) with mismatched args.
let pendingLoginRole = null;
let enterAppInFlight = null;

/** Clear persisted + in-browser Supabase session when this load is a history navigation — not OTP/OAuth handshake. */
async function purgeSessionAfterHistoryNavigation() {
    clearSupabasePersistedSession();
    try {
        await supabaseClient.auth.signOut();
    } catch (_) { /* noop */ }
    document.body.dataset.role = '';
    currentUser = null;
    currentRole = null;
    currentProfile = null;
    currentAccessToken = null;
    pendingVerifyEmail = null;
    authUiReady = false;
    showAuthScreen();
    try {
        sessionStorage.setItem(IMPACTLENS_HISTORY_SIGNOUT_NOTICE_KEY, '1');
    } catch (_) { /* noop */ }
}

function flushHistoryReturnSecurityNotice() {
    try {
        if (sessionStorage.getItem(IMPACTLENS_HISTORY_SIGNOUT_NOTICE_KEY) !== '1') return;
        sessionStorage.removeItem(IMPACTLENS_HISTORY_SIGNOUT_NOTICE_KEY);
        notify(HISTORY_RETURN_SECURITY_SIGNOUT_MSG, true);
    } catch (_) { /* noop */ }
}

async function enterAuthenticatedApp(session, requestedRole = null) {
    if (!session?.user) return;
    const userId = session.user.id;
    if (enterAppInFlight?.userId === userId) return enterAppInFlight.promise;
    const run = _enterAuthenticatedAppCore(session, requestedRole);
    enterAppInFlight = { userId, promise: run };
    try {
        return await run;
    } finally {
        if (enterAppInFlight?.promise === run) enterAppInFlight = null;
    }
}

async function _enterAuthenticatedAppCore(session, requestedRole = null) {
    if (!session?.user) return;
    currentUser = session.user;
    currentAccessToken = session.access_token || null;
    // The trigger creates user_profiles on email confirmation. If we somehow get
    // here without a row, treat the account as pending until the DB catches up.
    let profile;
    try {
        profile = await loadUserProfile(currentUser.id);
    } catch (err) {
        console.error('loadUserProfile:', err);
        showAppShell();
        const roleEl = document.getElementById('hdr-role');
        const userEl = document.getElementById('hdr-user');
        if (roleEl) roleEl.textContent = '—';
        if (userEl) userEl.textContent = currentUser.email || '—';
        notify('Signed in, but your profile could not be loaded. Refresh or check Supabase.', true);
        authUiReady = true;
        return;
    }
    currentProfile = profile;
    if (!currentProfile) {
        showAuthScreen();
        showPendingApproval({ email: currentUser.email, requested_role: requestedRole || 'user' });
        return;
    }
    if (currentProfile.account_status === 'rejected') {
        showRejectedAccount(currentProfile);
        return;
    }
    if (currentProfile.account_status === 'pending') {
        showPendingApproval(currentProfile);
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
    currentRole = normalizeApprovedRole(currentProfile.approved_role);
    showAppShell();
    const roleEl = document.getElementById('hdr-role');
    const userEl = document.getElementById('hdr-user');
    if (roleEl) roleEl.textContent = roleLabel(currentRole);
    if (userEl) userEl.textContent = currentUser.email || '—';
    applyRoleUI();
    const landing = { user: 'dashboard', infosec: 'draft-queue', admin: 'dashboard' }[currentRole] || 'add';
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

        if (currentRole === 'infosec' || currentRole === 'admin') {
            const { data: pData, error: pErr } = await supabaseClient.from('user_profiles').select('*').order('created_at', { ascending: false });
            if (!pErr) globalUserProfiles = pData || [];
        } else {
            globalUserProfiles = [];
        }
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

function approverLabelForRole(requestedRole) {
    if (requestedRole === 'user') return 'Info Sec';
    if (requestedRole === 'infosec' || requestedRole === 'admin') return 'Admin (CISO)';
    return '—';
}

function canApproveUserProfile(profile) {
    if (!profile || profile.account_status !== 'pending') return false;
    if (currentRole === 'admin') return true;
    if (currentRole === 'infosec') return profile.requested_role === 'user';
    return false;
}

function countActionablePendingUsers() {
    return globalUserProfiles.filter(p => p.account_status === 'pending' && canApproveUserProfile(p)).length;
}

function updateWorkflowBadges() {
    const drafts = globalAssets.filter(a =>
        a.status === ASSET_STATUS.DRAFT || a.status === ASSET_STATUS.REJECTED
    ).length;
    const pending = globalAssets.filter(a => a.status === ASSET_STATUS.PENDING).length;
    const pendingUsers = countActionablePendingUsers();
    const nd = document.getElementById('nav-drafts');
    const np = document.getElementById('nav-pending');
    const npu = document.getElementById('nav-pending-users');
    if (nd) nd.textContent = drafts;
    if (np) np.textContent = pending;
    if (npu) npu.textContent = pendingUsers;
    const tabCount = document.getElementById('users-tab-pending-count');
    if (tabCount) tabCount.textContent = pendingUsers;
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
            notify('Database is empty. Re-run supabase/master_setup.sql to seed demo assets.', true);
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
  if (name === 'my-submissions') renderMySubmissions();
  if (name === 'logs') renderSystemLogs();
  if (name === 'users') renderUserManagement();
  updateWorkflowBadges();
}

function ensureAddFormIsraPanels() {
    if (!assetRiskScenarios.length) {
        assetRiskScenarios = [blankRiskScenario()];
        currentRiskScenarioIx = 0;
    }
    if (!document.querySelector('#isra-threats-list .isra-multi-row')) {
        applyRiskScenarioToForm(assetRiskScenarios[currentRiskScenarioIx] || assetRiskScenarios[0]);
        renderRiskScenarioTabsUi();
        updateRiskScenarioToolbarLabels();
    }
}

function showSection(name) {
  const allowed = {
    user: ['dashboard', 'add', 'my-submissions', 'register', 'guidelines'],
    infosec: ['dashboard', 'add', 'my-submissions', 'draft-queue', 'pending-queue', 'register', 'risk', 'controls', 'actions', 'logs', 'users', 'guidelines'],
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

  if (name === 'users') showUsersTab(usersActiveTab || 'pending');
  if (name === 'add') ensureAddFormIsraPanels();

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
    'Email not affiliated with organization / not a recognised tenant',
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
    const actionsCount = approvedAssetsRequiringActionPlan().length;
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
    const out = { reason: '', originator: '', target: '', priorStatus: '', requestedRole: '', infosecOfficer: '' };
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
        else if (key === 'infosec_officer' || key === 'submitted_by') out.infosecOfficer = val;
    }
    return out;
}

function isAssetOriginator(asset, email = currentUser?.email) {
    if (!asset || !email) return false;
    return String(asset.created_by || '').toLowerCase() === String(email).toLowerCase();
}

/** Info Sec submitted this asset to the CISO queue (audit log). */
function infosecSubmittedAsset(assetId, me) {
    if (!assetId || !me) return false;
    const m = String(me).toLowerCase();
    return (globalLogs || []).some(l => {
        if (l.asset_id !== assetId || l.action !== 'ASSET_SUBMITTED_FOR_APPROVAL') return false;
        if (String(l.user_email || '').toLowerCase() === m) return true;
        return parseLogDetails(l.details).infosecOfficer.toLowerCase() === m;
    });
}

/** True when this officer profiled/submitted the asset (incl. approved & rejected outcomes). */
function assetHasInfosecSubmission(assetId, me) {
    if (!assetId || !me) return false;
    const m = String(me).toLowerCase();
    if (infosecSubmittedAsset(assetId, me)) return true;
    return (globalLogs || []).some(l => {
        if (l.asset_id !== assetId) return false;
        if (l.action === 'ASSET_REJECTED') {
            return parseLogDetails(l.details).infosecOfficer.toLowerCase() === m;
        }
        if (l.action === 'ASSET_APPROVED' && infosecSubmittedAsset(assetId, me)) return true;
        return false;
    });
}

function isMyLiveSubmission(asset, me, role = currentRole) {
    if (!asset || !me) return false;
    const m = String(me).toLowerCase();
    if (role === 'user') return isAssetOriginator(asset, m);
    if (role === 'infosec') {
        if (isAssetOriginator(asset, m)) return true;
        if (String(asset.updated_by || '').toLowerCase() === m) return true;
        return assetHasInfosecSubmission(asset.id, m);
    }
    return false;
}

function mySubmissionLogMatches(l, parsed, me, role = currentRole) {
    if (!l?.asset_id || !me) return false;
    const m = String(me).toLowerCase();
    const originator = (parsed.originator || '').toLowerCase();
    const officer = (parsed.infosecOfficer || '').toLowerCase();
    const actor = (l.user_email || '').toLowerCase();
    if (role === 'user') return originator === m;
    if (role === 'infosec') {
        if (originator === m) return true;
        if (officer === m) return true;
        if (l.action === 'ASSET_SUBMITTED_FOR_APPROVAL' && actor === m) return true;
        if (l.action === 'ASSET_DELETED' && assetHasInfosecSubmission(l.asset_id, m)) return true;
    }
    return false;
}

/**
 * Unified My Submissions rows: live assets + archived rejections/deletions from SystemLogs.
 */
function gatherMySubmissionRows() {
    if (!currentUser?.email) return [];
    const me = currentUser.email.toLowerCase();
    const role = currentRole;
    const byId = new Map();

    for (const asset of globalAssets) {
        if (!isMyLiveSubmission(asset, me, role)) continue;
        let reason = '';
        let eventAt = asset.reviewed_at || null;
        let actor = '';
        const originator = asset.created_by || '';
        if (asset.status === ASSET_STATUS.REJECTED) {
            const rejLog = (globalLogs || [])
                .filter(l => l.asset_id === asset.id && l.action === 'ASSET_REJECTED')
                .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))[0];
            if (rejLog) {
                reason = parseLogDetails(rejLog.details).reason;
                eventAt = rejLog.created_at || eventAt;
                actor = rejLog.user_email || '';
            }
        } else if (asset.status === ASSET_STATUS.APPROVED) {
            const apprLog = (globalLogs || [])
                .filter(l => l.asset_id === asset.id && l.action === 'ASSET_APPROVED')
                .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))[0];
            if (apprLog) {
                eventAt = apprLog.created_at || eventAt;
                actor = apprLog.user_email || '';
            }
        }
        byId.set(asset.id, {
            id: asset.id,
            name: asset.name || '—',
            type: asset.type || '—',
            status: asset.status || ASSET_STATUS.DRAFT,
            kind: 'live',
            reason,
            eventAt,
            actor,
            originator,
            evaluatedUserDraft: role === 'infosec' && originator && originator.toLowerCase() !== me,
            asset,
        });
    }

    // Info Sec: include CISO-approved assets they evaluated (even if submit log aged out of cache).
    if (role === 'infosec') {
        for (const asset of globalAssets) {
            if (asset.status !== ASSET_STATUS.APPROVED || byId.has(asset.id)) continue;
            if (!assetHasInfosecSubmission(asset.id, me)) continue;
            const apprLog = (globalLogs || [])
                .filter(l => l.asset_id === asset.id && l.action === 'ASSET_APPROVED')
                .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))[0];
            byId.set(asset.id, {
                id: asset.id,
                name: asset.name || '—',
                type: asset.type || '—',
                status: ASSET_STATUS.APPROVED,
                kind: 'live',
                reason: '',
                eventAt: apprLog?.created_at || asset.reviewed_at || null,
                actor: apprLog?.user_email || '',
                originator: asset.created_by || '',
                evaluatedUserDraft: !!(asset.created_by && asset.created_by.toLowerCase() !== me),
                asset,
            });
        }
    }

    const archiveActions = ['DRAFT_REJECTED', 'ASSET_DELETED'];
    for (const l of globalLogs || []) {
        if (!archiveActions.includes(l.action) || !l.asset_id) continue;
        const parsed = parseLogDetails(l.details);
        if (!mySubmissionLogMatches(l, parsed, me, role)) continue;
        const existing = byId.get(l.asset_id);
        if (existing?.kind === 'live') continue;
        const ts = l.created_at ? new Date(l.created_at).getTime() : 0;
        const prev = existing?.eventAt ? new Date(existing.eventAt).getTime() : 0;
        if (existing && ts <= prev) continue;
        const archived = globalAssets.find(a => a.id === l.asset_id);
        const archOrigin = parsed.originator || archived?.created_by || '';
        byId.set(l.asset_id, {
            id: l.asset_id,
            name: archived?.name || '—',
            type: archived?.type || '—',
            status: l.action === 'DRAFT_REJECTED' ? 'Draft Rejected' : 'Deleted',
            kind: l.action === 'DRAFT_REJECTED' ? 'draft-rejected' : 'deleted',
            reason: parsed.reason || '',
            eventAt: l.created_at,
            actor: l.user_email || '—',
            originator: archOrigin,
            evaluatedUserDraft: role === 'infosec' && archOrigin && archOrigin.toLowerCase() !== me,
            asset: archived || null,
        });
    }

    const sortRank = (row) => {
        const k = row.kind === 'live' ? row.status : row.kind;
        const order = {
            'draft-rejected': 0,
            deleted: 1,
            [ASSET_STATUS.REJECTED]: 2,
            [ASSET_STATUS.PENDING]: 3,
            [ASSET_STATUS.APPROVED]: 4,
            [ASSET_STATUS.DRAFT]: 5,
        };
        return order[k] ?? 9;
    };
    return [...byId.values()].sort((a, b) => sortRank(a) - sortRank(b));
}

function mySubmissionAssets() {
    return gatherMySubmissionRows()
        .filter(r => r.kind === 'live' && r.asset)
        .map(r => r.asset);
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
                msg = `Your asset ${aLabel} was <strong>REJECTED</strong> by the CISO. Check <strong>My Submissions</strong> for the reason.${reasonHtml(parsed.reason)}`;
                kind = 'warn';
                target = 'my-submissions';
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
            } else if (action === 'ASSET_REJECTED') {
                const officer = (parsed.infosecOfficer || '').toLowerCase();
                if (officer === me || (!officer && handled === me)) {
                    msg = `Your submission ${aLabel} was <strong>REJECTED</strong> by the CISO. Revise in the <strong>Draft Queue</strong> and resubmit.${reasonHtml(parsed.reason)}`;
                    kind = 'warn';
                    target = 'draft-queue';
                }
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
            } else if (action === 'USER_REQUEST') {
                msg = `New <strong>Standard User</strong> account pending your approval: ${escapeHtmlSafe(parsed.target || details)}`;
                kind = 'warn';
                target = 'users';
            }
        } else if (currentRole === 'admin') {
            if (action === 'ASSET_SUBMITTED_FOR_APPROVAL' && actor !== me) {
                msg = `Asset ${aLabel} is awaiting your approval.`;
                kind = 'warn';
                target = 'pending-queue';
            } else if (action === 'USER_REQUEST' || details.includes('account_status=pending')) {
                const needsAdmin = /requested_role=infosec|requested_role=admin/i.test(details);
                msg = needsAdmin
                    ? `New <strong>Info Sec</strong> account pending CISO approval: ${escapeHtmlSafe(parsed.target || details)}`
                    : `New user account pending approval: ${escapeHtmlSafe(parsed.target || details)}`;
                kind = 'warn';
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
    
    const hCount = approvedAssetsOnly().filter(a => liveAssetResidualTier(a) === 'High').length;
    
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
function parseJsonSafe(str, fallback = {}) {
  if (str == null || str === '') return { ...fallback };
  if (typeof str === 'object') return str;
  try { return JSON.parse(String(str)); } catch (_) { return { ...fallback }; }
}

/** Types where MBSS + firewall JSON are fixed (non-host / non-network perimeter). */
const MBSS_FW_LOCKED_TYPES = new Set(['PhA', 'PA']);
function isMbssFirewallTypeLocked(type) {
  return MBSS_FW_LOCKED_TYPES.has(type);
}
const LOCKED_MBSS_JSON_BY_TYPE = {
  PhA: { edr_epp: 'N', patch_current: 'N', disk_encryption: 'N', host_firewall: 'N', admin_priv_review: 'Y', last_review_date: '', notes: 'Physical asset — host MBSS baseline not applicable (system fixed).' },
  PA: { edr_epp: 'N', patch_current: 'N', disk_encryption: 'N', host_firewall: 'N', admin_priv_review: 'Y', last_review_date: '', notes: 'Personnel asset — endpoint baseline not applicable (system fixed).' },
};
const LOCKED_FIREWALL_JSON_BY_TYPE = {
  PhA: { scope: 'None documented', default_deny: 'N', change_control: 'Y', logging_soc: 'N', rule_review_cadence: 'Annual', overly_permissive: 'N', notes: 'Physical asset — perimeter at facility or campus layer only (system fixed).' },
  PA: { scope: 'None documented', default_deny: 'N', change_control: 'Y', logging_soc: 'N', rule_review_cadence: 'Annual', overly_permissive: 'N', notes: 'Personnel asset — network perimeter not applicable (system fixed).' },
};
function getLockedMbssObject(type) {
  return { ...(LOCKED_MBSS_JSON_BY_TYPE[type] || LOCKED_MBSS_JSON_BY_TYPE.PhA) };
}
function getLockedFirewallObject(type) {
  return { ...(LOCKED_FIREWALL_JSON_BY_TYPE[type] || LOCKED_FIREWALL_JSON_BY_TYPE.PhA) };
}

let mbssFwUiSyncKey = '';

function collectMbssFromForm() {
  const v = id => {
    const el = document.getElementById(id);
    return el && el.value === 'Y' ? 'Y' : 'N';
  };
  return {
    edr_epp: v('f-mbss-edr'),
    patch_current: v('f-mbss-patch'),
    disk_encryption: v('f-mbss-disk'),
    host_firewall: v('f-mbss-hostfw'),
    admin_priv_review: v('f-mbss-admin'),
    last_review_date: (document.getElementById('f-mbss-date')?.value || '').trim(),
    notes: (document.getElementById('f-mbss-notes')?.value || '').trim()
  };
}

function collectFirewallFromForm() {
  const v = id => {
    const el = document.getElementById(id);
    return el && el.value === 'Y' ? 'Y' : 'N';
  };
  return {
    scope: (document.getElementById('f-fw-scope')?.value || '').trim(),
    default_deny: v('f-fw-defaultdeny'),
    change_control: v('f-fw-change'),
    logging_soc: v('f-fw-logging'),
    rule_review_cadence: (document.getElementById('f-fw-cadence')?.value || '').trim(),
    overly_permissive: v('f-fw-permissive'),
    notes: (document.getElementById('f-fw-notes')?.value || '').trim()
  };
}

function loadMbssFirewallToForm(a) {
  const m = parseJsonSafe(a.mbss_json, {});
  const setYn = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.value = val === 'Y' ? 'Y' : 'N';
  };
  setYn('f-mbss-edr', m.edr_epp);
  setYn('f-mbss-patch', m.patch_current);
  setYn('f-mbss-disk', m.disk_encryption);
  setYn('f-mbss-hostfw', m.host_firewall);
  setYn('f-mbss-admin', m.admin_priv_review);
  if (document.getElementById('f-mbss-date')) document.getElementById('f-mbss-date').value = m.last_review_date || '';
  if (document.getElementById('f-mbss-notes')) document.getElementById('f-mbss-notes').value = m.notes || '';

  const f = parseJsonSafe(a.firewall_json, {});
  if (document.getElementById('f-fw-scope')) document.getElementById('f-fw-scope').value = f.scope || '';
  setYn('f-fw-defaultdeny', f.default_deny);
  setYn('f-fw-change', f.change_control);
  setYn('f-fw-logging', f.logging_soc);
  setYn('f-fw-permissive', f.overly_permissive);
  const cadEl = document.getElementById('f-fw-cadence');
  if (cadEl) {
    const v = (f.rule_review_cadence || '').trim();
    cadEl.querySelectorAll('option[data-legacy]').forEach(o => o.remove());
    const known = new Set(FW_REVIEW_CADENCE_CHOICES);
    if (v && !known.has(v)) {
      const o = document.createElement('option');
      o.value = v;
      o.textContent = v + ' (imported)';
      o.setAttribute('data-legacy', '1');
      cadEl.appendChild(o);
    }
    cadEl.value = v || '';
  }
  if (document.getElementById('f-fw-notes')) document.getElementById('f-fw-notes').value = f.notes || '';
}

function pushLockedMbssFirewallToForm(type) {
  loadMbssFirewallToForm({
    mbss_json: JSON.stringify(getLockedMbssObject(type)),
    firewall_json: JSON.stringify(getLockedFirewallObject(type)),
  });
}

function resetMbssFirewallFormToNewAssetDefaults() {
  ['f-mbss-edr', 'f-mbss-patch', 'f-mbss-disk', 'f-mbss-hostfw', 'f-mbss-admin'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = 'N';
  });
  if (document.getElementById('f-mbss-date')) document.getElementById('f-mbss-date').value = '';
  if (document.getElementById('f-mbss-notes')) document.getElementById('f-mbss-notes').value = '';
  if (document.getElementById('f-fw-scope')) document.getElementById('f-fw-scope').value = '';
  ['f-fw-defaultdeny', 'f-fw-change', 'f-fw-logging', 'f-fw-permissive'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = 'N';
  });
  const ce = document.getElementById('f-fw-cadence');
  if (ce) {
    ce.querySelectorAll('option[data-legacy]').forEach(o => o.remove());
    ce.value = '';
  }
  if (document.getElementById('f-fw-notes')) document.getElementById('f-fw-notes').value = '';
}

/** Mirror inherent/residual ratings and P×S under MBSS/firewall so assessors see impact while editing evidence. */
function syncMbssFirewallScoreMirrors() {
  const strip = document.getElementById('mbss-risk-score-strip');
  if (!strip) return;
  const badgeCls = r => ({ 'Very Low': 'badge-vl', Low: 'badge-lo', Moderate: 'badge-mo', High: 'badge-hi' }[r] || 'badge-lo');
  const inhEl = document.getElementById('r-inherit');
  const resEl = document.getElementById('r-residual');
  const inhTxt = (inhEl?.textContent || '—').trim() || '—';
  const resTxt = (resEl?.textContent || '—').trim() || '—';
  const mInh = document.getElementById('mbss-mirror-r-inherit');
  const mRes = document.getElementById('mbss-mirror-r-residual');
  const mInhPs = document.getElementById('mbss-mirror-inh-ps');
  const mResPs = document.getElementById('mbss-mirror-res-ps');
  const probD = (document.getElementById('f-prob-display')?.value || '').trim();
  const sevD = (document.getElementById('f-sev-display')?.value || '').trim();
  const rProb = (document.getElementById('f-res-prob-display')?.value || '').trim();
  const rSev = (document.getElementById('f-res-sev-display')?.value || '').trim();
  if (mInh) {
    mInh.textContent = inhTxt;
    mInh.className = `badge ${badgeCls(inhTxt)}`;
    mInh.style.fontSize = '12px';
    mInh.style.padding = '4px 10px';
  }
  if (mRes) {
    mRes.textContent = resTxt;
    mRes.className = `badge ${badgeCls(resTxt)}`;
    mRes.style.fontSize = '12px';
    mRes.style.padding = '4px 10px';
  }
  if (mInhPs) mInhPs.textContent = (probD && sevD) ? `${probD}×${sevD}` : '—';
  if (mResPs) mResPs.textContent = (rProb && rSev) ? `${rProb}×${rSev}` : '—';
}

function syncMbssFirewallSectionState() {
  const type = (document.getElementById('f-type')?.value || '').trim();
  const section = document.getElementById('sec-mbss-firewall');
  const banner = document.getElementById('mbss-firewall-type-lock-banner');
  if (!section) return;
  if (isMbssFirewallTypeLocked(type)) {
    pushLockedMbssFirewallToForm(type);
    section.querySelectorAll('input, select, textarea').forEach(el => { el.disabled = true; });
    if (banner) {
      banner.hidden = false;
      banner.textContent = type === 'PA'
        ? 'Personnel (PA): MBSS and firewall values are system-defined and cannot be edited.'
        : 'Physical asset (PhA): MBSS and firewall values are system-defined and cannot be edited.';
    }
    mbssFwUiSyncKey = `L:${type}`;
    return;
  }
  section.querySelectorAll('input, select, textarea').forEach(el => { el.disabled = false; });
  if (banner) banner.hidden = true;
  const key = `U:${type}:${editingId || 'new'}`;
  if (mbssFwUiSyncKey !== key) {
    mbssFwUiSyncKey = key;
    if (editingId) {
      const a = globalAssets.find(x => x.id === editingId);
      if (a && a.type === type) loadMbssFirewallToForm(a);
      else resetMbssFirewallFormToNewAssetDefaults();
    } else {
      resetMbssFirewallFormToNewAssetDefaults();
    }
  }
}

function buildAssetPayloadFromForm() {
  ensureScenarioResidualsPersistedAndComputed();
  const type = g('f-type');
  const name = g('f-name').trim();
  const id = editingId || g('f-id');
  const c = clampCia(document.getElementById('f-c').value);
  const ii = clampCia(document.getElementById('f-i').value);
  const a = clampCia(document.getElementById('f-a').value);
  const cMax = ciaMax(c, ii, a);

  const uniqCat = [...new Set(assetRiskScenarios.map(s => (s.riskCategory || '').trim()).filter(Boolean))].slice(0, 12).join('|');
  const descParts = assetRiskScenarios.map((s, i) =>
    `[Scenario ${i + 1}] ${(s.riskDesc || '').trim()}`.trim()
  ).filter(Boolean);

  const heat = rollupScenarioWorstHeatmapAxes(assetRiskScenarios);
  const repr = worstScenarioForReporting(assetRiskScenarios);

  const pHM = heat != null ? heat.prob : (repr != null && repr.prob != null ? repr.prob : (parseInt(g('f-prob'), 10) || 3));
  const sHM = heat != null ? heat.sev : (repr != null && repr.sev != null ? repr.sev : (parseInt(g('f-sev'), 10) || 3));
  const firstBasis = assetRiskScenarios.length ? (assetRiskScenarios[0].risk_basis || defaultRiskBasisObject()) : normalizeRiskBasisForPersist();
  const rollupInRat = repr?.inherit || rollupWorstInherentRatings(assetRiskScenarios.map(s => s.inherit));
  let rollupResRat = repr?.residual || rollupWorstResidualRating(assetRiskScenarios.map(s => s.residual));
  if (RESIDUAL_FLOOR_RANK[rollupResRat] > RESIDUAL_FLOOR_RANK[rollupInRat]) {
    rollupResRat = rollupInRat;
  }

  return {
    id, type, name,
    group_name: g('f-group'),
    hostname: g('f-hostname'), server: g('f-server'), custodian: g('f-custodian'), description: g('f-desc'),
    ip_address: g('f-ip'), environment: g('f-environment'), department: g('f-department'),
    asset_owners: (document.getElementById('f-asset-owners')?.value || '').trim(),
    classification_justification: (document.getElementById('f-classification-justification')?.value || '').trim(),
    pii: document.getElementById('f-pii').value,
    spi: document.getElementById('f-spi').value,
    corp: document.getElementById('f-corp').value,
    ciaC: c, ciaI: ii, ciaA: a, ciaScore: cMax,
    ciaClass: ciaClassFromValues(c, ii, a),
    riskCategory: uniqCat || repr?.riskCategory || '',
    riskDesc: descParts.join('\n').slice(0, 8000),
    risk_basis_json: JSON.stringify(firstBasis),
    asset_risks_json: JSON.stringify(assetRiskScenarios),
    cia_questionnaire_json: JSON.stringify(normalizeCiaQuestionnaireForPersist()),
    prob: pHM, sev: sHM, inherit: rollupInRat, residual: rollupResRat,
    actionType: repr?.actionType || g('f-action-type'),
    actionStatus: repr?.actionStatus || g('f-action-status'),
    actionPlan: repr?.actionPlan || g('f-action-plan'),
    actionOwner: repr?.actionOwner || g('f-action-owner'),
    actionDate: repr?.actionDate || g('f-action-date'),
    updated_by: currentUser?.email || null,
    mbss_json: isMbssFirewallTypeLocked(type)
      ? JSON.stringify(getLockedMbssObject(type))
      : JSON.stringify(collectMbssFromForm()),
    firewall_json: isMbssFirewallTypeLocked(type)
      ? JSON.stringify(getLockedFirewallObject(type))
      : JSON.stringify(collectFirewallFromForm())
  };
}

function draftDefaultsFromType(type) {
  if (!ALLOWED_ASSET_TYPES.has(type)) return {};
  const c = 3;
  const i = 3;
  const a = 3;
  return {
    pii: 'N', spi: 'N', corp: 'N',
    ciaC: c, ciaI: i, ciaA: a,
    ciaScore: ciaMax(c, i, a), ciaClass: ciaClassFromValues(c, i, a),
    prob: 3, sev: 3, inherit: 'Moderate', residual: 'Moderate',
    riskCategory: '', riskDesc: '', actionType: 'Mitigate', actionStatus: 'Pending',
    actionPlan: '', actionOwner: '', actionDate: ''
  };
}

function normalizeCiaQuestionnaireForPersist() {
  const gv = id => (document.getElementById(id)?.value || '').trim();
  return {
    disclosure_impact: gv('f-q-disclosure-impact') || '2',
    integrity_impact: gv('f-q-integrity-impact') || '2',
    availability_impact: gv('f-q-availability-impact') || '2',
    personal_data_scope: gv('f-q-personal-scope') || 'none',
    corp_strategic: gv('f-q-corp-strategic') || 'N',
    version: 1,
  };
}

function loadCiaQuestionnaireToForm(rawJson) {
  const q = parseJsonSafe(rawJson, {});
  const setSel = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
  setSel('f-q-disclosure-impact', q.disclosure_impact || '2');
  setSel('f-q-integrity-impact', q.integrity_impact || '2');
  setSel('f-q-availability-impact', q.availability_impact || '2');
  setSel('f-q-personal-scope', q.personal_data_scope || 'none');
  setSel('f-q-corp-strategic', q.corp_strategic === 'Y' ? 'Y' : 'N');
}

/** Map questionnaire answers onto PI / corp / CIA sliders (still refine justification below). */
function syncCiaQuestionnaireIntoClassificationFields() {
  const clamp15 = x => Math.max(1, Math.min(5, parseInt(String(x), 10) || 3));
  const disc = clamp15(document.getElementById('f-q-disclosure-impact')?.value);
  const integ = clamp15(document.getElementById('f-q-integrity-impact')?.value);
  const avail = clamp15(document.getElementById('f-q-availability-impact')?.value);
  const pEl = document.getElementById('f-pii');
  const spiEl = document.getElementById('f-spi');
  const scope = (document.getElementById('f-q-personal-scope')?.value || 'none').trim();
  if (pEl && spiEl) {
    if (scope === 'ordinary') { pEl.value = 'Y'; spiEl.value = 'N'; }
    else if (scope === 'spi') { pEl.value = 'Y'; spiEl.value = 'Y'; }
    else { pEl.value = 'N'; spiEl.value = 'N'; }
  }
  const corpEl = document.getElementById('f-corp');
  const corpAnswer = (document.getElementById('f-q-corp-strategic')?.value || 'N').trim() === 'Y';
  const disclosureHeavy = disc >= 4;
  if (corpEl) corpEl.value = (corpAnswer || disclosureHeavy) ? 'Y' : 'N';
  const fC = document.getElementById('f-c');
  const fI = document.getElementById('f-i');
  const fA = document.getElementById('f-a');
  if (fC) fC.value = String(disc);
  if (fI) fI.value = String(integ);
  if (fA) fA.value = String(avail);
}

/** Normalized ISRA narrative + qualitative anchors persisted in risk_basis_json */
function normalizeRiskBasisForPersist() {
  const gs = id => (document.getElementById(id)?.value || '').trim();
  const threats = collectThreatsFromDom();
  const vulnerabilities = collectVulnsFromDom();
  const threat_statement = joinThreatStatements(threats);
  const vulnerability_statement = joinVulnStatements(vulnerabilities);
  return {
    threats,
    vulnerabilities,
    threat_statement,
    vulnerability_statement,
    occurrence_justification: gs('f-occurrence-justification'),
    likelihood_qual: Math.max(1, Math.min(5, parseInt(gs('f-likelihood-qual') || '3', 10))),
    impact_qual: Math.max(1, Math.min(5, parseInt(gs('f-impact-qual') || '3', 10))),
    threat_choice: maxThreatBand(threats),
    vulnerability_choice: maxVulnBand(vulnerabilities),
    prior_incidents: (() => {
      const x = gs('f-prior-incidents').toUpperCase();
      if (x === 'Y' || x === 'YES') return 'Y';
      if (x === 'U' || x === 'UNKNOWN') return 'U';
      return 'N';
    })(),
  };
}

function loadRiskBasisToForm(raw) {
  const m = parseJsonSafe(raw, {});
  const setVal = (id, v) => { const el = document.getElementById(id); if (el != null && v !== undefined) el.value = v; };
  renderIsraThreatVulnPanels(m);
  setVal('f-occurrence-justification', m.occurrence_justification || '');
  setVal('f-likelihood-qual', m.likelihood_qual != null ? String(m.likelihood_qual) : '3');
  setVal('f-impact-qual', m.impact_qual != null ? String(m.impact_qual) : '3');
  setVal('f-prior-incidents', m.prior_incidents || 'N');
  resetIsraGuideSelects();
  const occEl = document.getElementById('f-occurrence-justification');
  if (occEl) occEl.dataset.israGuided = '';
  updateIsraBandSummary();
}

/**
 * Translate qualitative likelihood/impact (+ evidence fields) into inherent anchors 1–5.
 * Existing calculateRiskMath() still applies CIA / FA / exposure escalations afterward.
 */
function syncInherentAnchorsFromRiskBasis() {
  if (!document.getElementById('f-likelihood-qual')) return;
  const b = normalizeRiskBasisForPersist();
  const anch = anchorsFromRiskBasisPayload(b);
  const probH = document.getElementById('f-prob');
  const sevH = document.getElementById('f-sev');
  if (probH) probH.value = String(anch.p);
  if (sevH) sevH.value = String(anch.s);
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

/** Info Sec / Admin — ISRA completeness before persisting assessed assets. */
function validateIsraMandatoryFields() {
  flushCurrentRiskScenarioSnapshot();
  for (let i = 0; i < assetRiskScenarios.length; i++) {
    const sc = assetRiskScenarios[i];
    if (!(sc.riskCategory || '').trim())
      return `Risk scenario #${i + 1}: template / category required.`;
    if (!(sc.riskDesc || '').trim())
      return `Risk scenario #${i + 1}: synthesized risk description required.`;
    const rb = sc.risk_basis || defaultRiskBasisObject();
    const thrS = joinThreatStatements(normalizeThreatsArray(rb));
    const vulS = joinVulnStatements(normalizeVulnsArray(rb));
    const occS = String(rb.occurrence_justification || '').trim();
    if (thrS.length < 24 || vulS.length < 24 || occS.length < 24)
      return `Risk scenario #${i + 1}: combined threat narratives, weakness narratives, and occurrence justification each need ≥ 24 characters.`;
    const emptyThreat = normalizeThreatsArray(rb).some(t => !String(t.statement || '').trim());
    const emptyVuln = normalizeVulnsArray(rb).some(v => !String(v.statement || '').trim());
    if (emptyThreat || emptyVuln)
      return `Risk scenario #${i + 1}: every threat and weakness row needs a narrative.`;
  }
  const cj = (document.getElementById('f-classification-justification')?.value || '').trim();
  if (cj.length < 24) return 'Classification justification required (how questionnaire + CIA/PI posture were decided; ≥ 24 characters).';
  return '';
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

    let payload;
    if (currentRole === 'infosec') {
      const v = validateIsraMandatoryFields();
      if (v) { setSaveStatus('err', '<strong>✗ ' + escapeHtml(v) + '</strong>'); return; }
      calculateRiskMath();
      payload = buildAssetPayloadFromForm();
    } else if (currentRole === 'admin') {
      flushCurrentRiskScenarioSnapshot();
      const hasProfiling =
        assetRiskScenarios.some(s => (s.riskCategory || '').trim()) ||
        !!(g('f-risk-category') || '').trim();
      if (hasProfiling) {
        const v = validateIsraMandatoryFields();
        if (v) { setSaveStatus('err', '<strong>✗ ' + escapeHtml(v) + '</strong>'); return; }
        calculateRiskMath();
      }
      payload = buildAssetPayloadFromForm();
    } else {
      payload = buildAssetPayloadFromForm();
    }
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
      detailMsg = `Status: Pending · awaiting CISO approval · originator=${payload.created_by || currentUser?.email || 'unknown'} · infosec_officer=${currentUser?.email || 'unknown'}`;
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
  const originator = asset.created_by || 'unknown';
  const infosecOfficer = asset.updated_by || 'unknown';
  const reason = await promptReason({
    title: 'Reject submission',
    eyebrow: 'CISO Review · Pending Approval',
    description: 'The asset is marked Rejected for both the Standard User (originator) and the Info Sec officer who submitted it. The reason is logged and appears in each role\'s inbox and workflow views.',
    presets: REASON_PRESETS.rejectAssetPending,
    confirmLabel: 'Reject submission',
    tone: 'warn',
  });
  if (reason === null) return;
  const { error } = await supabaseClient.from('Assets').update({
    status: ASSET_STATUS.REJECTED,
    reviewed_at: new Date().toISOString(),
    updated_by: currentUser?.email
  }).eq('id', id);
  if (error) return notify(error.message, true);
  await logSystemEvent(
    'ASSET_REJECTED',
    `Reason: ${reason} · originator=${originator} · infosec_officer=${infosecOfficer} · prior_status=${asset.status || ASSET_STATUS.PENDING}`,
    id
  );
  await syncFromCloud(true);
  notify(`Asset ${id} rejected — surfaced to ${originator} and ${infosecOfficer}.`);
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
      mbssFwUiSyncKey = '';
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
          'f-asset-owners': a.asset_owners,
          'f-classification-justification': a.classification_justification,
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
      ['f-c', 'f-i', 'f-a'].forEach(id => {
          const el = document.getElementById(id);
          if (el) el.value = String(normalizeCiaStored(el.value));
      });
      loadCiaQuestionnaireToForm(a.cia_questionnaire_json || '{}');
      assetRiskScenarios = migrateLegacyToRiskScenarios(a);
      currentRiskScenarioIx = 0;
      applyRiskScenarioToForm(assetRiskScenarios[0]);
      renderRiskScenarioTabsUi();
      updateRiskScenarioToolbarLabels();

      const typeEl = document.getElementById('f-type');
      if (typeEl) typeEl.dataset.lastType = a.type;

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
    } else if (currentRole === 'infosec' && status === ASSET_STATUS.REJECTED) {
        banner.innerHTML = '<strong>CISO Rejected</strong> — Revise the assessment and save to resubmit for <span class="badge badge-mo">Pending Approval</span>. The originator sees <span class="badge badge-hi">Rejected</span> in My Submissions.';
        banner.hidden = false;
    } else if (currentRole === 'user' && status === ASSET_STATUS.REJECTED) {
        banner.innerHTML = '<strong>Rejected by CISO</strong> — Your submission was returned for Info Sec revision. See <strong>My Submissions</strong> for status; you cannot edit this record.';
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
  mbssFwUiSyncKey = '';
  assetRiskScenarios = [blankRiskScenario()];
  currentRiskScenarioIx = 0;
  const fields = ['f-name','f-group','f-hostname','f-server','f-custodian','f-desc', 'f-ip', 'f-department', 'f-asset-owners', 'f-classification-justification', 'f-occurrence-justification', 'f-risk-desc','f-action-plan','f-action-owner','f-action-date','f-risk-category'];
  fields.forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
  
  const selects = ['f-type', 'f-id'];
  selects.forEach(id => { const el = document.getElementById(id); if(el) { el.value = ''; el.dataset.lastType = ''; } });

  if(document.getElementById('f-environment')) document.getElementById('f-environment').value = 'Internal';
  ['f-q-disclosure-impact','f-q-integrity-impact','f-q-availability-impact'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '2';
  });
  if (document.getElementById('f-q-personal-scope')) document.getElementById('f-q-personal-scope').value = 'none';
  if (document.getElementById('f-q-corp-strategic')) document.getElementById('f-q-corp-strategic').value = 'N';
  syncCiaQuestionnaireIntoClassificationFields();

  if(document.getElementById('f-prob')) document.getElementById('f-prob').value = '3';
  if(document.getElementById('f-sev')) document.getElementById('f-sev').value = '3';
  if(document.getElementById('f-likelihood-qual')) document.getElementById('f-likelihood-qual').value = '3';
  if(document.getElementById('f-impact-qual')) document.getElementById('f-impact-qual').value = '3';
  if(document.getElementById('f-prior-incidents')) document.getElementById('f-prior-incidents').value = 'N';
  resetIsraGuideSelects();
  renderIsraThreatVulnPanels(defaultRiskBasisObject());
  const occEl = document.getElementById('f-occurrence-justification');
  if (occEl) occEl.dataset.israGuided = '';
  if(document.getElementById('f-action-type')) document.getElementById('f-action-type').value = 'Mitigate';
  if(document.getElementById('f-action-status')) document.getElementById('f-action-status').value = 'Pending';
  
  for(let i=1; i<=13; i++) { const cb = document.getElementById('ctrl'+i); if(cb) cb.checked = false; }

  ['f-mbss-edr','f-mbss-patch','f-mbss-disk','f-mbss-hostfw','f-mbss-admin'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = 'N';
  });
  if (document.getElementById('f-mbss-date')) document.getElementById('f-mbss-date').value = '';
  if (document.getElementById('f-mbss-notes')) document.getElementById('f-mbss-notes').value = '';
  if (document.getElementById('f-fw-scope')) document.getElementById('f-fw-scope').value = '';
  ['f-fw-defaultdeny','f-fw-change','f-fw-logging','f-fw-permissive'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = 'N';
  });
  if (document.getElementById('f-fw-cadence')) {
    const ce = document.getElementById('f-fw-cadence');
    ce.querySelectorAll('option[data-legacy]').forEach(o => o.remove());
    ce.value = '';
  }
  if (document.getElementById('f-fw-notes')) document.getElementById('f-fw-notes').value = '';
  
  editingId = null;
  const titleEl = document.getElementById('form-title');
  if(titleEl) titleEl.innerHTML = 'INSERT <span>RECORD</span>';
  const statusEl = document.getElementById('form-workflow-status');
  if (statusEl) statusEl.textContent = ASSET_STATUS.DRAFT;
  setFormSectionsLocked(currentRole === 'user');
  const banner = document.getElementById('reapproval-banner');
  if (banner) { banner.hidden = true; banner.innerHTML = ''; }

  applyRiskScenarioToForm(assetRiskScenarios[0]);
  renderRiskScenarioTabsUi();
  updateRiskScenarioToolbarLabels();

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
  const rejected = globalAssets.filter(a => a.status === ASSET_STATUS.REJECTED);
  const drafts = globalAssets.filter(a => a.status === ASSET_STATUS.DRAFT);
  if (!rejected.length && !drafts.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No draft or rejected assets in queue.</td></tr>';
    return;
  }
  const canActOnDraft = currentRole === 'admin' || currentRole === 'infosec';
  const rowHtml = (a, mode) => {
    const actions = mode === 'rejected'
      ? (canActOnDraft
          ? workflowActionBtn('edit-asset', a.id, 'Revise & resubmit →', 'btn btn-sm btn-primary')
          : '')
      : [
          workflowActionBtn('edit-asset', a.id, 'Assess →', 'btn btn-sm btn-primary'),
          canActOnDraft
            ? workflowActionBtn('reject-draft', a.id, 'Reject', 'btn btn-sm btn-danger', 'margin-left:4px')
            : '',
          canActOnDraft
            ? workflowActionBtn('delete-asset', a.id, 'Delete', 'btn btn-sm btn-danger', 'margin-left:4px;opacity:0.85')
            : ''
        ].filter(Boolean).join('');
    return `
    <tr>
      <td><span class="badge badge-id">${escapeHtmlSafe(a.id)}</span> ${statusBadge(a.status)}</td>
      <td><strong>${escapeHtmlSafe(a.name || '')}</strong></td>
      <td><span class="badge badge-type">${a.type}</span></td>
      <td style="color:var(--text2)">${a.created_by || '—'}</td>
      <td style="white-space:nowrap">${actions}</td>
    </tr>`;
  };
  const parts = [];
  if (rejected.length) {
    parts.push(`<tr class="queue-section-row"><td colspan="5" style="padding:10px 12px;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--danger);background:rgba(255,58,46,.08);border-bottom:1px solid var(--border)">CISO rejected — revise &amp; resubmit</td></tr>`);
    parts.push(rejected.map(a => rowHtml(a, 'rejected')).join(''));
  }
  if (drafts.length) {
    if (rejected.length) {
      parts.push(`<tr class="queue-section-row"><td colspan="5" style="padding:10px 12px;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--text3);background:var(--surface2);border-bottom:1px solid var(--border)">Awaiting Info Sec profiling</td></tr>`);
    }
    parts.push(drafts.map(a => rowHtml(a, 'draft')).join(''));
  }
  tbody.innerHTML = parts.join('');
}

function mySubmissionStatusBadge(row) {
  if (row.kind === 'draft-rejected') {
    return '<span class="badge badge-hi">Draft Rejected</span>';
  }
  if (row.kind === 'deleted') {
    return '<span class="badge badge-hi" style="opacity:0.92">Deleted</span>';
  }
  return statusBadge(row.status);
}

function mySubmissionNote(row) {
  const reasonLine = row.reason
    ? `<span class="ms-note-reason">Reason: ${escapeHtmlSafe(row.reason)}</span>`
    : '';
  if (row.kind === 'draft-rejected') {
    return `<span class="ms-note ms-note--bad">Removed from queue by ${escapeHtmlSafe(row.actor || 'Info Sec')}</span>${reasonLine}`;
  }
  if (row.kind === 'deleted') {
    return `<span class="ms-note ms-note--bad">Permanently deleted by ${escapeHtmlSafe(row.actor || 'an officer')}</span>${reasonLine}`;
  }
  if (row.status === ASSET_STATUS.REJECTED) {
    const who = currentRole === 'user'
      ? 'Returned by CISO — Info Sec will revise'
      : 'Rejected by CISO — revise in Draft Queue';
    return `<span class="ms-note ms-note--bad">${who}</span>${reasonLine}`;
  }
  if (row.status === ASSET_STATUS.PENDING) {
    return '<span class="ms-note ms-note--warn">With CISO for approval</span>';
  }
  if (row.status === ASSET_STATUS.DRAFT) {
    return currentRole === 'user'
      ? '<span class="ms-note ms-note--muted">Awaiting Info Sec profiling</span>'
      : '<span class="ms-note ms-note--muted">In your draft workflow</span>';
  }
  if (row.status === ASSET_STATUS.APPROVED) {
    if (currentRole === 'infosec' && row.evaluatedUserDraft) {
      const by = row.actor ? ` · CISO sign-off by ${escapeHtmlSafe(row.actor)}` : '';
      return `<span class="ms-note ms-note--ok">You evaluated this user submission — approved in register</span>`
        + `<span class="ms-note ms-note--muted">Originator: ${escapeHtmlSafe(row.originator || '—')}${by}</span>`;
    }
    if (currentRole === 'infosec') {
      return '<span class="ms-note ms-note--ok">You submitted this assessment — approved in register</span>';
    }
    return '<span class="ms-note ms-note--ok">Approved in register</span>';
  }
  return '—';
}

function renderMySubmissions() {
  const tbody = document.getElementById('my-submissions-body');
  if (!tbody) return;
  const items = gatherMySubmissionRows();
  const colSpan = currentRole === 'infosec' ? 6 : 5;
  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="${colSpan}" class="ms-empty">No submissions yet. Use <strong>Add Asset</strong> to register a new record.</td></tr>`;
    return;
  }
  tbody.innerHTML = items.map(row => {
    const when = row.eventAt
      ? `<span class="ms-note-time">${escapeHtmlSafe(new Date(row.eventAt).toLocaleString())}</span>`
      : '';
    const originCol = currentRole === 'infosec' && row.originator && row.originator.toLowerCase() !== (currentUser?.email || '').toLowerCase()
      ? `<span class="ms-origin">${escapeHtmlSafe(row.originator)}</span>`
      : '<span class="ms-origin ms-origin--na">—</span>';
    return `<tr>
      <td><span class="badge badge-id">${escapeHtmlSafe(row.id)}</span></td>
      <td><strong>${escapeHtmlSafe(row.name)}</strong></td>
      <td><span class="badge badge-type">${escapeHtmlSafe(row.type)}</span></td>
      ${currentRole === 'infosec' ? `<td>${originCol}</td>` : ''}
      <td>${mySubmissionStatusBadge(row)}</td>
      <td class="ms-notes-cell">${mySubmissionNote(row)}${when}</td>
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
    const reviewBtn = workflowActionBtn('edit-asset', a.id, isAdmin ? 'Review' : 'Open (read-only)', 'btn btn-sm');
    let adminActions;
    if (isAdmin) {
      adminActions =
        workflowActionBtn('reject-pending', a.id, 'Reject', 'btn btn-sm btn-danger')
        + workflowActionBtn('delete-asset', a.id, 'Delete', 'btn btn-sm btn-danger', 'opacity:0.85')
        + workflowActionBtn('approve-asset', a.id, 'Approve', 'btn btn-sm btn-success');
    } else if (isInfoSec) {
      // Info Sec can withdraw their own pending submission with a logged reason.
      adminActions =
        '<span class="badge badge-mo" style="margin-left:8px">Awaiting CISO Review</span>'
        + workflowActionBtn('delete-asset', a.id, 'Withdraw', 'btn btn-sm btn-danger', 'margin-left:8px;opacity:0.9');
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

function showUsersTab(tab) {
  usersActiveTab = tab;
  document.querySelectorAll('.users-tab').forEach(btn => {
    const on = btn.dataset.usersTab === tab;
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-selected', on ? 'true' : 'false');
  });
  renderUserManagement();
}
window.showUsersTab = showUsersTab;

async function renderUserManagement() {
  const tbody = document.getElementById('users-body');
  const hint = document.getElementById('users-tab-hint');
  if (!tbody || !supabaseClient) return;
  if (currentRole !== 'infosec' && currentRole !== 'admin') {
    tbody.innerHTML = '<tr><td colspan="5">You do not have access to account approvals.</td></tr>';
    return;
  }

  tbody.innerHTML = '<tr><td colspan="5">Loading…</td></tr>';
  let rows = globalUserProfiles;
  if (!rows.length) {
    const { data, error } = await supabaseClient.from('user_profiles').select('*').order('created_at', { ascending: false });
    if (error) {
      tbody.innerHTML = `<tr><td colspan="5">Error: ${escapeHtmlSafe(error.message)}. Run supabase/master_setup.sql.</td></tr>`;
      return;
    }
    rows = globalUserProfiles = data || [];
  }

  const tab = usersActiveTab || 'pending';
  if (hint) {
    hint.textContent = tab === 'pending'
      ? 'Info Sec approves Standard User requests · Admin (CISO) approves Info Sec (and any other) requests.'
      : tab === 'active'
        ? 'Accounts that completed email verification and role approval.'
        : 'Declined account requests — applicants cannot sign in.';
  }

  let filtered = rows;
  if (tab === 'pending') filtered = rows.filter(p => p.account_status === 'pending');
  else if (tab === 'active') filtered = rows.filter(p => p.account_status === 'active');
  else if (tab === 'rejected') filtered = rows.filter(p => p.account_status === 'rejected');

  if (tab === 'pending') {
    filtered = filtered.sort((a, b) => {
      const aMine = canApproveUserProfile(a) ? 0 : 1;
      const bMine = canApproveUserProfile(b) ? 0 : 1;
      return aMine - bMine || new Date(b.created_at) - new Date(a.created_at);
    });
  }

  if (!filtered.length) {
    const empty = { pending: 'No accounts awaiting approval.', active: 'No active accounts.', rejected: 'No rejected accounts.' };
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;">${empty[tab] || 'No records.'}</td></tr>`;
    updateWorkflowBadges();
    return;
  }

  if (tab === 'pending') {
    tbody.innerHTML = filtered.map(p => {
      const canAct = canApproveUserProfile(p);
      const actions = canAct
        ? `<button type="button" class="btn btn-sm btn-success" onclick="approveUserAccount('${p.id}')">Approve</button>
           <button type="button" class="btn btn-sm btn-danger" onclick="rejectUserAccount('${p.id}')">Reject</button>`
        : `<span class="badge badge-type">${escapeHtmlSafe(approverLabelForRole(p.requested_role))}</span>`;
      return `<tr>
        <td>${escapeHtmlSafe(p.email)}</td>
        <td>${escapeHtmlSafe(roleLabel(p.requested_role))}</td>
        <td>${escapeHtmlSafe(approverLabelForRole(p.requested_role))}</td>
        <td><span class="badge badge-mo">Pending</span></td>
        <td>${actions}</td>
      </tr>`;
    }).join('');
  } else if (tab === 'active') {
    tbody.innerHTML = filtered.map(p => `<tr>
      <td>${escapeHtmlSafe(p.email)}</td>
      <td>${escapeHtmlSafe(roleLabel(p.approved_role || p.requested_role))}</td>
      <td>${escapeHtmlSafe(approverLabelForRole(p.requested_role))}</td>
      <td><span class="badge badge-lo">Active</span></td>
      <td style="font-size:11px;color:var(--text2)">${p.approved_at ? new Date(p.approved_at).toLocaleString() : '—'}</td>
    </tr>`).join('');
  } else {
    tbody.innerHTML = filtered.map(p => `<tr>
      <td>${escapeHtmlSafe(p.email)}</td>
      <td>${escapeHtmlSafe(roleLabel(p.requested_role))}</td>
      <td>—</td>
      <td><span class="badge badge-hi">Rejected</span></td>
      <td style="font-size:11px;color:var(--text2)">${escapeHtmlSafe(p.rejection_reason || '—')}</td>
    </tr>`).join('');
  }
  updateWorkflowBadges();
}

async function approveUserAccount(userId) {
  if (!currentUser) return;
  const { data: target } = await supabaseClient.from('user_profiles').select('*').eq('id', userId).single();
  if (!target) return notify('User not found.', true);
  if (!canApproveUserProfile(target)) {
    return notify(`This account must be approved by ${approverLabelForRole(target.requested_role)}.`, true);
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
  await syncUserProfilesQuiet();
  renderUserManagement();
  updateWorkflowBadges();
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
  await syncUserProfilesQuiet();
  renderUserManagement();
  updateWorkflowBadges();
}

async function syncUserProfilesQuiet() {
  if (!supabaseClient || !['infosec', 'admin'].includes(currentRole)) return;
  const { data, error } = await supabaseClient.from('user_profiles').select('*').order('created_at', { ascending: false });
  if (!error) globalUserProfiles = data || [];
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

// -------- CSV / IAR import — export (Excel column parity, MBSS + Firewall sheets) --------
const ASSET_CSV_COLUMNS = [
  'type', 'name', 'group_name', 'hostname', 'server', 'custodian', 'description',
  'ip_address', 'environment', 'department', 'asset_owners'
];

const CSV_SHEET1_HEADERS = ['Asset ID', 'Name of Asset', 'Description', 'Group', 'Hostname', 'Server', 'Custodian', 'IP Address', 'Environment', 'Department', 'Type', 'Asset owners'];
const CSV_SHEET2_HEADERS = ['Asset ID', 'Name of Asset', 'PII', 'SPI', 'Corp Info', 'C', 'I', 'A', 'Valuation', 'Class', 'Type', 'Classification justification', 'CIA questionnaire JSON'];
const CSV_SHEET3_HEADERS = ['Asset ID', 'Name of Asset', 'Risk / Threat Description', 'Probability', 'Severity', 'Inherent', 'Residual', 'Risk category key', 'Threat band', 'Vuln band', 'Risk basis JSON', 'Asset risks JSON'];
const CSV_SHEET4_HEADERS = ['Asset ID', 'Name of Asset', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C9', 'C10', 'C11', 'C12', 'C13', 'Residual', 'Strategy'];
const CSV_SHEET5_HEADERS = ['Asset ID', 'Name of Asset', 'Residual', 'Strategy', 'Status', 'Action Plan', 'Action Owner', 'Target Date'];
const CSV_SHEET6_HEADERS = ['Asset ID', 'Name of Asset', 'NIST CSF', 'ISO 27001 / 27002', 'CIS Controls', 'SOC 2', 'PCI-DSS'];

/**
 * MBSS-style host baseline — JSON keys in mbss_json (hardcoded contract).
 * Maps to CIS Controls v8 + NIST CSF 2.0 for ISMS evidence (organizational interpretation, not a substitute for full control implementation).
 */
const MBSS_FIELD_SPEC = [
  { key: 'edr_epp', header: 'EDR / EPP', yn: true, ref: 'CIS v8 10-malware defenses · NIST CSF PR.PT-5, DE.CM' },
  { key: 'patch_current', header: 'Patch current', yn: true, ref: 'CIS v8 7-maintenance · NIST PR.IP-3' },
  { key: 'disk_encryption', header: 'Disk encryption', yn: true, ref: 'CIS v8 3-data protection · NIST PR.DS-1' },
  { key: 'host_firewall', header: 'Host firewall', yn: true, ref: 'CIS v8 13-network monitoring & hardening · NIST PR.PT-4' },
  { key: 'admin_priv_review', header: 'Admin review', yn: true, ref: 'CIS v8 4–5-account & credential mgmt · NIST PR.AC-4, PR.PT-3' },
  { key: 'last_review_date', header: 'Last review date', yn: false, ref: 'ISO 27001 A.8.8-type evidence date' },
  { key: 'notes', header: 'MBSS notes', yn: false, ref: 'Narrative — tools, exceptions, compensating controls' },
];
const CSV_SHEET11_HEADERS = ['Asset ID', 'Name of Asset', ...MBSS_FIELD_SPEC.map(f => f.header)];

/**
 * Perimeter / firewall review — JSON keys in firewall_json (hardcoded contract).
 * Aligns with boundary-defense themes in CIS v8 §12 + NIST SP 800-53 / CSF SC, PR families.
 */
const FIREWALL_FIELD_SPEC = [
  { key: 'scope', header: 'Scope', yn: false, ref: 'CIS v8 12-boundaries · NIST SC-7, PR.AC-5' },
  { key: 'default_deny', header: 'Default deny', yn: true, ref: 'CIS 12.2 least-privilege paths · NIST SC-7(5)' },
  { key: 'change_control', header: 'Change control', yn: true, ref: 'CIS 4.x change mgmt · NIST CM-3, SA-10' },
  { key: 'logging_soc', header: 'Central logging', yn: true, ref: 'CIS 8-security logging · NIST AU-2, SI-4' },
  { key: 'rule_review_cadence', header: 'Rule review cadence', yn: false, ref: 'CIS 12.x lifecycle · NIST CA-2, PM-5' },
  { key: 'overly_permissive', header: 'Overly permissive rules', yn: true, ref: 'CIS 12.6 rule hygiene · NIST SC-7 continuous review' },
  { key: 'notes', header: 'Firewall notes', yn: false, ref: 'Narrative — rule IDs, risky allows, remediation' },
];
const CSV_SHEET12_HEADERS = ['Asset ID', 'Name of Asset', ...FIREWALL_FIELD_SPEC.map(f => f.header)];

/** Excel data-validation list sources (comma-separated; no commas inside one option). */
const XLSX_LIST_ASSET_TYPE = 'IA,PhA,PA,SA,SV,FA';
const XLSX_LIST_ENVIRONMENT = 'Internal,Internet Facing,Hybrid';
const XLSX_LIST_YN = 'Y,N';
const XLSX_LIST_CIA_1_3 = '1,2,3';
const XLSX_LIST_PROB_SEV = '1,2,3,4,5';
const XLSX_LIST_RISK_RATING = 'Very Low,Low,Moderate,High';
const XLSX_LIST_STRATEGY = 'Mitigate,Transfer,Avoid,Accept';
const XLSX_LIST_ACTION_STATUS = 'Pending,In Progress,Done';
const XLSX_LIST_CIA_CLASS = 'Public,Internal Use,Confidential,Restricted';
const XLSX_LIST_FW_SCOPE = 'Network firewall,WAF,Cloud NSG / SG,Host + perimeter,None documented';
/** Canonical rule-review rhythm (form + Excel validation + import expects exact spellings). */
const FW_REVIEW_CADENCE_CHOICES = ['Monthly', 'Quarterly', 'Semi-annual', 'Annual', 'Ad hoc'];
const XLSX_LIST_FW_CADENCE = FW_REVIEW_CADENCE_CHOICES.join(',');

const IAR_TEMPLATE_DATA_FIRST_ROW = 5;
const IAR_TEMPLATE_DATA_LAST_ROW = 400;

/** 1-based column index to Excel letters (1=A, 27=AA). */
function excelColLetter(n) {
  let result = '';
  let num = n;
  while (num > 0) {
    num--;
    result = String.fromCharCode(65 + (num % 26)) + result;
    num = Math.floor(num / 26);
  }
  return result;
}

function iarTemplateAddList(ws, col1Based, listCsv, dataFirstRow = IAR_TEMPLATE_DATA_FIRST_ROW) {
  const L = excelColLetter(col1Based);
  const a = `${L}${dataFirstRow}`;
  const b = `${L}${IAR_TEMPLATE_DATA_LAST_ROW}`;
  ws.dataValidations.add(`${a}:${b}`, {
    type: 'list',
    allowBlank: true,
    showInputMessage: true,
    promptTitle: 'Allowed values',
    prompt: 'Choose from the dropdown.',
    showErrorMessage: true,
    errorStyle: 'warning',
    errorTitle: 'Invalid entry',
    error: 'Pick a value from the list (ImpactLens import expects these exact tokens).',
    formulae: [`"${listCsv}"`]
  });
}

function getAssetsForIarExport() {
  return globalAssets.filter(a =>
    a.status === ASSET_STATUS.APPROVED || a.status === ASSET_STATUS.PENDING
  );
}

function escapeCsvCell(val) {
  const s = val == null ? '' : String(val);
  if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

/** Canonical risk_basis blob for CSV / Excel parity (structured bands + narratives). */
function exportRiskBasisJsonCell(asset) {
  const merged = { ...defaultRiskBasisObject(), ...parseJsonSafe(asset?.risk_basis_json, {}) };
  return JSON.stringify(merged);
}

/** asset_risks_json as JSON text (prefer array if parseable); round-trip aligned with importer. */
function exportAssetRisksJsonCell(asset) {
  const parsed = parseAssetRiskScenariosArray(asset?.asset_risks_json);
  if (parsed) return JSON.stringify(parsed);
  const raw = String(asset?.asset_risks_json ?? '').trim();
  return raw || '[]';
}

function csvThreatVulnBandsFromRiskBasis(asset) {
  const rb = { ...defaultRiskBasisObject(), ...parseJsonSafe(asset?.risk_basis_json, {}) };
  return [(rb.threat_choice != null && rb.threat_choice !== '') ? rb.threat_choice : 2,
    (rb.vulnerability_choice != null && rb.vulnerability_choice !== '') ? rb.vulnerability_choice : 2];
}

function downloadTextFile(filename, text, mime = 'text/csv;charset=utf-8') {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function parseCsvLine(line) {
  const out = [];
  let cur = '';
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') { inQ = !inQ; continue; }
    if (ch === ',' && !inQ) { out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur.trim());
  return out;
}

/** Map CSV header to internal key (aligned with Excel export labels). */
function normalizeCsvHeader(raw) {
  const t = (raw || '').trim().toLowerCase();
  const exact = {
    'asset id': 'id',
    'name of asset': 'name',
    description: 'description',
    group: 'group_name',
    hostname: 'hostname',
    server: 'server',
    custodian: 'custodian',
    'ip address': 'ip_address',
    environment: 'environment',
    department: 'department',
    type: 'type',
    pii: 'pii',
    spi: 'spi',
    'corp info': 'corp',
    c: 'ciaC',
    i: 'ciaI',
    a: 'ciaA',
    valuation: 'ciaScore',
    class: 'ciaClass',
    'risk / threat description': 'riskDesc',
    probability: 'prob',
    severity: 'sev',
    inherent: 'inherit',
    residual: 'residual',
    strategy: 'actionType',
    status: 'actionStatus',
    'action plan': 'actionPlan',
    'action owner': 'actionOwner',
    'target date': 'actionDate',
    'nist csf': '_nist',
    'iso 27001 / 27002': '_iso',
    'cis controls': '_cis',
    'soc 2': '_soc2',
    'pci-dss': '_pci',
    'edr / epp': 'mbss_edr_epp',
    'patch current': 'mbss_patch',
    'disk encryption': 'mbss_disk',
    'host firewall': 'mbss_hostfw',
    'admin review': 'mbss_admin',
    'last review date': 'mbss_lastdate',
    'mbss notes': 'mbss_notes',
    'firewall notes': 'fw_notes',
    scope: 'fw_scope',
    'default deny': 'fw_defaultdeny',
    'change control': 'fw_change',
    'central logging': 'fw_logging',
    'rule review cadence': 'fw_cadence',
    'overly permissive rules': 'fw_permissive',
    'asset owners': 'asset_owners',
    'classification justification': 'classification_justification',
    'cia questionnaire json': 'cia_questionnaire_json',
    'risk category key': 'riskCategory',
    'threat band': 'threat_band',
    'vuln band': 'vuln_band',
    'risk basis json': 'risk_basis_json',
    'asset risks json': 'asset_risks_json'
  };
  if (exact[t]) return exact[t];
  const rawTrim = (raw || '').trim();
  if (/^c\d+$/i.test(rawTrim)) return rawTrim.toUpperCase();
  return t.replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
}

function parseCsvToRows(text) {
  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n').filter(l => l.trim());
  if (!lines.length) return [];
  const headersRaw = parseCsvLine(lines[0]);
  const headersNorm = headersRaw.map(normalizeCsvHeader);
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const cells = parseCsvLine(lines[i]);
    if (cells.every(c => !c)) continue;
    const row = {};
    headersNorm.forEach((h, idx) => {
      if (!h || h.startsWith('_')) return;
      row[h] = cells[idx] || '';
    });
    rows.push(row);
  }
  return rows;
}

function detectCsvImportKind(keys) {
  const h = new Set(keys.filter(Boolean));
  if (h.has('C1') || h.has('C10')) return 'controls';
  if ((h.has('actionPlan') || h.has('actionType')) && (h.has('actionDate') || h.has('actionStatus'))) return 'treatment';
  if (h.has('_nist') || h.has('_iso')) return 'compliance';
  if (h.has('mbss_edr_epp') || h.has('mbss_patch')) return 'mbss';
  if (h.has('fw_scope') || (h.has('fw_cadence') && h.has('fw_defaultdeny'))) return 'firewall';
  if (h.has('inherit') || h.has('riskDesc') ||
      (h.has('id') && (h.has('threat_band') || h.has('vuln_band') || h.has('risk_basis_json') || h.has('asset_risks_json') || (h.has('riskCategory') && !h.has('description'))))) return 'risk';
  if (h.has('ciaScore') || (h.has('ciaC') && h.has('corp'))) return 'sensitivity';
  if (h.has('description') && h.has('type')) return 'identification';
  return 'legacy';
}

function ynCell(v) {
  const s = (v || '').toString().trim().toUpperCase();
  return s === 'Y' || s === 'YES' || s === 'TRUE' || s === '1' ? 'Y' : 'N';
}

function initAssetIdCounters() {
  const counters = {};
  globalAssets.forEach(row => {
    const parts = (row.id || '').split('-');
    if (parts.length !== 2) return;
    const t = parts[0];
    const num = parseInt(parts[1], 10);
    if (!isNaN(num)) counters[t] = Math.max(counters[t] || 0, num);
  });
  return counters;
}

function nextCsvAssetId(type, counters) {
  counters[type] = (counters[type] || 0) + 1;
  return `${type}-${String(counters[type]).padStart(3, '0')}`;
}

function buildDraftPayloadFromCsvRow(row, counters) {
  const type = (row.type || '').trim();
  const name = (row.name || '').trim();
  if (!type || !name) return { error: 'Row missing type or name' };
  if (!ALLOWED_ASSET_TYPES.has(type)) return { error: `Invalid type "${type}" (use IA, PhA, PA, SA, SV, FA)` };
  let id = (row.id || '').trim();
  if (id && globalAssets.some(a => a.id === id)) return { error: `Duplicate id ${id}` };
  if (!id) id = nextCsvAssetId(type, counters);
  const defaults = draftDefaultsFromType(type);
  return {
    id,
    type,
    name,
    status: ASSET_STATUS.DRAFT,
    group_name: row.group_name || '',
    hostname: row.hostname || '',
    server: row.server || '',
    custodian: row.custodian || '',
    description: row.description || '',
    ip_address: row.ip_address || '',
    environment: row.environment || 'Internal',
    department: row.department || '',
    asset_owners: row.asset_owners || '',
    created_by: currentUser?.email || null,
    updated_by: currentUser?.email || null,
    mbss_json: '{}',
    firewall_json: '{}',
    ...defaults
  };
}

async function patchAssetById(id, partial) {
  await directFetch('Assets', {
    method: 'PATCH',
    params: { id: 'eq.' + encodeURIComponent(id) },
    body: partial,
    prefer: 'return=minimal',
    timeoutMs: 15000
  });
}

async function replaceAssetControls(assetId, ctrlIds) {
  try {
    await directFetch('AssetControls', {
      method: 'DELETE',
      params: { asset_id: 'eq.' + assetId },
      prefer: 'return=minimal',
      timeoutMs: 8000
    });
  } catch (e) { console.warn('Ctrl cleanup:', e); }
  const controls = ctrlIds.map(cid => ({ asset_id: assetId, ctrl_id: cid }));
  if (controls.length) {
    await directFetch('AssetControls', {
      method: 'POST',
      body: controls,
      prefer: 'return=minimal',
      timeoutMs: 8000
    });
  }
}

function downloadAssetCsvTemplate() {
  const example = ['IA-999', 'Example Student Records', 'Description', 'Registrar', 'REG-DB-01', 'PostgreSQL', 'University Registrar',
    '10.0.0.1', 'Internal', 'Office of the Registrar', 'IA', 'Registrar / Data steward'].map(escapeCsvCell).join(',');
  downloadTextFile('ImpactLens_01_Asset_Identification_template.csv',
    CSV_SHEET1_HEADERS.map(escapeCsvCell).join(',') + '\n' + example + '\n');
}

function downloadAllIarCsvTemplates() {
  const stamp = new Date().toISOString().slice(0, 10);
  const sheets = [
    [`ImpactLens_01_Asset_Identification_template_${stamp}.csv`, CSV_SHEET1_HEADERS.join(',') + '\n'],
    [`ImpactLens_02_Sensitivity_template_${stamp}.csv`, CSV_SHEET2_HEADERS.join(',') + '\n'],
    [`ImpactLens_03_Risk_template_${stamp}.csv`, CSV_SHEET3_HEADERS.join(',') + '\n'],
    [`ImpactLens_04_Controls_template_${stamp}.csv`, CSV_SHEET4_HEADERS.join(',') + '\n'],
    [`ImpactLens_05_Treatment_template_${stamp}.csv`, CSV_SHEET5_HEADERS.join(',') + '\n'],
    [`ImpactLens_06_Compliance_template_${stamp}.csv`, CSV_SHEET6_HEADERS.join(',') + '\n'],
    [`ImpactLens_08_MBSS_template_${stamp}.csv`, CSV_SHEET11_HEADERS.join(',') + '\n'],
    [`ImpactLens_09_Firewall_template_${stamp}.csv`, CSV_SHEET12_HEADERS.join(',') + '\n']
  ];
  sheets.forEach(([name, body], i) => { setTimeout(() => downloadTextFile(name, body), i * 200); });
  notify('Downloading CSV templates (one file per sheet). Check your downloads folder.');
}

/**
 * Styled .xlsx workbook — same branding as audit export, column widths, and dropdowns.
 * CSV cannot hold bold, widths, or validation; use this for user-friendly data entry, then Save As CSV to import.
 */
async function downloadIarExcelTemplateWorkbook() {
  if (typeof ExcelJS === 'undefined') {
    notify('ExcelJS library not loaded.', true);
    return;
  }
  const COL_TITLE_BG = 'FF111118';
  const COL_TITLE_NEON = 'FFC8FF00';
  const COL_HDR_BG = 'FF1A1A22';
  const COL_HDR_FG = 'FFC8FF00';
  const COL_SUB_BG = 'FF2A2A35';
  const COL_BORDER = 'FFC0C0CC';

  const styleTitle = (ws, row, text, cols) => {
    ws.mergeCells(row, 1, row, cols);
    const c = ws.getCell(row, 1);
    c.value = text;
    c.font = { name: 'Calibri', size: 16, bold: true, color: { argb: COL_TITLE_NEON } };
    c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: COL_TITLE_BG } };
    c.alignment = { vertical: 'middle', horizontal: 'left', indent: 1 };
    c.border = { bottom: { style: 'medium', color: { argb: COL_TITLE_NEON } } };
    ws.getRow(row).height = 30;
  };
  const styleSubtitle = (ws, row, text, cols) => {
    ws.mergeCells(row, 1, row, cols);
    const c = ws.getCell(row, 1);
    c.value = text;
    c.font = { name: 'Calibri', size: 10, bold: true, italic: true, color: { argb: 'FFB5B5C5' } };
    c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: COL_SUB_BG } };
    c.alignment = { vertical: 'middle', horizontal: 'left', indent: 1 };
    ws.getRow(row).height = 18;
  };
  const styleHeaderRow = (ws, rowNum, colCount) => {
    for (let col = 1; col <= colCount; col++) {
      const c = ws.getCell(rowNum, col);
      c.font = { bold: true, color: { argb: COL_HDR_FG }, size: 10 };
      c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: COL_HDR_BG } };
      c.border = {
        top: { style: 'medium', color: { argb: COL_HDR_FG } },
        bottom: { style: 'medium', color: { argb: COL_HDR_FG } },
        left: { style: 'thin', color: { argb: COL_BORDER } },
        right: { style: 'thin', color: { argb: COL_BORDER } }
      };
      c.alignment = { vertical: 'middle', horizontal: 'center', wrapText: true };
    }
    ws.getRow(rowNum).height = 26;
  };
  const setWidths = (ws, widths) => {
    widths.forEach((w, i) => {
      ws.getColumn(i + 1).width = w;
    });
  };

  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const wb = new ExcelJS.Workbook();
  wb.creator = 'ImpactLens';
  wb.created = new Date();

  const hint = 'Fill rows below, then File → Save As → CSV (UTF-8) for Import CSV. Dropdowns work in Excel and LibreOffice Calc.';

  {
    const ws = wb.addWorksheet('1 — Asset ID', { views: [{ state: 'frozen', ySplit: 4 }] });
    styleTitle(ws, 1, 'IMPACTLENS  —  Template: Asset Identification', 12);
    styleSubtitle(ws, 2, hint + '  ·  Sheet 1 of 8', 12);
    ws.addRow([]);
    const hdr = ws.addRow(CSV_SHEET1_HEADERS);
    styleHeaderRow(ws, hdr.number, 12);
    const ex = ws.addRow(['IA-999', 'Example asset name', 'Short description', 'Unit / group', 'HOST-01', 'DB primary', 'Custodian name',
      '10.0.0.1 or Cloud', 'Internal', 'Department name', 'IA', 'One owner per line (optional)']);
    ex.font = { italic: true, color: { argb: 'FF6A6A78' } };
    iarTemplateAddList(ws, 9, XLSX_LIST_ENVIRONMENT);
    iarTemplateAddList(ws, 11, XLSX_LIST_ASSET_TYPE);
    setWidths(ws, [12, 38, 46, 18, 18, 22, 22, 16, 16, 22, 10, 28]);
  }

  {
    const ws = wb.addWorksheet('2 — Sensitivity', { views: [{ state: 'frozen', ySplit: 4 }] });
    styleTitle(ws, 1, 'IMPACTLENS  —  Sensitivity & Valuation', 13);
    styleSubtitle(ws, 2, hint + '  ·  Match Asset ID from sheet 1', 13);
    ws.addRow([]);
    const hdr = ws.addRow(CSV_SHEET2_HEADERS);
    styleHeaderRow(ws, hdr.number, 13);
    ws.addRow(['IA-999', 'Example asset', 'Y', 'Y', 'Y', '3', '3', '3', '9', 'Restricted', 'IA',
      'Brief justification for CIA / PI stance', '{"disclosure":"","integrity":"","availability":"","personal_data":"","corporate":""}']);
    for (const c of [3, 4, 5]) iarTemplateAddList(ws, c, XLSX_LIST_YN);
    for (const c of [6, 7, 8]) iarTemplateAddList(ws, c, XLSX_LIST_CIA_1_3);
    iarTemplateAddList(ws, 10, XLSX_LIST_CIA_CLASS);
    iarTemplateAddList(ws, 11, XLSX_LIST_ASSET_TYPE);
    setWidths(ws, [12, 38, 6, 6, 9, 5, 5, 5, 10, 18, 8, 36, 48]);
  }

  {
    const ws = wb.addWorksheet('3 — Risk', { views: [{ state: 'frozen', ySplit: 4 }] });
    styleTitle(ws, 1, 'IMPACTLENS  —  Risk Assessment', 12);
    styleSubtitle(ws, 2, hint, 12);
    ws.addRow([]);
    const hdr = ws.addRow(CSV_SHEET3_HEADERS);
    styleHeaderRow(ws, hdr.number, 12);
    ws.addRow(['IA-999', 'Example', 'Describe threat / scenario', '3', '4', 'Moderate', 'Low', '',
      '2', '2', '', '[]']);
    iarTemplateAddList(ws, 4, XLSX_LIST_PROB_SEV);
    iarTemplateAddList(ws, 5, XLSX_LIST_PROB_SEV);
    iarTemplateAddList(ws, 6, XLSX_LIST_RISK_RATING);
    iarTemplateAddList(ws, 7, XLSX_LIST_RISK_RATING);
    iarTemplateAddList(ws, 9, XLSX_LIST_CIA_1_3);
    iarTemplateAddList(ws, 10, XLSX_LIST_CIA_1_3);
    setWidths(ws, [12, 38, 60, 12, 10, 14, 14, 24, 8, 8, 40, 42]);
  }

  {
    const ws = wb.addWorksheet('4 — Controls', { views: [{ state: 'frozen', ySplit: 5, xSplit: 2 }] });
    styleTitle(ws, 1, 'IMPACTLENS  —  Controls C1–C13', 17);
    styleSubtitle(ws, 2, hint + '  ·  C1–C13 = Y/N', 17);
    ws.addRow([]);
    const leg = ws.addRow(['Legend', 'C1 Procedures · C2 SoD · C3 RBAC · C4 MFA · C5 Physical · C6 Backup · C7 Encryption · C8 Disposal · C9 EDR · C10 WAF · C11 Vuln · C12 VLAN · C13 IRP']);
    ws.mergeCells(leg.number, 2, leg.number, 17);
    leg.getCell(1).font = { italic: true, color: { argb: 'FF6A6A78' } };
    const hdr = ws.addRow(CSV_SHEET4_HEADERS);
    styleHeaderRow(ws, hdr.number, 17);
    const cells = ['IA-999', 'Example'];
    for (let i = 0; i < 13; i++) cells.push('N');
    cells.push('Moderate', 'Mitigate');
    ws.addRow(cells);
    for (let c = 3; c <= 15; c++) iarTemplateAddList(ws, c, XLSX_LIST_YN);
    iarTemplateAddList(ws, 16, XLSX_LIST_RISK_RATING);
    iarTemplateAddList(ws, 17, XLSX_LIST_STRATEGY);
    const widths = [12, 32];
    for (let i = 0; i < 13; i++) widths.push(5);
    widths.push(14, 14);
    setWidths(ws, widths);
  }

  {
    const ws = wb.addWorksheet('5 — Treatment', { views: [{ state: 'frozen', ySplit: 4 }] });
    styleTitle(ws, 1, 'IMPACTLENS  —  Residual & Treatment', 8);
    styleSubtitle(ws, 2, hint, 8);
    ws.addRow([]);
    const hdr = ws.addRow(CSV_SHEET5_HEADERS);
    styleHeaderRow(ws, hdr.number, 8);
    ws.addRow(['IA-999', 'Example', 'Low', 'Mitigate', 'In Progress', 'Action text', 'Owner', '2026-12-31']);
    iarTemplateAddList(ws, 3, XLSX_LIST_RISK_RATING);
    iarTemplateAddList(ws, 4, XLSX_LIST_STRATEGY);
    iarTemplateAddList(ws, 5, XLSX_LIST_ACTION_STATUS);
    setWidths(ws, [12, 38, 14, 14, 14, 48, 20, 14]);
  }

  {
    const ws = wb.addWorksheet('6 — Compliance note', { views: [{ state: 'frozen', ySplit: 4 }] });
    styleTitle(ws, 1, 'Compliance mapping (export-only)', 7);
    styleSubtitle(ws, 2, 'This sheet is filled automatically when you export from ImpactLens or run CSV pack Export 06. No import.', 7);
    ws.addRow([]);
    const hdr = ws.addRow(CSV_SHEET6_HEADERS);
    styleHeaderRow(ws, hdr.number, 7);
    setWidths(ws, [12, 38, 28, 32, 24, 22, 22]);
  }

  {
    const COL_LEG = 'FF6A6A78';
    const ws = wb.addWorksheet('8 — MBSS Endpoint Baseline', { views: [{ state: 'frozen', ySplit: 5 }] });
    styleTitle(ws, 1, 'IMPACTLENS  —  MBSS-style endpoint baseline (CIS v8 + NIST CSF)', 9);
    styleSubtitle(ws, 2, hint, 9);
    const leg = ws.addRow([MBSS_FIELD_SPEC.map(f => `${f.header}: ${f.ref}`).join(' · ')]);
    ws.mergeCells(leg.number, 1, leg.number, 9);
    leg.getCell(1).font = { italic: true, size: 9, color: { argb: COL_LEG } };
    leg.getCell(1).alignment = { wrapText: true, vertical: 'top' };
    leg.height = 36;
    const hdr = ws.addRow(CSV_SHEET11_HEADERS);
    styleHeaderRow(ws, hdr.number, 9);
    const DATA0 = 6;
    ws.addRow(['IA-999', 'Example', 'Y', 'Y', 'Y', 'Y', 'Y', '2026-06-01', 'Notes here']);
    for (const c of [3, 4, 5, 6, 7]) iarTemplateAddList(ws, c, XLSX_LIST_YN, DATA0);
    setWidths(ws, [12, 36, 9, 9, 9, 9, 9, 14, 48]);
  }

  {
    const COL_LEG = 'FF6A6A78';
    const ws = wb.addWorksheet('9 — Firewall Perimeter Review', { views: [{ state: 'frozen', ySplit: 5 }] });
    styleTitle(ws, 1, 'IMPACTLENS  —  Firewall perimeter review (CIS v8 §12 + NIST SC)', 9);
    styleSubtitle(ws, 2, hint, 9);
    const leg = ws.addRow([FIREWALL_FIELD_SPEC.map(f => `${f.header}: ${f.ref}`).join(' · ')]);
    ws.mergeCells(leg.number, 1, leg.number, 9);
    leg.getCell(1).font = { italic: true, size: 9, color: { argb: COL_LEG } };
    leg.getCell(1).alignment = { wrapText: true, vertical: 'top' };
    leg.height = 36;
    const hdr = ws.addRow(CSV_SHEET12_HEADERS);
    styleHeaderRow(ws, hdr.number, 9);
    const DATA0 = 6;
    ws.addRow(['IA-999', 'Example', 'WAF', 'Y', 'Y', 'Y', 'Quarterly', 'N', 'Rule review notes']);
    iarTemplateAddList(ws, 3, XLSX_LIST_FW_SCOPE, DATA0);
    for (const c of [4, 5, 6, 8]) iarTemplateAddList(ws, c, XLSX_LIST_YN, DATA0);
    iarTemplateAddList(ws, 7, XLSX_LIST_FW_CADENCE, DATA0);
    setWidths(ws, [12, 36, 24, 12, 12, 12, 16, 12, 48]);
  }

  const buf = await wb.xlsx.writeBuffer();
  const blob = new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ImpactLens_IAR_Entry_Templates_${stamp}.xlsx`;
  a.click();
  URL.revokeObjectURL(url);
  notify('Downloaded styled Excel templates with dropdowns. CSV files stay plain — use Excel for pick-lists, then export CSV to import.');
}

function csvLine(headers, values) {
  return headers.map((_, i) => escapeCsvCell(values[i])).join(',');
}

function exportIarCsvPack() {
  if (currentRole !== 'infosec' && currentRole !== 'admin') {
    notify('CSV export requires Info Sec or Admin role.', true);
    return;
  }
  const assets = getAssetsForIarExport();
  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');

  const s1 = [CSV_SHEET1_HEADERS.join(',')].concat(assets.map(a => csvLine(CSV_SHEET1_HEADERS, [
    a.id, a.name, a.description, a.group_name, a.hostname, a.server, a.custodian, a.ip_address, a.environment, a.department, a.type,
    (a.asset_owners != null && String(a.asset_owners).trim()) ? String(a.asset_owners).trim() : ''
  ]))).join('\n');

  const s2 = [CSV_SHEET2_HEADERS.join(',')].concat(assets.map(a => {
    const ciaQ = (() => {
      const raw = a.cia_questionnaire_json;
      if (raw == null || !String(raw).trim()) return '';
      const q = parseJsonSafe(String(raw).trim(), null);
      return (q !== null && typeof q === 'object' && !Array.isArray(q)) ? JSON.stringify(q) : String(raw).trim();
    })();
    return csvLine(CSV_SHEET2_HEADERS, [
      a.id, a.name, a.pii === 'Y' ? 'Y' : 'N', a.spi === 'Y' ? 'Y' : 'N', a.corp === 'Y' ? 'Y' : 'N',
      a.ciaC, a.ciaI, a.ciaA, a.ciaScore, a.ciaClass, a.type,
      (a.classification_justification != null && String(a.classification_justification).trim())
        ? String(a.classification_justification).trim() : '',
      ciaQ
    ]);
  })).join('\n');

  const s3 = [CSV_SHEET3_HEADERS.join(',')].concat(assets.map(a => {
    const bands = csvThreatVulnBandsFromRiskBasis(a);
    return csvLine(CSV_SHEET3_HEADERS, [
      a.id, a.name, a.riskDesc || '', a.prob, a.sev, a.inherit, a.residual,
      (a.riskCategory != null && String(a.riskCategory).trim()) ? String(a.riskCategory).trim() : '',
      bands[0], bands[1], exportRiskBasisJsonCell(a), exportAssetRisksJsonCell(a)
    ]);
  })).join('\n');

  const s4 = [CSV_SHEET4_HEADERS.join(',')].concat(assets.map(a => {
    const ctrlIds = new Set(globalControls.filter(c => c.asset_id === a.id).map(c => c.ctrl_id));
    const cells = [a.id, a.name];
    for (let i = 1; i <= 13; i++) cells.push(ctrlIds.has(i) ? 'Y' : 'N');
    cells.push(a.residual, a.actionType);
    return csvLine(CSV_SHEET4_HEADERS, cells);
  })).join('\n');

  const s5 = [CSV_SHEET5_HEADERS.join(',')].concat(assets.map(a => csvLine(CSV_SHEET5_HEADERS, [
    a.id, a.name, a.residual, a.actionType, a.actionStatus, a.actionPlan, a.actionOwner, a.actionDate
  ]))).join('\n');

  const s6 = [CSV_SHEET6_HEADERS.join(',')].concat(assets.map(a => {
    const ctrlIds = globalControls.filter(c => c.asset_id === a.id).map(c => c.ctrl_id);
    const fw = getFrameworksForControls(ctrlIds, a.type);
    return csvLine(CSV_SHEET6_HEADERS, [a.id, a.name, fw.nist, fw.iso, fw.cis, fw.soc2, fw.pci]);
  })).join('\n');

  const s11 = [CSV_SHEET11_HEADERS.join(',')].concat(assets.map(a => {
    const m = parseJsonSafe(a.mbss_json, {});
    const cells = [a.id, a.name, ...MBSS_FIELD_SPEC.map(f => {
      const v = m[f.key];
      if (f.yn) return v === 'Y' ? 'Y' : 'N';
      return (v != null && v !== '') ? String(v) : '';
    })];
    return csvLine(CSV_SHEET11_HEADERS, cells);
  })).join('\n');

  const s12 = [CSV_SHEET12_HEADERS.join(',')].concat(assets.map(a => {
    const f = parseJsonSafe(a.firewall_json, {});
    const cells = [a.id, a.name, ...FIREWALL_FIELD_SPEC.map(fl => {
      const v = f[fl.key];
      if (fl.yn) return v === 'Y' ? 'Y' : 'N';
      return (v != null && v !== '') ? String(v) : '';
    })];
    return csvLine(CSV_SHEET12_HEADERS, cells);
  })).join('\n');

  const files = [
    [`ImpactLens_${stamp}_01_Asset_Identification.csv`, s1],
    [`ImpactLens_${stamp}_02_Sensitivity_Valuation.csv`, s2],
    [`ImpactLens_${stamp}_03_Risk_Assessment.csv`, s3],
    [`ImpactLens_${stamp}_04_Controls_C1-C13.csv`, s4],
    [`ImpactLens_${stamp}_05_Residual_Treatment.csv`, s5],
    [`ImpactLens_${stamp}_06_Compliance_Mapping.csv`, s6],
    [`ImpactLens_${stamp}_08_MBSS_Baseline.csv`, s11],
    [`ImpactLens_${stamp}_09_Firewall_Review.csv`, s12]
  ];
  (async () => {
    for (const [fn, body] of files) {
      downloadTextFile(fn, body);
      await sleep(280);
    }
    notify(`Exported ${files.length} CSV files (all IAR sheets with data; ${assets.length} assets).`);
  })();
}

function triggerAssetCsvImport() {
  if (!currentUser) {
    notify('Sign in to import a CSV.', true);
    return;
  }
  if (!['user', 'infosec', 'admin'].includes(currentRole || '')) {
    notify('Your role cannot import CSV files.', true);
    return;
  }
  document.getElementById('asset-csv-input')?.click();
}

async function handleAssetCsvFileSelected(ev) {
  const file = ev.target?.files?.[0];
  ev.target.value = '';
  if (!file) return;
  if (!/\.csv$/i.test(file.name)) {
    notify('Please select a .csv file.', true);
    return;
  }
  try {
    const text = await file.text();
    await importAssetsFromCsvText(text);
  } catch (err) {
    notify('Could not read CSV: ' + (err.message || err), true);
  }
}

async function importAssetsFromCsvText(text) {
  if (!supabaseClient || !currentAccessToken) {
    notify('Sign in again to import assets.', true);
    return;
  }
  const rows = parseCsvToRows(text);
  if (!rows.length) {
    notify('CSV is empty or has no data rows.', true);
    return;
  }
  const kind = detectCsvImportKind(Object.keys(rows[0]));
  if (currentRole === 'user') {
    if (kind !== 'identification' && kind !== 'legacy') {
      notify('As a Standard User you can only import Sheet 1 — Asset Identification (or the legacy template). Info Sec completes other sheets.', true);
      return;
    }
  } else if (currentRole !== 'infosec' && currentRole !== 'admin') {
    notify('CSV import requires a signed-in role with import access.', true);
    return;
  }
  try {
    if (kind === 'legacy') return await importCsvIdentificationLegacy(rows);
    if (kind === 'identification') return await importCsvIdentification(rows);
    if (kind === 'sensitivity') return await importCsvSensitivity(rows);
    if (kind === 'risk') return await importCsvRisk(rows);
    if (kind === 'controls') return await importCsvControls(rows);
    if (kind === 'treatment') return await importCsvTreatment(rows);
    if (kind === 'mbss') return await importCsvMbss(rows);
    if (kind === 'firewall') return await importCsvFirewall(rows);
    if (kind === 'compliance') {
      notify('Compliance sheet is export-only (derived from controls). Import sheets 1–5, 11, or 12.', true);
      return;
    }
    return await importCsvIdentificationLegacy(rows);
  } catch (err) {
    notify('CSV import failed: ' + (err.message || err), true);
  }
}

async function importCsvIdentificationLegacy(rows) {
  const counters = initAssetIdCounters();
  const payloads = [];
  const errors = [];
  rows.forEach((row, idx) => {
    const built = buildDraftPayloadFromCsvRow(row, counters);
    if (built.error) errors.push(`Row ${idx + 2}: ${built.error}`);
    else payloads.push(built);
  });
  if (!payloads.length) {
    notify(errors[0] || 'No valid rows.', true);
    return;
  }
  await directFetch('Assets', { method: 'POST', body: payloads, prefer: 'resolution=merge-duplicates,return=minimal', timeoutMs: 25000 });
  await logSystemEvent('ASSET_CSV_IMPORTED', `Imported ${payloads.length} Draft (legacy CSV) · ${currentUser?.email || ''}`);
  await syncFromCloud(true);
  notify(`Imported ${payloads.length} Draft asset(s).${errors.length ? ' (' + errors.length + ' skipped.)' : ''}`);
  updateWorkflowBadges();
}

async function importCsvIdentification(rows) {
  const counters = initAssetIdCounters();
  const payloads = [];
  const errors = [];
  rows.forEach((row, idx) => {
    const id = (row.id || '').trim();
    const type = (row.type || '').trim();
    const name = (row.name || '').trim();
    if (!type || !name) { errors.push(`Row ${idx + 2}: missing type or name`); return; }
    if (!ALLOWED_ASSET_TYPES.has(type)) { errors.push(`Row ${idx + 2}: invalid type`); return; }
    let fid = id;
    if (fid && globalAssets.some(a => a.id === fid)) { errors.push(`Row ${idx + 2}: duplicate ${fid}`); return; }
    if (!fid) fid = nextCsvAssetId(type, counters);
    const defaults = draftDefaultsFromType(type);
    payloads.push({
      id: fid, type, name, status: ASSET_STATUS.DRAFT,
      group_name: row.group_name || '', hostname: row.hostname || '', server: row.server || '', custodian: row.custodian || '',
      description: row.description || '', ip_address: row.ip_address || '', environment: row.environment || 'Internal',
      department: row.department || '', asset_owners: row.asset_owners || '',
      created_by: currentUser?.email || null, updated_by: currentUser?.email || null,
      mbss_json: '{}', firewall_json: '{}', ...defaults
    });
  });
  if (!payloads.length) { notify(errors[0] || 'No valid rows.', true); return; }
  await directFetch('Assets', { method: 'POST', body: payloads, prefer: 'resolution=merge-duplicates,return=minimal', timeoutMs: 25000 });
  await logSystemEvent('ASSET_CSV_IMPORTED', `Imported ${payloads.length} Draft (Sheet 1 layout) · ${currentUser?.email || ''}`);
  await syncFromCloud(true);
  notify(`Imported ${payloads.length} Draft asset(s).`);
  updateWorkflowBadges();
}

async function importCsvSensitivity(rows) {
  let n = 0;
  for (const row of rows) {
    const id = (row.id || '').trim();
    if (!id || !globalAssets.some(x => x.id === id)) continue;
    const a = globalAssets.find(x => x.id === id);
    const partial = {
      pii: ynCell(row.pii),
      spi: ynCell(row.spi),
      corp: ynCell(row.corp),
      updated_by: currentUser?.email || null
    };
    partial.ciaC = clampCia(parseInt(row.ciaC, 10) || normalizeCiaStored(a.ciaC));
    partial.ciaI = clampCia(parseInt(row.ciaI, 10) || normalizeCiaStored(a.ciaI));
    partial.ciaA = clampCia(parseInt(row.ciaA, 10) || normalizeCiaStored(a.ciaA));
    partial.ciaScore = ciaMax(partial.ciaC, partial.ciaI, partial.ciaA);
    partial.ciaClass = ciaClassFromValues(partial.ciaC, partial.ciaI, partial.ciaA);
    if (row.ciaClass != null && String(row.ciaClass).trim())
      partial.ciaClass = String(row.ciaClass).trim();
    if (row.classification_justification != null && String(row.classification_justification).trim())
      partial.classification_justification = String(row.classification_justification).trim();
    if (row.cia_questionnaire_json != null && String(row.cia_questionnaire_json).trim()) {
      const qRaw = String(row.cia_questionnaire_json).trim();
      const qp = parseJsonSafe(qRaw, null);
      if (qp !== null && typeof qp === 'object' && !Array.isArray(qp))
        partial.cia_questionnaire_json = JSON.stringify(qp);
    }
    await patchAssetById(id, partial);
    n++;
  }
  await logSystemEvent('ASSET_CSV_IMPORTED', `Sensitivity CSV merged · ${n} row(s) · ${currentUser?.email || ''}`);
  await syncFromCloud(true);
  notify(`Updated ${n} asset(s) from Sensitivity CSV.`);
}

async function importCsvRisk(rows) {
  let n = 0;
  for (const row of rows) {
    const id = (row.id || '').trim();
    if (!id || !globalAssets.some(x => x.id === id)) continue;
    const a = globalAssets.find(x => x.id === id);
    const patch = { updated_by: currentUser?.email || null };

    patch.riskDesc = (row.riskDesc != null && String(row.riskDesc).trim() !== '')
      ? row.riskDesc
      : (a.riskDesc || '');
    const pNum = parseInt(row.prob, 10);
    const sNum = parseInt(row.sev, 10);
    patch.prob = !isNaN(pNum) ? pNum : (parseInt(a.prob, 10) || 3);
    patch.sev = !isNaN(sNum) ? sNum : (parseInt(a.sev, 10) || 3);
    patch.inherit = (row.inherit != null && String(row.inherit).trim())
      ? String(row.inherit).trim()
      : (a.inherit || 'Moderate');
    patch.residual = (row.residual != null && String(row.residual).trim())
      ? String(row.residual).trim()
      : (a.residual || 'Moderate');
    if (row.riskCategory != null && String(row.riskCategory).trim())
      patch.riskCategory = String(row.riskCategory).trim();

    let rb = { ...defaultRiskBasisObject(), ...parseJsonSafe(a.risk_basis_json, {}) };
    if (row.risk_basis_json != null && String(row.risk_basis_json).trim()) {
      const j = parseJsonSafe(String(row.risk_basis_json).trim(), null);
      if (j && typeof j === 'object' && !Array.isArray(j)) rb = { ...rb, ...j };
    }
    const tb = parseInt(row.threat_band, 10);
    const vb = parseInt(row.vuln_band, 10);
    if (!isNaN(tb) && tb >= 1 && tb <= 5) rb.threat_choice = tb;
    if (!isNaN(vb) && vb >= 1 && vb <= 5) rb.vulnerability_choice = vb;
    patch.risk_basis_json = JSON.stringify(rb);

    if (row.asset_risks_json != null && String(row.asset_risks_json).trim()) {
      const ar = parseJsonSafe(String(row.asset_risks_json).trim(), null);
      if (Array.isArray(ar)) patch.asset_risks_json = JSON.stringify(ar.map(normalizeImportedRiskScenarioRow));
    }

    await patchAssetById(id, patch);
    n++;
  }
  await logSystemEvent('ASSET_CSV_IMPORTED', `Risk CSV merged · ${n} row(s)`);
  await syncFromCloud(true);
  notify(`Updated ${n} asset(s) from Risk Assessment CSV.`);
}

async function importCsvControls(rows) {
  let n = 0;
  for (const row of rows) {
    const id = (row.id || '').trim();
    if (!id || !globalAssets.some(x => x.id === id)) continue;
    const ctrlIds = [];
    for (let c = 1; c <= 13; c++) {
      const key = 'C' + c;
      if (ynCell(row[key]) === 'Y') ctrlIds.push(c);
    }
    await replaceAssetControls(id, ctrlIds);
    const patch = { updated_by: currentUser?.email || null };
    if (row.residual) patch.residual = row.residual;
    if (row.actionType) patch.actionType = row.actionType;
    await patchAssetById(id, patch);
    n++;
  }
  await logSystemEvent('ASSET_CSV_IMPORTED', `Controls CSV merged · ${n} asset(s)`);
  await syncFromCloud(true);
  notify(`Imported controls for ${n} asset(s).`);
}

async function importCsvTreatment(rows) {
  let n = 0;
  for (const row of rows) {
    const id = (row.id || '').trim();
    if (!id || !globalAssets.some(x => x.id === id)) continue;
    await patchAssetById(id, {
      residual: row.residual || undefined,
      actionType: row.actionType || undefined,
      actionStatus: row.actionStatus || undefined,
      actionPlan: row.actionPlan || undefined,
      actionOwner: row.actionOwner || undefined,
      actionDate: row.actionDate || undefined,
      updated_by: currentUser?.email || null
    });
    n++;
  }
  await logSystemEvent('ASSET_CSV_IMPORTED', `Treatment CSV merged · ${n} asset(s)`);
  await syncFromCloud(true);
  notify(`Updated treatment for ${n} asset(s).`);
}

async function importCsvMbss(rows) {
  let n = 0;
  for (const row of rows) {
    const id = (row.id || '').trim();
    if (!id || !globalAssets.some(x => x.id === id)) continue;
    const m = {
      edr_epp: ynCell(row.mbss_edr_epp),
      patch_current: ynCell(row.mbss_patch),
      disk_encryption: ynCell(row.mbss_disk),
      host_firewall: ynCell(row.mbss_hostfw),
      admin_priv_review: ynCell(row.mbss_admin),
      last_review_date: (row.mbss_lastdate || '').trim(),
      notes: (row.mbss_notes || '').trim()
    };
    await patchAssetById(id, { mbss_json: JSON.stringify(m), updated_by: currentUser?.email || null });
    n++;
  }
  await syncFromCloud(true);
  notify(`Updated MBSS baseline for ${n} asset(s). Run supabase/hotfix_mbss_firewall_columns.sql if PATCH fails.`);
}

async function importCsvFirewall(rows) {
  let n = 0;
  for (const row of rows) {
    const id = (row.id || '').trim();
    if (!id || !globalAssets.some(x => x.id === id)) continue;
    const f = {
      scope: (row.fw_scope || '').trim(),
      default_deny: ynCell(row.fw_defaultdeny),
      change_control: ynCell(row.fw_change),
      logging_soc: ynCell(row.fw_logging),
      rule_review_cadence: (row.fw_cadence || '').trim(),
      overly_permissive: ynCell(row.fw_permissive),
      notes: (row.fw_notes || '').trim()
    };
    await patchAssetById(id, { firewall_json: JSON.stringify(f), updated_by: currentUser?.email || null });
    n++;
  }
  await syncFromCloud(true);
  notify(`Updated firewall review for ${n} asset(s).`);
}

/** Standard User: approved register only, Sheet 1 column layout (aligned with CSV template / IAR pack sheet 01). */
function exportUserAssetTableCsv() {
  if (!currentUser) {
    notify('Sign in to export.', true);
    return;
  }
  if (currentRole !== 'user') return;
  const assets = approvedAssetsOnly();
  if (!assets.length) {
    notify('No approved records to export.', true);
    return;
  }
  const body = [CSV_SHEET1_HEADERS.join(',')].concat(assets.map(a => csvLine(CSV_SHEET1_HEADERS, [
    a.id, a.name, a.description || '', a.group_name || '', a.hostname || '', a.server || '', a.custodian || '',
    a.ip_address || '', a.environment || '', a.department || '', a.type,
    (a.asset_owners != null && String(a.asset_owners).trim()) ? String(a.asset_owners).trim() : ''
  ]))).join('\n');
  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  downloadTextFile(`ImpactLens_Approved_Register_${stamp}.csv`, body);
  notify(`Exported ${assets.length} approved asset row(s) (identification columns).`);
}

function exportAssetRegisterCsv() {
  if (currentRole !== 'infosec' && currentRole !== 'admin') {
    notify('CSV export requires Info Sec or Admin role.', true);
    return;
  }
  const headers = ['id', 'status', 'type', 'name', ...ASSET_CSV_COLUMNS.filter(c => c !== 'type' && c !== 'name'),
    'ciaScore', 'ciaClass', 'classification_justification', 'cia_questionnaire_json',
    'inherit', 'residual', 'riskCategory', 'riskDesc', 'prob', 'sev',
    'risk_basis_json', 'asset_risks_json', 'mbss_json', 'firewall_json'];
  const rows = globalAssets.map(a => [
    a.id, a.status, a.type, a.name, a.group_name, a.hostname, a.server, a.custodian, a.description,
    a.ip_address, a.environment, a.department, (a.asset_owners || '').trim() ? a.asset_owners : '',
    a.ciaScore, a.ciaClass,
    (a.classification_justification || '').trim() ? a.classification_justification : '',
    (() => {
      const raw = a.cia_questionnaire_json;
      if (raw == null || !String(raw).trim()) return '';
      const q = parseJsonSafe(String(raw).trim(), null);
      return (q !== null && typeof q === 'object' && !Array.isArray(q)) ? JSON.stringify(q) : String(raw).trim();
    })(),
    a.inherit, a.residual, a.riskCategory, a.riskDesc, a.prob, a.sev,
    exportRiskBasisJsonCell(a), exportAssetRisksJsonCell(a),
    a.mbss_json || '', a.firewall_json || ''
  ].map(escapeCsvCell));
  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const stamp = new Date().toISOString().slice(0, 10);
  downloadTextFile(`ImpactLens_Register_quick_${stamp}.csv`, csv);
  notify(`Quick export: ${globalAssets.length} asset row(s).`);
}

function renderRegister() {
  const tbody = document.getElementById('reg-body');
  if (!tbody) return;
  const regDesc = document.getElementById('reg-page-desc');
  if (regDesc) {
    regDesc.textContent = currentRole === 'user'
      ? '// Official approved register (read-only). CSV template + Import CSV create Drafts for Info Sec.'
      : '// Approved register — CSV import creates Draft assets for profiling';
  }
  const data = approvedAssetsOnly();
  const isUser = currentRole === 'user';
  const colSpan = 6;

  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="${colSpan}" style="text-align:center;">No approved records.</td></tr>`;
    return;
  }

  tbody.innerHTML = data.map(a => {
    const actionsCell = isUser
      ? '<span style="color:var(--text3);font-size:11px;">View in register</span>'
      : `${workflowActionBtn('edit-asset', a.id, 'Edit', 'btn btn-sm')}`
        + `${workflowActionBtn('delete-asset', a.id, 'Del', 'btn btn-sm btn-danger', 'margin-left:4px')}`;
    return `
    <tr>
      <td><span class="badge badge-id">${a.id}</span></td>
      <td><strong>${a.name}</strong></td>
      <td><span class="badge badge-type">${a.type}</span></td>
      <td style="color:var(--text2)">${a.group_name || '—'}</td>
      <td style="color:var(--text2)">${a.hostname || '—'}</td>
      <td>${actionsCell}</td>
    </tr>
  `;
  }).join('');
}

function renderRiskRegister() {
  let data = [...approvedAssetsOnly()];
  data.sort((a, b) => {
    const order = { High: 0, Moderate: 1, Low: 2, 'Very Low': 3 };
    const ra = liveRegisterMetricsForAsset(a).residual;
    const rb = liveRegisterMetricsForAsset(b).residual;
    const diff = (order[ra] || 4) - (order[rb] || 4);
    if (diff !== 0) return diff;
    const ia = liveRegisterMetricsForAsset(a).inherit;
    const ib = liveRegisterMetricsForAsset(b).inherit;
    return (order[ia] || 4) - (order[ib] || 4);
  });

  const tbody = document.getElementById('risk-body');
  if (!tbody) return;

  if (!data.length) { tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;">No records in DB.</td></tr>`; return; }

  const pxs = (p, s) => (p && s ? `<div style="font-size:9px;color:var(--text3);margin-top:2px;">P${p}×S${s}</div>` : '');

  tbody.innerHTML = data.map(a => {
    const repr = liveRegisterMetricsForAsset(a);
    const inh = repr.inherit || a.inherit;
    const res = repr.residual || a.residual;
    const ctrls = globalControls.filter(c => c.asset_id === a.id).length;
    const rc = parsedRiskScenarioCountForAsset(a);
    const snippet = escapeHtmlSafe((a.riskDesc || '—').substring(0, 60));
    const more = (a.riskDesc || '').length > 60 ? '…' : '';
    const multi = rc > 1 ? ` <span style="color:var(--accent2);font-weight:600;">(${rc} risks)</span>` : '';
    const resP = repr.resProb ?? Math.max(1, (repr.prob || 3) - 1);
    const resS = repr.resSev ?? Math.max(1, (repr.sev || 3) - 1);
    const gapHint = (repr.controlGaps && repr.controlGaps.length)
      ? `<div style="font-size:9px;color:var(--warn);margin-top:2px;">↑ control gap floor</div>` : '';
    return `
    <tr>
      <td><span class="badge badge-id">${a.id}</span></td>
      <td><strong>${escapeHtmlSafe(a.name || '')}</strong></td>
      <td style="color:var(--text2);font-size:11px">${snippet}${more}${multi}</td>
      <td>${riskBadge(inh)}${pxs(repr.prob, repr.sev)}</td>
      <td style="font-size:11px;color:var(--text2);">${ctrls} Controls</td>
      <td>${riskBadge(res)}${pxs(resP, resS)}${gapHint}</td>
    </tr>
  `;
  }).join('');
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
    const items = approvedAssetsRequiringActionPlan()
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
        
        html += groupItems.map(a => {
            const resTier = liveAssetResidualTier(a);
            return `
            <div class="card" style="border-left:3px solid ${resTier==='High'?'var(--danger)':'var(--warn)'}; margin-bottom:12px; padding:16px 24px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
                    <div>
                        <span class="badge badge-id" style="margin-right:8px">${a.id}</span>
                        <strong style="font-size:14px">${a.name}</strong>
                        <span class="badge badge-type" style="margin-left:8px">${a.type}</span>
                    </div>
                    ${riskBadge(resTier)}
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
        `;
        }).join('');
        html += `</div>`; 
    }
    el.innerHTML = html;
}

function renderDashboardUser() {
  const approved = approvedAssetsOnly();
  const total = approved.length;
  const email = (currentUser?.email || '').toLowerCase();
  const mine = globalAssets.filter(a => (a.created_by || '').toLowerCase() === email);

  const setTxt = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  setTxt('dm-user-drafts', String(mine.filter(a => a.status === ASSET_STATUS.DRAFT).length));
  setTxt('dm-user-pending', String(mine.filter(a => a.status === ASSET_STATUS.PENDING).length));
  setTxt('dm-user-approved', String(mine.filter(a => a.status === ASSET_STATUS.APPROVED).length));
  setTxt('dm-user-rejected', String(mine.filter(a => a.status === ASSET_STATUS.REJECTED).length));

  setTxt('dm-total', String(total));
  const lbl = document.getElementById('dm-total-label');
  if (lbl) lbl.textContent = 'Approved in register';
  setTxt('dm-pii', String(approved.filter(a => a.pii === 'Y' || a.spi === 'Y').length));

  if (document.getElementById('hdr-total')) document.getElementById('hdr-total').textContent = total;
  if (document.getElementById('nav-total')) document.getElementById('nav-total').textContent = total;

  const barHtml = (label, val, t, color) => {
    if (!val) return '';
    const pct = Math.round((val / t) * 100);
    return `<div class="chart-bar-row"><div class="chart-bar-label">${label}</div><div class="chart-bar-track"><div class="chart-bar-fill" style="width:${pct}%;background:${color};color:#000">${pct > 10 ? pct + '%' : ''}</div></div><div class="chart-bar-count" style="width:24px;text-align:right;">${val}</div></div>`;
  };

  const byType = {};
  approved.forEach(a => { byType[a.type] = (byType[a.type] || 0) + 1; });
  const typeColors = { IA: 'var(--accent)', PhA: 'var(--accent2)', PA: 'var(--success)', SA: 'var(--warn)', SV: 'var(--purple)', FA: 'var(--info)' };
  const typeEl = document.getElementById('dash-types');
  if (typeEl) {
    if (!Object.keys(byType).length) typeEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
    else typeEl.innerHTML = Object.keys(byType).map(t => barHtml(t, byType[t], total || 1, typeColors[t])).join('');
  }

  const byClass = {};
  approved.forEach(a => { byClass[a.ciaClass] = (byClass[a.ciaClass] || 0) + 1; });
  const cColors = { Public: 'var(--success)', 'Internal Use': 'var(--accent2)', Confidential: 'var(--warn)', Restricted: 'var(--danger)' };
  const classEl = document.getElementById('dash-class-user');
  if (classEl) {
    if (!Object.keys(byClass).length) classEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
    else classEl.innerHTML = Object.keys(byClass).map(c => barHtml(c, byClass[c], total || 1, cColors[c])).join('');
  }
}

function renderDashboard() {
  if (currentRole === 'user') {
    renderDashboardUser();
    return;
  }
  const lbl = document.getElementById('dm-total-label');
  if (lbl) lbl.textContent = 'Approved in register';
  const approved = approvedAssetsOnly();
  const total = approved.length;

  /* -------- Risk posture KPIs (elevated = High + Moderate residual, live engine) -------- */
  const liveById = new Map(approved.map(a => [a.id, liveRegisterMetricsForAsset(a)]));
  const residualOf = (a) => liveById.get(a.id)?.residual ?? effectiveAssetResidual(a);
  const inherentOf = (a) => liveById.get(a.id)?.inherit ?? effectiveAssetInherent(a);
  const elevated = approved.filter(a => isElevatedResidualTier(residualOf(a)));
  const actionPlans = approved.filter(a => isElevatedResidualTier(residualOf(a)) && a.actionType !== 'Accept');
  const acceptable = approved.filter(a => {
    const r = residualOf(a);
    return r === 'Low' || r === 'Very Low';
  });
  const elevatedN = elevated.length;
  const acceptableN = acceptable.length;
  const thresholdPct = total ? Math.round((elevatedN / total) * 1000) / 10 : 0;
  const acceptablePct = total ? Math.round((acceptableN / total) * 1000) / 10 : 0;

  const inhMap = { High: 4, Moderate: 3, Low: 2, 'Very Low': 1 };
  const inhVals = approved.map(a => inhMap[inherentOf(a)]).filter(v => v > 0);
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
  setTxt('dm-risk-acceptable-pct', `${acceptablePct}% acceptable`);
  setTxt('dm-risk-threshold-n', String(elevatedN));
  setTxt('dm-risk-avg-inherit', avgInh ? `Avg inherent tier: ${avgInh.toFixed(2)} (1=Very Low … 4=High)` : 'Avg inherent tier: —');
  setTxt('dm-risk-analysis-pct', `${analysisPct}%`);
  setTxt('dm-risk-response-pct', `${responsePct}%`);

  if(document.getElementById('hdr-total')) document.getElementById('hdr-total').textContent = total;
  if(document.getElementById('nav-total')) document.getElementById('nav-total').textContent = total;
  if(document.getElementById('dm-total')) document.getElementById('dm-total').textContent = total;
  
  const highRisk = approved.filter(a => residualOf(a) === 'High').length;
  const modRisk = approved.filter(a => residualOf(a) === 'Moderate').length;
  const lowRisk = approved.filter(a => residualOf(a) === 'Low').length;
  const vlowRisk = approved.filter(a => residualOf(a) === 'Very Low').length;
  const piiCount = approved.filter(a => a.pii === 'Y' || a.spi === 'Y').length;
  
  if(document.getElementById('dm-high')) document.getElementById('dm-high').textContent = highRisk;
  if(document.getElementById('dm-mod')) document.getElementById('dm-mod').textContent = modRisk;
  if(document.getElementById('dm-low')) document.getElementById('dm-low').textContent = lowRisk;
  if(document.getElementById('dm-vlow')) document.getElementById('dm-vlow').textContent = vlowRisk;
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

  const byRes = {};
  approved.forEach(a => {
    const r = residualOf(a);
    byRes[r] = (byRes[r] || 0) + 1;
  });
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
      const topRisks = [...approved].sort((a, b) => (sevMap[residualOf(a)] || 6) - (sevMap[residualOf(b)] || 6)).slice(0, 5);
      if(!topRisks.length) trEl.innerHTML = '<p style="color:var(--text3);text-align:center;">No data</p>';
      else trEl.innerHTML = topRisks.map(a => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
          <div><span class="badge badge-id" style="margin-right:6px;font-size:9px">${a.id}</span><span style="font-size:12px;color:var(--text)">${a.name}</span></div>
          ${riskBadge(residualOf(a))}
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

  const actionPlanN = actionPlans.length;
  const stDone = actionPlans.filter(a => a.actionStatus === 'Done').length;
  const stProg = actionPlans.filter(a => a.actionStatus === 'In Progress').length;
  const stPend = actionPlans.filter(a => a.actionStatus === 'Pending').length;
  const stSum = stDone + stProg + stPend;
  const stOther = Math.max(0, actionPlanN - stSum);
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
        styleTitle(ws, 1, 'IMPACTLENS  —  Information Asset Register', cols);
        styleSubtitle(ws, 2, 'Generated ' + new Date().toLocaleString() + '  ·  Role: ' + (isAdmin ? 'Admin (CISO)' : 'Information Security') + '  ·  Records: ' + assets.length, cols);
        ws.addRow([]);
    };

    // =====================================================
    // Sheet A — Asset Identification (PDF section 1+2)
    // =====================================================
    {
        const ws = wb.addWorksheet('1 — Asset Identification', { views: [{ state: 'frozen', ySplit: 4 }] });
        addBranding(ws, CSV_SHEET1_HEADERS.length);
        const headers = [...CSV_SHEET1_HEADERS];
        const hdr = ws.addRow(headers);
        styleHeaderRow(ws, hdr.number, headers.length);
        assets.forEach(a => {
            const r = ws.addRow([a.id, a.name, a.description, a.group_name, a.hostname, a.server, a.custodian, a.ip_address, a.environment, a.department, a.type,
              (a.asset_owners != null && String(a.asset_owners).trim()) ? String(a.asset_owners).trim() : '']);
            r.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            r.getCell(11).alignment = { horizontal: 'center' };
            styleBodyCells(ws, r.number, headers.length);
        });
        setCols(ws, [12, 38, 46, 18, 18, 22, 22, 16, 16, 22, 8, 28]);
    }

    // =====================================================
    // Sheet B — Information Sensitivity & Valuation (PDF section 3)
    // =====================================================
    {
        const ws = wb.addWorksheet('2 — Sensitivity & Valuation', { views: [{ state: 'frozen', ySplit: 4 }] });
        addBranding(ws, CSV_SHEET2_HEADERS.length);
        const headers = [...CSV_SHEET2_HEADERS];
        const hdr = ws.addRow(headers);
        styleHeaderRow(ws, hdr.number, headers.length);
        assets.forEach(a => {
            const ciaQ = (() => {
              const raw = a.cia_questionnaire_json;
              if (raw == null || !String(raw).trim()) return '';
              const q = parseJsonSafe(String(raw).trim(), null);
              return (q !== null && typeof q === 'object' && !Array.isArray(q)) ? JSON.stringify(q) : String(raw).trim();
            })();
            const r = ws.addRow([a.id, a.name, yn(a.pii), yn(a.spi), yn(a.corp), a.ciaC, a.ciaI, a.ciaA, a.ciaScore, a.ciaClass, a.type,
              (a.classification_justification != null && String(a.classification_justification).trim()) ? String(a.classification_justification).trim() : '',
              ciaQ]);
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
            r.getCell(11).alignment = { horizontal: 'center' };
            styleBodyCells(ws, r.number, headers.length);
        });
        setCols(ws, [12, 38, 6, 6, 9, 5, 5, 5, 10, 16, 8, 36, 42]);
    }

    // =====================================================
    // Sheet C — Risk Assessment (PDF section 4 — IAR / Risk)
    // =====================================================
    {
        const ws = wb.addWorksheet('3 — Risk Assessment', { views: [{ state: 'frozen', ySplit: 4 }] });
        addBranding(ws, 12);
        const headers = [...CSV_SHEET3_HEADERS];
        const hdr = ws.addRow(headers);
        styleHeaderRow(ws, hdr.number, headers.length);
        assets.forEach(a => {
            const bands = csvThreatVulnBandsFromRiskBasis(a);
            const rowVals = [a.id, a.name, a.riskDesc || '', a.prob, a.sev, a.inherit, a.residual,
              (a.riskCategory != null && String(a.riskCategory).trim()) ? String(a.riskCategory).trim() : '',
              bands[0], bands[1], exportRiskBasisJsonCell(a), exportAssetRisksJsonCell(a)];
            const r = ws.addRow(rowVals);
            r.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            [4, 5, 9, 10].forEach(i => { r.getCell(i).alignment = { horizontal: 'center' }; });
            const inh = r.getCell(6); inh.fill = excelRiskFill(a.inherit);  inh.font = { bold: true, color: { argb: excelRiskTextOn(a.inherit)  } }; inh.alignment = { horizontal: 'center' };
            const res = r.getCell(7); res.fill = excelRiskFill(a.residual); res.font = { bold: true, color: { argb: excelRiskTextOn(a.residual) } }; res.alignment = { horizontal: 'center' };
            styleBodyCells(ws, r.number, headers.length);
        });
        setCols(ws, [12, 38, 60, 12, 10, 12, 12, 24, 8, 8, 40, 42]);
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
    const reviewerEmail = currentUser?.email || 'admin@example.org';

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
    // Sheet 8–9 — MBSS baseline & firewall perimeter review (after rejected
    // audit so tab order is 1…7, 8, 9; then Admin 10–12).
    // =====================================================
    {
        const wsM = wb.addWorksheet('8 — MBSS Endpoint Baseline', { views: [{ state: 'frozen', ySplit: 5 }] });
        addBranding(wsM, 9);
        const mbssLegend = wsM.addRow([MBSS_FIELD_SPEC.map(f => `${f.header}: ${f.ref}`).join(' · ')]);
        wsM.mergeCells(mbssLegend.number, 1, mbssLegend.number, 9);
        mbssLegend.getCell(1).font = { italic: true, size: 9, color: { argb: COL_INK_MUTED } };
        mbssLegend.getCell(1).alignment = { wrapText: true, vertical: 'top' };
        mbssLegend.height = 40;
        const mh = wsM.addRow(CSV_SHEET11_HEADERS);
        styleHeaderRow(wsM, mh.number, CSV_SHEET11_HEADERS.length);
        assets.forEach(a => {
            const m = parseJsonSafe(a.mbss_json, {});
            const cells = [a.id, a.name, ...MBSS_FIELD_SPEC.map(f => {
                const v = m[f.key];
                if (f.yn) return yn(v);
                return (v != null && v !== '') ? String(v) : '';
            })];
            const r = wsM.addRow(cells);
            r.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            [3, 4, 5, 6, 7].forEach(i => {
                const v = r.getCell(i).value;
                r.getCell(i).fill = ynFill(v);
                r.getCell(i).font = ynFont(v);
                r.getCell(i).alignment = { horizontal: 'center' };
            });
            styleBodyCells(wsM, r.number, CSV_SHEET11_HEADERS.length);
        });
        setCols(wsM, [12, 36, 8, 8, 8, 8, 8, 14, 48]);
    }
    {
        const wsF = wb.addWorksheet('9 — Firewall Perimeter Review', { views: [{ state: 'frozen', ySplit: 5 }] });
        addBranding(wsF, 9);
        const fwLegend = wsF.addRow([FIREWALL_FIELD_SPEC.map(f => `${f.header}: ${f.ref}`).join(' · ')]);
        wsF.mergeCells(fwLegend.number, 1, fwLegend.number, 9);
        fwLegend.getCell(1).font = { italic: true, size: 9, color: { argb: COL_INK_MUTED } };
        fwLegend.getCell(1).alignment = { wrapText: true, vertical: 'top' };
        fwLegend.height = 40;
        const fh = wsF.addRow(CSV_SHEET12_HEADERS);
        styleHeaderRow(wsF, fh.number, CSV_SHEET12_HEADERS.length);
        assets.forEach(a => {
            const f = parseJsonSafe(a.firewall_json, {});
            const cells = [a.id, a.name, ...FIREWALL_FIELD_SPEC.map(fl => {
                const v = f[fl.key];
                if (fl.yn) return yn(v);
                return (v != null && v !== '') ? String(v) : '';
            })];
            const r = wsF.addRow(cells);
            r.getCell(1).font = { bold: true, color: { argb: COL_TITLE_FG } };
            [4, 5, 6, 8].forEach(i => {
                const v = r.getCell(i).value;
                r.getCell(i).fill = ynFill(v);
                r.getCell(i).font = ynFont(v);
                r.getCell(i).alignment = { horizontal: 'center' };
            });
            styleBodyCells(wsF, r.number, CSV_SHEET12_HEADERS.length);
        });
        setCols(wsF, [12, 36, 22, 10, 10, 10, 14, 12, 48]);
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
        // Negative-action audit stats (drive sheet 11 Highlights + sheet 10 history)
        const cntAssetRejected = (globalLogs || []).filter(l => l.action === 'ASSET_REJECTED').length;
        const cntDraftRejected = (globalLogs || []).filter(l => l.action === 'DRAFT_REJECTED').length;
        const cntAssetDeleted  = (globalLogs || []).filter(l => l.action === 'ASSET_DELETED').length;
        const cntUserRejected  = (globalLogs || []).filter(l => l.action === 'USER_REJECTED').length;
        const negativeTotal    = cntAssetRejected + cntDraftRejected + cntAssetDeleted + cntUserRejected;

        // -----------------------------------------------------------
        // Sheet 10 — Document History (real audit trail from SystemLogs)
        // -----------------------------------------------------------
        const wsH = wb.addWorksheet('10 — Document History');
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
        // Sheet 11 — Highlights (revision narrative + aggregate stats)
        // -----------------------------------------------------------
        const wsX = wb.addWorksheet('11 — Highlights');
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
                const verb = l.action === 'DRAFT_REJECTED' ? 'draft rejected' : 'rejected (CISO)';
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
            ['Rejections & Deletions (audit)', `${negativeTotal} total — ${cntAssetRejected} returned, ${cntDraftRejected} draft-rejected, ${cntAssetDeleted} deleted, ${cntUserRejected} user-rejected (see sheet 7 — Rejected & Deleted)`],
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
        // Sheet 12 — Sign Off (always populated with realistic defaults)
        // -----------------------------------------------------------
        const wsS = wb.addWorksheet('12 — Sign Off');
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
// BFCache restore: same JS heap as before freeze — sign out if they were in the app.
window.addEventListener('pageshow', (e) => {
    if (!e.persisted || !supabaseClient) return;
    if (urlHasAuthHandshakeParams()) return;
    if (authUiReady && currentUser) {
        handleLogout(HISTORY_RETURN_SECURITY_SIGNOUT_MSG);
    }
});

(async function initApp() {
    if (!supabaseClient) {
        showAuthScreen();
        return;
    }

    const handledCallback = await handleAuthCallbackFromUrl();
    if (!handledCallback) {
        const { data: { session: initialSession } } = await supabaseClient.auth.getSession();
        if (wasHistoryNavigation() && !urlHasAuthHandshakeParams() && initialSession) {
            await purgeSessionAfterHistoryNavigation();
        } else if (initialSession) {
            await enterAuthenticatedApp(initialSession);
        } else {
            showAuthScreen();
        }
    }

    flushHistoryReturnSecurityNotice();

    supabaseClient.auth.onAuthStateChange(async (event, session) => {
        if (event === 'INITIAL_SESSION') return;
        if (event === 'SIGNED_IN' && session) {
            if (authUiReady && currentUser?.id === session.user?.id) return;
            const role = pendingLoginRole;
            pendingLoginRole = null;
            try {
                await enterAuthenticatedApp(session, role);
            } catch (err) {
                console.error('SIGNED_IN handler:', err);
                if (!authUiReady) showAuthScreen();
                notify(formatAuthError(err), true);
            }
            return;
        }
        if (event === 'USER_UPDATED' && session?.user?.email_confirmed_at) {
            notify('Email address confirmed.');
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
window.downloadAssetCsvTemplate = downloadAssetCsvTemplate;
window.downloadAllIarCsvTemplates = downloadAllIarCsvTemplates;
window.downloadIarExcelTemplateWorkbook = downloadIarExcelTemplateWorkbook;
window.exportUserAssetTableCsv = exportUserAssetTableCsv;
window.exportIarCsvPack = exportIarCsvPack;
window.triggerAssetCsvImport    = triggerAssetCsvImport;
window.handleAssetCsvFileSelected = handleAssetCsvFileSelected;
window.exportAssetRegisterCsv     = exportAssetRegisterCsv;
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
window.applyIsraNarrativeGuides = applyIsraNarrativeGuides;
window.markIsraNarrativeManual = markIsraNarrativeManual;
window.syncPriorIncidentsFromGuide = syncPriorIncidentsFromGuide;
window.updateIsraBandSummary = updateIsraBandSummary;
window.addIsraThreatRow = addIsraThreatRow;
window.removeIsraThreatRow = removeIsraThreatRow;
window.addIsraVulnRow = addIsraVulnRow;
window.removeIsraVulnRow = removeIsraVulnRow;
window.composeIsraRowFromGuides = composeIsraRowFromGuides;
window.syncCiaQuestionnaireIntoClassificationFields = syncCiaQuestionnaireIntoClassificationFields;
window.addRiskScenario             = addRiskScenario;
window.removeCurrentRiskScenario   = removeCurrentRiskScenario;
window.switchRiskScenarioIndex     = switchRiskScenarioIndex;
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