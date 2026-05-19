/**
 * Regenerates the asset DELETE/INSERT/controls block in supabase/master_setup.sql
 * with 110–120 assets, cia_questionnaire_json (1–5), multi-scenario asset_risks_json,
 * risk_basis_json (threats[] / vulnerabilities[] bands 1–5, max-based CIA), owners & justification.
 *
 * Run from repo root: node scripts/regenerate_master_asset_seed.mjs
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');
const masterPath = path.join(root, 'supabase', 'master_setup.sql');

const TARGET_TOTAL = 117;

/** Matches assets/scripts/app.js INHERIT matrix (severity-probability → rating). */
const INHERIT = {
  '5-1': 'Moderate', '5-2': 'Moderate', '5-3': 'High', '5-4': 'High', '5-5': 'High',
  '4-1': 'Low', '4-2': 'Moderate', '4-3': 'Moderate', '4-4': 'High', '4-5': 'High',
  '3-1': 'Low', '3-2': 'Moderate', '3-3': 'Moderate', '3-4': 'Moderate', '3-5': 'High',
  '2-1': 'Low', '2-2': 'Low', '2-3': 'Moderate', '2-4': 'Moderate', '2-5': 'Moderate',
  '1-1': 'Very Low', '1-2': 'Low', '1-3': 'Low', '1-4': 'Low', '1-5': 'Moderate',
};

const RISK_RANK = { 'Very Low': 0, 'Low': 1, 'Moderate': 2, 'High': 3 };

function clampPS(n) {
  return Math.max(1, Math.min(5, parseInt(String(n), 10) || 3));
}

function inheritFromPS(prob, sev) {
  return INHERIT[`${clampPS(sev)}-${clampPS(prob)}`] || 'Moderate';
}

/** Residual after control stack — `gaps` simulates material control gaps (High residual demo). */
function residualFromAppliedControls(prob, sev, controlStrength = 'full') {
  const p = clampPS(prob);
  const s = clampPS(sev);
  let pDrop;
  let sDrop;
  if (controlStrength === 'gaps') {
    pDrop = 0;
    sDrop = 0;
  } else if (controlStrength === 'partial') {
    pDrop = 1;
    sDrop = 1;
  } else {
    pDrop = p >= 4 ? 2 : 1;
    sDrop = s >= 4 ? 2 : 1;
  }
  const resP = clampPS(p - pDrop);
  const resS = clampPS(s - sDrop);
  return { resP, resS, residual: inheritFromPS(resP, resS) };
}

function rollupWorstRating(vals) {
  const arr = (vals || []).filter(Boolean);
  if (!arr.length) return 'Moderate';
  return arr.reduce((w, x) => (RISK_RANK[x] > RISK_RANK[w] ? x : w), 'Very Low');
}

/** Residual cannot exceed inherent unless mandatory-control floors apply (seed assumes controls in place). */
function capResidualToInherent(inherit, residual) {
  if ((RISK_RANK[residual] ?? 0) > (RISK_RANK[inherit] ?? 0)) return inherit;
  return residual;
}

function scenarioMetrics(prob, sev, controlStrength = 'full') {
  const p = clampPS(prob);
  const s = clampPS(sev);
  const inherit = inheritFromPS(p, s);
  const { resP, resSev, residual } = residualFromAppliedControls(p, s, controlStrength);
  const capped = capResidualToInherent(inherit, residual);
  return { prob: p, sev: s, inherit, residual: capped, resProb: resP, resSev, controlStrength };
}

function worstScenarioForSeed(scenarios) {
  if (!scenarios.length) return scenarios[0];
  return scenarios.reduce((w, sc) => {
    const rCmp = (RISK_RANK[sc.residual] ?? 0) - (RISK_RANK[w.residual] ?? 0);
    const iCmp = (RISK_RANK[sc.inherit] ?? 0) - (RISK_RANK[w.inherit] ?? 0);
    if (rCmp > 0 || (rCmp === 0 && iCmp > 0)) return sc;
    return w;
  }, scenarios[0]);
}

/** Realistic P×S spread with a visible High tail for dashboard elevation KPIs. */
function controlStrengthForAsset(type, env, cat, rowSeed) {
  const catKey = String(cat || '');
  const isCrownJewel =
    (type === 'IA' || type === 'FA' || type === 'SA') &&
    (env === 'Internet Facing' ||
      /leak|emr|payroll|bank|bor|proc|endow|president|vpn|adm-portal|pay-gw|unauth|vuln|ddos|supply/i.test(catKey));
  if (isCrownJewel && (rowSeed % 11 === 0 || rowSeed % 13 === 0 || rowSeed % 17 === 0)) return 'gaps';
  if (isCrownJewel && rowSeed % 7 === 0) return 'partial';
  if (env === 'Internet Facing' && rowSeed % 19 === 0) return 'partial';
  return 'full';
}

function assignRealisticRisk(type, env, cat, rowSeed, tplProb, tplSev) {
  const roll = rowSeed % 20;
  const catKey = String(cat || '');
  const strength = controlStrengthForAsset(type, env, cat, rowSeed);
  const isCritical =
    (type === 'IA' || type === 'FA') &&
    (tplSev >= 5 || /leak|emr|payroll|bank|bor|proc|endow|president|vpn|adm-portal|pay-gw/i.test(catKey));
  const isPeripheral = type === 'PhA' || (type === 'SV' && env === 'Internal' && tplSev <= 3);

  let prob;
  let sev;
  if (strength === 'gaps') {
    prob = 5;
    sev = rowSeed % 3 === 0 ? 5 : 4;
  } else if (strength === 'partial') {
    prob = clampPS(Math.max(tplProb, 4));
    sev = clampPS(Math.max(tplSev, 4));
  } else if (isCritical) {
    prob = clampPS(Math.max(tplProb, 3));
    sev = clampPS(Math.max(tplSev, 4));
  } else if (isPeripheral && roll < 9) {
    prob = 1 + (roll % 2);
    sev = 1 + (roll % 3);
  } else if (roll < 7) {
    prob = 2;
    sev = 2;
  } else if (roll < 12) {
    prob = 2;
    sev = 3;
  } else if (roll < 16) {
    prob = 3;
    sev = 3;
  } else {
    prob = clampPS(tplProb);
    sev = clampPS(tplSev);
  }

  return scenarioMetrics(prob, sev, strength);
}

const PLM_ASSETS_BASE = [
  ['IA', 'PLM Central Registration System (CRS) Database', 'Registrar', 'CRS-DB-PROD', 'CRS Primary PostgreSQL', 'University Registrar', 'Student records, grades, enrollment — primary SIS datastore.', '10.20.1.10', 'Internal', 'Office of the Registrar', 'cyber_ext_leak', 3, 5, 'High', 'Moderate'],
  ['IA', 'Yoshii Scholarship Foundation Beneficiary Records', 'Scholarship Office', 'SCHOL-DB-01', 'Scholarship DB Server', 'Scholarship Office Head', 'Financial aid and donor-linked student PII/SPI.', '10.20.2.15', 'Internal', 'Scholarship & Financial Aid', 'legal_dpa', 3, 5, 'High', 'Moderate'],
  ['IA', 'Intramunotes Mobile App User Database', 'ICTO', 'INTRA-DB-01', 'Intramunotes API Backend', 'ICTO App Dev Lead', 'Campus community notes, posts, and student identifiers.', '10.20.8.50', 'Internet Facing', 'ICTO / Student Affairs', 'cyber_ext_leak', 4, 4, 'High', 'Moderate'],
  ['IA', 'Haribon AWS Cloud Research Dataset', 'Research', 'HARIBON-S3-01', 'AWS EC2 / S3 Research', 'Research Data Steward', 'Biodiversity research files hosted on AWS for Haribon partnership.', 'Cloud', 'Internet Facing', 'Research & Extension', 'cyber_ext_supply', 2, 4, 'Moderate', 'Low'],
  ['IA', 'PLM Alumni Relations CRM Database', 'Alumni Affairs', 'ALUM-CRM-01', 'Alumni CRM Server', 'Alumni Affairs Director', 'Alumni contact history and employment tracking.', '10.20.3.20', 'Hybrid', 'Alumni Affairs', 'hr_insider', 3, 4, 'High', 'Moderate'],
  ['IA', 'University Clinic EMR Records', 'Medical Services', 'CLINIC-EMR-01', 'Clinic EMR DB', 'Chief Clinic Physician', 'Electronic medical records and patient history.', '10.50.1.10', 'Internal', 'University Clinic', 'cyber_ext_leak', 3, 5, 'High', 'High'],
  ['IA', 'HR Payroll Master File', 'Human Resources', 'HR-PAY-01', 'Payroll DB', 'HR Director', 'Faculty and staff salary, SSS, PhilHealth data.', '10.30.1.10', 'Internal', 'Human Resources', 'hr_insider', 2, 5, 'Moderate', 'Moderate'],
  ['IA', 'Board of Regents Confidential Minutes Archive', 'Administration', 'BOR-ARCH-01', 'Exec File Server', 'Board Secretary', 'Restricted governance documents and resolutions.', '10.10.1.5', 'Internal', 'Office of the President', 'hr_insider', 2, 5, 'Moderate', 'High'],
  ['PhA', 'Gusaling Corazon Aquino Main Server Room', 'ICTO', 'GCA-SRVR-01', 'GCA Data Center Rack A', 'ICTO Infrastructure', 'Primary on-prem server room in GCA building.', '10.99.10.1', 'Internal', 'ICTO', 'phys_destruct', 2, 5, 'Moderate', 'Moderate'],
  ['PhA', 'Gusaling Corazon Aquino Network Core Switch Stack', 'ICTO', 'GCA-CORE-SW', 'GCA Network Closet', 'Network Operations', 'Core switching for GCA academic buildings.', '10.99.10.2', 'Internal', 'ICTO', 'phys_destruct', 3, 4, 'High', 'Moderate'],
  ['PhA', 'Tanghalang Bayan AV Control Rack', 'Cultural Affairs', 'TB-AV-RACK', 'TB Stage Tech Booth', 'Theater Technical Director', 'Audio-visual control systems for university events.', '10.40.5.10', 'Internal', 'Cultural Affairs', 'phys_theft', 3, 3, 'Moderate', 'Low'],
  ['PhA', 'Tanghalang Bayan Wireless Microphone Inventory', 'Cultural Affairs', 'TB-WIRELESS', 'TB Storage', 'Events Coordinator', 'Wireless mics and receivers for performances.', 'N/A', 'Internal', 'Cultural Affairs', 'phys_theft', 3, 2, 'Moderate', 'Low'],
  ['PhA', 'Main Library RFID Gate System', 'Library', 'LIB-RFID-01', 'Library Entrance', 'Library Systems Admin', 'RFID anti-theft gates and sensors.', '10.20.5.1', 'Internal', 'University Library', 'phys_theft', 2, 3, 'Moderate', 'Low'],
  ['PhA', 'CET Fabrication Lab 3D Printers', 'CET', 'CET-3DP-01', 'CET Fab Lab', 'CET Lab Technician', 'Additive manufacturing equipment for engineering prototypes.', 'DHCP', 'Internal', 'College of Engineering', 'phys_theft', 3, 2, 'Moderate', 'Low'],
  ['PhA', 'Campus CCTV NVR Cluster', 'Security', 'SEC-NVR-01', 'Security Office', 'Chief of Security', '30-day retention video surveillance storage.', '10.99.1.50', 'Internal', 'Campus Security', 'phys_destruct', 3, 4, 'High', 'Moderate'],
  ['PhA', 'Finance Vault & Safe Deposit Unit', 'Finance', 'FIN-VAULT', 'Cashier Building', 'Head Cashier', 'Physical safe for daily university collections.', 'N/A', 'Internal', 'Finance', 'phys_theft', 2, 4, 'Moderate', 'Low'],
  ['SA', 'Intramunotes Android/iOS Application', 'ICTO', 'INTRA-APP', 'Intramunotes Build Pipeline', 'Mobile Dev Lead', 'Official PLM student community mobile app.', 'Cloud', 'Internet Facing', 'ICTO', 'cyber_int_vuln', 4, 4, 'High', 'Moderate'],
  ['SA', 'PLM Learning Management System (Moodle)', 'Academic', 'LMS-APP-01', 'LMS Application Server', 'Academic IT', 'Online modules, quizzes, and grade sync.', '10.20.10.5', 'Hybrid', 'Academic Affairs', 'cyber_ext_ddos', 3, 3, 'Moderate', 'Moderate'],
  ['SA', 'CRS Web Portal Application', 'Registrar', 'CRS-WEB-01', 'CRS App Tier', 'Registrar IT Liaison', 'Student-facing enrollment and grades portal.', '10.20.1.20', 'Internet Facing', 'Registrar', 'cyber_int_vuln', 4, 5, 'High', 'Moderate'],
  ['SA', 'University HRIS Platform', 'HR', 'HRIS-APP', 'HR Application Server', 'HR Systems Admin', 'Leave, attendance, and personnel workflows.', '10.30.1.20', 'Internal', 'Human Resources', 'cyber_int_unauth', 3, 4, 'High', 'Moderate'],
  ['SA', 'Finance Budget Planning System', 'Finance', 'FIN-BPS', 'Finance App Server', 'Finance Systems', 'Annual budgeting and allotment tracking.', '10.40.1.10', 'Internal', 'Finance', 'hr_accidental', 2, 4, 'Moderate', 'Moderate'],
  ['SA', 'Research Grant Management System', 'Research', 'RGMS-APP', 'Research App Server', 'Research Office', 'Grant proposals and compliance reporting.', '10.60.1.10', 'Internal', 'Research & Extension', 'cyber_int_vuln', 3, 3, 'Moderate', 'Low'],
  ['SV', 'PLM Official Website (www.plm.edu.ph)', 'ICTO', 'WEB-PROD-01', 'Public Web Farm', 'Web Development Team', 'Primary public-facing university portal.', '203.177.X.X', 'Internet Facing', 'ICTO', 'cyber_ext_ddos', 4, 3, 'High', 'Moderate'],
  ['SV', 'Microsoft 365 Student Email Tenant', 'ICTO', 'O365-MAIL', 'Cloud Tenant', 'Mail Administrator', 'Student email and Teams collaboration.', 'Cloud', 'Internet Facing', 'ICTO', 'cyber_ext_supply', 2, 4, 'Moderate', 'Moderate'],
  ['SV', 'Campus Wi-Fi Authentication (Eduroam)', 'ICTO', 'WIFI-RADIUS', 'RADIUS Cluster', 'Network Operations', 'Wireless access for students and faculty.', '10.99.2.1', 'Hybrid', 'ICTO', 'cyber_int_unauth', 3, 3, 'Moderate', 'Moderate'],
  ['SV', 'Cloudflare DDoS Protection Service', 'ICTO', 'CF-EDGE', 'Edge Proxy', 'Infrastructure Lead', 'CDN and DDoS mitigation for public services.', 'Cloud', 'Internet Facing', 'ICTO', 'cyber_ext_ddos', 3, 3, 'Moderate', 'Low'],
  ['SV', 'AWS Haribon Research Hosting', 'Research', 'AWS-HARIBON', 'AWS Account', 'Cloud Administrator', 'Haribon partnership workloads on AWS.', 'Cloud', 'Internet Facing', 'Research', 'cyber_ext_supply', 2, 4, 'Moderate', 'Moderate'],
  ['PA', 'University President Executive Office', 'Administration', 'EXEC-OFFICE', 'Executive Suite', 'Executive Secretary', 'Top management and board liaison personnel.', 'N/A', 'Hybrid', 'Office of the President', 'hr_insider', 3, 5, 'High', 'High'],
  ['PA', 'ICTO Systems Administration Team', 'ICTO', 'ICTO-ADMINS', 'ICTO Operations', 'ICTO Director', 'Privileged administrators with domain-wide access.', 'N/A', 'Internal', 'ICTO', 'cyber_int_unauth', 3, 5, 'High', 'Moderate'],
  ['PA', 'Registrar Frontline Staff', 'Registrar', 'REG-STAFF', 'Registrar Counters', 'Registrar Head', 'Staff processing transcripts and enrollment.', 'N/A', 'Internal', 'Registrar', 'hr_accidental', 3, 4, 'Moderate', 'Moderate'],
  ['PA', 'Scholarship Verification Officers', 'Scholarship', 'SCHOL-STAFF', 'Scholarship Office', 'Scholarship Coordinator', 'Officers validating Yoshii and institutional grants.', 'N/A', 'Internal', 'Scholarship Office', 'hr_insider', 2, 4, 'Moderate', 'Moderate'],
  ['FA', 'University Main Operating Bank Account Portal', 'Finance', 'BANK-GW-01', 'Banking Gateway', 'Finance IT', 'Online banking for tuition and operations.', '10.40.1.5', 'Internet Facing', 'Finance', 'cyber_int_unauth', 3, 5, 'High', 'Low'],
  ['FA', 'Cashier Daily Collection Ledger', 'Finance', 'CASH-LEDGER', 'Cashier System', 'Head Cashier', 'Daily cash intake and deposit records.', '10.40.2.1', 'Internal', 'Finance', 'phys_theft', 3, 4, 'Moderate', 'Moderate'],
  ['FA', 'Yoshii Scholarship Disbursement Account', 'Scholarship', 'YOSHII-ACCT', 'Scholarship Finance', 'Scholarship Accountant', 'Dedicated fund flows for Yoshii beneficiaries.', '10.40.3.1', 'Internal', 'Scholarship Office', 'legal_dpa', 2, 5, 'Moderate', 'Moderate'],
  ['IA', 'Student Disciplinary Case Files', 'Student Affairs', 'DSA-CASES', 'DSA Records', 'Dean of Student Affairs', 'Conduct cases and sanctions documentation.', '10.20.9.10', 'Internal', 'Student Affairs', 'legal_dpa', 2, 4, 'Moderate', 'High'],
  ['IA', 'COVID-19 Health Declaration Archives', 'Medical Services', 'CLINIC-COVID', 'Clinic Records', 'Clinic Admin', 'Historical health screening submissions.', '10.50.1.20', 'Internal', 'University Clinic', 'legal_dpa', 2, 3, 'Moderate', 'Moderate'],
  ['SA', 'Library Online Catalog (OPAC)', 'Library', 'LIB-OPAC', 'Library App', 'Library IT', 'Bibliographic and patron loan data.', '10.20.5.15', 'Hybrid', 'Library', 'cyber_int_vuln', 3, 3, 'Moderate', 'Low'],
  ['PhA', 'College of Law Moot Court Recording System', 'Law', 'LAW-MOOT-AV', 'Law Building AV', 'Law IT Coordinator', 'Recording infrastructure for legal training.', '10.20.7.5', 'Internal', 'College of Law', 'phys_theft', 2, 2, 'Low', 'Low'],
  ['SV', 'PayMongo Tuition Payment Gateway', 'Finance', 'PAY-GW', 'Payment Service', 'Finance Systems', 'Online tuition payment integration.', 'Cloud', 'Internet Facing', 'Finance', 'cyber_ext_supply', 3, 5, 'High', 'Moderate'],
  ['IA', 'Faculty Research Publication Repository', 'Research', 'REPO-DSPACE', 'DSpace Server', 'Research Librarian', 'Thesis and faculty research archive.', '10.60.2.10', 'Hybrid', 'Library / Research', 'cyber_ext_leak', 2, 3, 'Moderate', 'Low'],
  ['PhA', 'Gusaling Corazon Aquino UPS Battery Banks', 'ICTO', 'GCA-UPS', 'GCA Server Room', 'Facilities Electrician', 'Power backup for GCA data center.', 'N/A', 'Internal', 'Facilities', 'phys_destruct', 2, 4, 'Moderate', 'Moderate'],
  ['SA', 'Campus ID Card Printing Software', 'Security', 'ID-PRINT', 'ID Office Workstation', 'ID Office Supervisor', 'ID card encoding and photo capture.', '10.99.3.10', 'Internal', 'Campus Security', 'cyber_ext_leak', 2, 3, 'Moderate', 'Low'],
  ['IA', 'Athletics Medical Clearance Forms DB', 'Athletics', 'ATH-MED-01', 'Athletics Records', 'Athletics Director', 'Student athlete health clearances.', '10.20.11.5', 'Internal', 'Athletics', 'legal_dpa', 2, 3, 'Moderate', 'Moderate'],
  ['SV', 'PLM VPN Remote Access Service', 'ICTO', 'VPN-GW', 'VPN Concentrator', 'Network Lead', 'Remote admin and faculty access.', '10.99.0.1', 'Internet Facing', 'ICTO', 'cyber_int_unauth', 3, 4, 'High', 'Moderate'],
  ['PhA', 'Tanghalang Bayan Stage Lighting Console', 'Cultural Affairs', 'TB-LIGHT', 'Stage Control', 'Stage Manager', 'DMX lighting control for productions.', 'N/A', 'Internal', 'Cultural Affairs', 'phys_theft', 2, 2, 'Low', 'Low'],
  ['IA', 'International Programs Exchange Records', 'International', 'INTL-REC', 'Intl Office DB', 'International Programs Head', 'Foreign exchange student documentation.', '10.20.12.10', 'Internal', 'International Affairs', 'legal_dpa', 3, 4, 'High', 'Moderate'],
  ['SA', 'Admission Online Application Portal', 'Admissions', 'ADM-PORTAL', 'Admissions Web', 'Admissions IT', 'Freshman and transferee application pipeline.', '10.20.1.50', 'Internet Facing', 'Admissions', 'cyber_ext_leak', 4, 4, 'High', 'Moderate'],
  ['PhA', 'Science Lab Gas Line Manifold (Intramuros)', 'Sciences', 'SCI-GAS', 'Science Bldg Basement', 'Lab Safety Officer', 'Laboratory gas distribution physical infrastructure.', 'N/A', 'Internal', 'College of Sciences', 'phys_destruct', 1, 5, 'Moderate', 'Moderate'],
  ['FA', 'Endowment Investment Portfolio Records', 'Finance', 'ENDOW-PORT', 'Finance Records', 'VP Finance', 'Long-term university investments.', '10.40.4.1', 'Internal', 'Finance', 'cyber_int_unauth', 2, 5, 'Moderate', 'High'],
  ['IA', 'Dormitory Housing Assignment System Data', 'Student Affairs', 'DORM-DB', 'Housing DB', 'Housing Coordinator', 'On-campus housing assignments and billing.', '10.20.9.20', 'Internal', 'Student Affairs', 'cyber_ext_leak', 3, 3, 'Moderate', 'Moderate'],
  ['SV', 'Supabase Backend for Intramunotes (BaaS)', 'ICTO', 'INTRA-SUPA', 'Supabase Project', 'Intramunotes DevOps', 'Managed backend for Intramunotes prototype/production.', 'Cloud', 'Internet Facing', 'ICTO', 'cyber_ext_supply', 3, 4, 'High', 'Moderate'],
  ['PhA', 'Haribon Field Equipment GPS Trackers', 'Research', 'HARIBON-GPS', 'Field Kit', 'Field Research Lead', 'GPS units for biodiversity field work.', 'N/A', 'Hybrid', 'Research', 'phys_theft', 3, 2, 'Moderate', 'Low'],
  ['SA', 'Board Room Video Conferencing System', 'Administration', 'BOR-VC', 'Board Room', 'Executive Assistant', 'VC system for regents meetings.', '10.10.1.10', 'Internal', 'Office of the President', 'cyber_ext_leak', 2, 3, 'Moderate', 'Low'],
  ['IA', 'Faculty Evaluation (SET) Results Warehouse', 'Academic', 'SET-WAREHOUSE', 'Academic DB', 'Academic Planning', 'Aggregated teaching evaluation scores.', '10.20.10.20', 'Internal', 'Academic Affairs', 'hr_insider', 2, 3, 'Moderate', 'Moderate'],
  ['PhA', 'PLM Intramuros Generator Sets', 'Facilities', 'GEN-INTRAM', 'Power House', 'Facilities Manager', 'Emergency generators for main campus.', 'N/A', 'Internal', 'Facilities Management', 'phys_destruct', 2, 5, 'Moderate', 'Moderate'],
  ['SV', 'ICTO Service Desk Ticketing (osTicket)', 'ICTO', 'SD-TICKET', 'Helpdesk Server', 'Service Desk Lead', 'IT support ticket tracking.', '10.99.5.10', 'Internal', 'ICTO', 'cyber_int_vuln', 3, 2, 'Moderate', 'Low'],
  ['IA', 'Procurement Bid Document Repository', 'Procurement', 'PROC-BIDS', 'Procurement Share', 'BAC Secretariat', 'Sensitive bid proposals and awards.', '10.40.6.10', 'Internal', 'Procurement', 'hr_insider', 2, 4, 'Moderate', 'High'],
];

const EXTRA_TEMPLATES = [
  ['IA', 'Departmental File Share — {unit}', '{unit}', 'FS-{abbr}-01', 'SMB Share Cluster', '{unit} IT Focal', 'Shared drives for {unit} documents and spreadsheets.', '10.25.{n}.10', 'Internal', '{unit}', 'hr_insider', 2, 3, 'Moderate', 'Low'],
  ['SA', '{unit} Room Booking & Scheduling Portal', '{unit}', 'BOOK-{abbr}', 'Dept App Server', '{unit} Chair', 'Classroom and facility reservation workflow.', '10.25.{n}.15', 'Hybrid', '{unit}', 'cyber_int_vuln', 3, 3, 'Moderate', 'Low'],
  ['SV', 'DNS / Internal Zone — {campus}', 'ICTO', 'DNS-{abbr}', 'BIND / AD DNS', 'Network Ops', 'Internal name resolution for {campus}.', '10.99.{n}.2', 'Internal', 'ICTO', 'cyber_int_unauth', 2, 3, 'Moderate', 'Low'],
  ['PhA', '{unit} Smart Classroom Projection Rack', '{unit}', 'PROJ-{abbr}', 'Room AV Rack', 'Facilities AV', 'HDMI switching and lecturer podium controls.', '10.25.{n}.99', 'Internal', '{unit}', 'phys_theft', 2, 3, 'Low', 'Low'],
  ['IA', 'Laboratory Incident & Safety Logs — {unit}', '{unit}', 'LAB-SAF-{abbr}', 'Dept DB', 'Lab Coordinator', 'Chemical safety and incident narratives.', '10.25.{n}.20', 'Internal', '{unit}', 'legal_dpa', 2, 4, 'Moderate', 'Moderate'],
  ['PA', '{unit} Department Secretary / Encoder Role', '{unit}', 'PA-{abbr}-STAFF', 'Workstations', '{unit} Chair', '{unit} document encoding with access to departmental records.', 'N/A', 'Internal', '{unit}', 'hr_accidental', 3, 3, 'Moderate', 'Moderate'],
  ['FA', '{unit} Discretionary Fund Custody Ledger', '{unit}', 'FUND-{abbr}', 'Custodian workstation', '{unit} Finance Focal', 'Petty cash and activity fund tracking.', '10.25.{n}.30', 'Internal', '{unit}', 'phys_theft', 2, 4, 'Moderate', 'Moderate'],
  ['SV', 'SMTP Relay & Mail Hygiene Appliance', 'ICTO', 'SMTP-{abbr}', 'Messaging Gateway', 'Mail Admin', 'Outbound mail scanning and DKIM signing.', '10.99.{n}.5', 'Internal', 'ICTO', 'cyber_ext_supply', 3, 3, 'Moderate', 'Low'],
  ['SA', 'Asset Tagging & Inventory Mobile Tool', 'ICTO', 'INV-MOB-{abbr}', 'MDM-managed build', 'Property Unit', 'Mobile barcode scans for PAR/ICS updates.', 'Cloud', 'Hybrid', 'General Services', 'cyber_ext_leak', 2, 3, 'Moderate', 'Low'],
  ['IA', 'NSTP Deployment & Community Logs', 'NSTP', 'NSTP-DB-{abbr}', 'NSTP MIS', 'NSTP Coordinator', 'Student NSTP engagements and beneficiary data.', '10.20.{n}.40', 'Internal', 'NSTP Office', 'legal_dpa', 2, 3, 'Moderate', 'Moderate'],
];

const UNITS = [
  ['College of Nursing', 'NURS', 'GCA'],
  ['College of Architecture', 'ARCH', 'GCA'],
  ['College of Tourism', 'Tour', 'GCA'],
  ['CS & IT Programs', 'CSIST', 'GCA'],
  ['College of Business', 'COB', 'GCA'],
  ['Development Communication', 'DevCom', 'GCA'],
  ['Guidance & Counseling Office', 'GCO', 'GCA'],
  ['General Services Division', 'GSD', 'Main'],
  ['Property & Supply Office', 'PSO', 'Main'],
  ['University Research Office Annex', 'UROA', 'Annex'],
  ['PLC Laboratory School', 'PLC', 'LC'],
  ['Evening Programs Office', 'EPO', 'GCA'],
  ['Office for International Linkages Annex', 'OILA', 'GCA'],
  ['Continuing Education Hub', 'CEH', 'Annex'],
  ['Student Publication Room', 'PUB', 'GCA'],
  ['ROTC Unit Records', 'ROTC', 'GCA'],
  ['Campus Sustainability Office', 'CSO', 'GCA'],
  ['Disaster Risk Reduction Desk', 'DRR', 'GCA'],
  ['Gender & Development Secretariat', 'GAD', 'GCA'],
  ['Internal Audit Observation Logs', 'IAU', 'GCA'],
];

function esc(s) {
  return String(s ?? '').replace(/'/g, "''");
}

function dollarChunks(id, rb, ar, cq, mbssS, fw) {
  /** Per-row PostgreSQL dollar-quote tags so payloads never need escaping */
  const p = id.replace(/-/g, '');
  const dRb = `$rb_${p}$${rb}$rb_${p}$`;
  const dAr = `$ar_${p}$${ar}$ar_${p}$`;
  const cqS = JSON.stringify(cq);
  const dCq = `$cq_${p}$${cqS}$cq_${p}$`;
  const dM = `$mb_${p}$${mbssS}$mb_${p}$`;
  const dF = `$fw_${p}$${fw}$fw_${p}$`;
  return { dRb, dAr, dCq, dM, dF };
}

/** CIA 1–5 profiles by asset type (ISO 27005 / NIST SP 800-60 aligned). */
function baseProfile(type) {
  switch (type) {
    case 'IA': return { pii: 'Y', spi: 'Y', corp: 'Y', c: 4, i: 4, a: 4 };
    case 'PhA': return { pii: 'N', spi: 'N', corp: 'N', c: 2, i: 2, a: 3 };
    case 'PA': return { pii: 'Y', spi: 'N', corp: 'Y', c: 3, i: 3, a: 3 };
    case 'SA': return { pii: 'N', spi: 'N', corp: 'Y', c: 3, i: 4, a: 3 };
    case 'SV': return { pii: 'N', spi: 'N', corp: 'Y', c: 3, i: 3, a: 4 };
    case 'FA': return { pii: 'Y', spi: 'Y', corp: 'Y', c: 4, i: 4, a: 4 };
    default: return { pii: 'N', spi: 'N', corp: 'N', c: 3, i: 3, a: 3 };
  }
}

function jitterProfile(type, seed) {
  const p = { ...baseProfile(type) };
  const v = seed % 7;
  const clamp15 = x => Math.max(1, Math.min(5, x));
  if (v === 1) p.c = clamp15(p.c - 1);
  if (v === 2) p.i = clamp15(p.i - 1);
  if (v === 3) p.a = clamp15(p.a - 1);
  if (v === 4) { p.c = clamp15(p.c + 1); p.spi = type === 'IA' ? 'N' : p.spi; }
  if (v === 5 && type === 'SV') p.a = clamp15(p.a + 1);
  if (v === 6 && type === 'PhA') { p.c = 2; p.i = 2; p.a = 2; }
  return p;
}

function ciaMax(c, i, a) {
  return Math.max(c, i, a);
}

function ciaClassFromMax(c, i, a) {
  const m = ciaMax(c, i, a);
  if (m <= 1) return 'Public';
  if (m <= 2) return 'Internal Use';
  if (m <= 3) return 'Confidential';
  return 'Restricted';
}

/** Map legacy 1–3 band to 1–5 spread. */
function band15(v) {
  const n = parseInt(String(v), 10) || 3;
  if (n <= 3) return [2, 3, 4][Math.max(0, n - 1)];
  return Math.max(1, Math.min(5, n));
}

function defaultRiskBasis(primaryCat, threatBand, vulnBand) {
  const tb = band15(threatBand);
  const vb = band15(vulnBand);
  const threatStmt =
    `${primaryCat}: external or insider actor could misuse access paths against this asset (band ${tb}/5).`;
  const vulnStmt =
    'Residual control gaps include patch posture, privileged access breadth, logging coverage, and annual backup restore verification (band ' + vb + '/5).';
  return {
    threats: [{ band: tb, actor: 'external', path: 'credential', statement: threatStmt }],
    vulnerabilities: [{ band: vb, gap: 'access', scope: 'systemic', statement: vulnStmt }],
    threat_statement: threatStmt,
    vulnerability_statement: vulnStmt,
    occurrence_justification:
      'No known organizational incidents for this scenario; peer-sector and assurance testing inform a conservative likelihood estimate.',
    likelihood_qual: Math.max(1, Math.min(5, 2 + (tb + vb) % 3)),
    impact_qual: Math.max(1, Math.min(5, 2 + ((tb * 2 + vb) % 4))),
    prior_incidents: (tb + vb) % 5 === 0 ? 'Y' : 'N',
    threat_choice: tb,
    vulnerability_choice: vb,
  };
}

function ciaQuestionnaireFromProfile(profile, disclosureHint) {
  const scope =
    profile.pii === 'Y' && profile.spi === 'Y' ? 'spi' :
    profile.pii === 'Y' ? 'ordinary' : 'none';
  const clamp15 = x => Math.max(1, Math.min(5, parseInt(String(x), 10) || 3));
  return {
    disclosure_impact: String(clamp15(disclosureHint ?? profile.c)),
    integrity_impact: String(clamp15(profile.i)),
    availability_impact: String(clamp15(profile.a)),
    personal_data_scope: scope,
    corp_strategic: profile.corp,
    version: 2,
  };
}

function mbssPayload(type, env) {
  if (type === 'PhA')
    return { edr_epp: 'N', patch_current: 'N', disk_encryption: 'N', host_firewall: 'N', admin_priv_review: 'Y', last_review_date: '', notes: 'Physical asset — host MBSS baseline not applicable (system fixed).' };
  if (type === 'PA')
    return { edr_epp: 'N', patch_current: 'N', disk_encryption: 'N', host_firewall: 'N', admin_priv_review: 'Y', last_review_date: '', notes: 'Personnel asset — endpoint baseline not applicable (system fixed).' };
  return { edr_epp: 'Y', patch_current: 'Y', disk_encryption: 'Y', host_firewall: 'Y', admin_priv_review: 'Y', last_review_date: '2026-05-01', notes: 'ISMS seed baseline; validate per asset.' };
}

function firewallPayload(type, env) {
  if (type === 'PhA')
    return { scope: 'None documented', default_deny: 'N', change_control: 'Y', logging_soc: 'N', rule_review_cadence: 'Annual', overly_permissive: 'N', notes: 'Physical asset — perimeter at facility or campus layer only (system fixed).' };
  if (type === 'PA')
    return { scope: 'None documented', default_deny: 'N', change_control: 'Y', logging_soc: 'N', rule_review_cadence: 'Annual', overly_permissive: 'N', notes: 'Personnel asset — network perimeter not applicable (system fixed).' };
  if (env === 'Internet Facing' && ['SV', 'SA', 'IA', 'FA'].includes(type))
    return { scope: 'WAF', default_deny: 'Y', change_control: 'Y', logging_soc: 'Y', rule_review_cadence: 'Quarterly', overly_permissive: 'N', notes: 'Internet-facing; edge WAF or equivalent in scope.' };
  return { scope: 'Network firewall', default_deny: 'Y', change_control: 'Y', logging_soc: 'Y', rule_review_cadence: 'Quarterly', overly_permissive: 'N', notes: 'Internal or hybrid; campus firewall baseline.' };
}

/** Multi-risk scenarios: secondary angles stay at or below primary P×S. */
function riskScenariosForAsset(rowSeed, meta) {
  const { id, riskCategory, riskDesc, prob, sev, inherit, residual, resP, resSev,
    primaryCat, controlStrength = 'full' } = meta;
  const n =
    meta.type === 'PhA' || meta.type === 'PA' ? 1 :
      rowSeed % 11 === 0 ? 3 :
      rowSeed % 6 === 0 ? 2 :
      rowSeed % 4 === 0 ? 2 : 1;

  const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));
  const secondCats = ['operational_availability', 'legal_regulatory', 'supply_chain_dependency', 'insider_shadow_it'];
  const out = [];

  for (let k = 0; k < n; k++) {
    const tc = 2 + ((rowSeed + k * 7) % 4);
    const vc = 2 + ((rowSeed + k * 5) % 4);
    const cat =
      k === 0 ? riskCategory :
      `${secondCats[k % secondCats.length]}__${riskCategory}`;
    const desc =
      k === 0 ? riskDesc :
      `${secondCats[k % secondCats.length].replace(/_/g, ' ')} angle on the same asset: ${riskDesc.slice(0, 120)}`;

    let metrics;
    if (k === 0) {
      metrics = scenarioMetrics(prob, sev, controlStrength);
    } else {
      metrics = scenarioMetrics(
        clamp(prob - 1 - (k % 2), 1, 5),
        clamp(sev - 1 - (k % 2), 1, 5),
        'full',
      );
    }
    const { prob: p0, sev: s0, inherit: inh, residual: res, resProb: rp, resSev: rs } = metrics;

    /** @type {Record<string, unknown>} */
    const sc = {
      id: `${id.replace(/-/g, '')}-rs${k}`,
      riskCategory: cat,
      riskDesc: desc.slice(0, 4000),
      risk_basis: defaultRiskBasis(primaryCat, tc, vc),
      prob: p0,
      sev: s0,
      inherit: inh,
      residual: res,
      resProb: rp,
      resSev: rs,
      actionType: 'Mitigate',
      actionStatus: k === 1 ? 'In Progress' : 'Pending',
      actionPlan:
        k === 0 ? 'ISMS mitigation in progress.' :
          `Scenario-specific control gap closure — ${cat.split('__')[0]}.`,
      actionOwner: 'Asset Owner',
      actionDate: '2026-12-31',
    };
    out.push(sc);
  }
  return out;
}

/** @typedef {ReturnType<typeof buildRow>} BuiltRow */

function buildRow(idx0, counters, tpl, variant) {
  const [type] = tpl;
  counters[type] = (counters[type] || 0) + 1;
  const num = counters[type];
  const id = `${type}-${String(num).padStart(3, '0')}`;
  let name, group, hostname, server, custodian, description, ip, env, dept, cat, prob, sev;

  if (variant === 'base') {
    [, name, group, hostname, server, custodian, description, ip, env, dept, cat, prob, sev] = tpl;
  } else {
    const unit = UNITS[idx0 % UNITS.length];
    const [unitFull, abbr] = unit;
    const tplRow = tpl;
    const n = 40 + ((idx0 * 3) % 50);
    const campus = unit[2] || 'GCA';
    const ph = tplRow.slice(1).map((cell) => String(cell)
      .replace(/\{unit\}/g, unitFull)
      .replace(/\{abbr\}/g, abbr + String(idx0 % 900 + 100))
      .replace(/\{n\}/g, String(n))
      .replace(/\{campus\}/g, campus));
    [name, group, hostname, server, custodian, description, ip, env, dept, cat, prob, sev] = ph;
  }

  prob = +prob;
  sev = +sev;
  const risk = assignRealisticRisk(type, env, cat, idx0, prob, sev);
  prob = risk.prob;
  sev = risk.sev;

  const prof = jitterProfile(type, idx0);
  const cMax = ciaMax(prof.c, prof.i, prof.a);
  const cSum = prof.c + prof.i + prof.a;
  const ciaClass = ciaClassFromMax(prof.c, prof.i, prof.a);
  const disclosureHint = Math.max(1, Math.min(5, prof.c + (idx0 % 2 === 0 ? 0 : -1)));

  const tc = 2 + (idx0 % 4);
  const vc = 2 + ((idx0 * 2) % 4);
  const primaryCat = cat;
  const risk_basis = defaultRiskBasis(primaryCat, tc, vc);
  const scenarios = riskScenariosForAsset(idx0, {
    id, type, riskCategory: cat, riskDesc: description.slice(0, 600),
    prob, sev, inherit: risk.inherit, residual: risk.residual,
    resP: risk.resProb, resSev: risk.resSev,
    controlStrength: risk.controlStrength,
    primaryCat,
  });
  const reporting = worstScenarioForSeed(scenarios);
  prob = reporting.prob;
  sev = reporting.sev;
  const rollupInh = reporting.inherit;
  const rollupRes = reporting.residual;

  /** align roll-up narrative with primary scenario wording */
  const rollDesc =
    scenarios[0].riskDesc.length > description.length ?
      scenarios[0].riskDesc.slice(0, 8000) :
      description.slice(0, 240);

  const owners =
    `${custodian}\nDeputy custodian (${group})`;

  const justification =
    `CIA C=${prof.c}/I=${prof.i}/A=${prof.a} (max ${cMax}, sum ${cSum}, ${ciaClass}). ` +
    `Questionnaire maps disclosure (${disclosureHint}) to confidentiality; integrity and availability reflect operational reliance. ` +
    `Personal-data scope reflects privacy-law-aligned interpretation for this asset profile.`;

  const cq = ciaQuestionnaireFromProfile(prof, disclosureHint);
  const mbss = JSON.stringify(mbssPayload(type, env));
  const fw = JSON.stringify(firewallPayload(type, env));
  const rb = JSON.stringify(risk_basis);
  const ar = JSON.stringify(scenarios);
  const { dRb, dAr, dCq, dM, dF } = dollarChunks(id, rb, ar, cq, mbss, fw);

  return `('${id}', 'Approved', '${type}', '${esc(name)}', '${esc(group)}', '${esc(hostname)}', '${esc(server)}', '${esc(custodian)}', '${esc(description)}', '${esc(ip)}', '${esc(env)}', '${esc(dept)}', '${prof.pii}', '${prof.spi}', '${prof.corp}', ${prof.c}, ${prof.i}, ${prof.a}, ${cMax}, '${esc(ciaClass)}', '${esc(cat)}', '${esc(rollDesc)}', ${prob}, ${sev}, '${rollupInh}', '${rollupRes}', 'Mitigate', 'In Progress', 'ISMS mitigation in progress.', 'Asset Owner', '2026-12-31', '${esc(owners)}', '${esc(justification)}', ${dRb}, ${dAr}, ${dCq}, ${dM}, ${dF})`;
}

function ctrlPool(type) {
  const map = {
    IA: [1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 6, 2],
    PhA: [5, 6, 7, 8, 13],
    SA: [2, 3, 4, 9, 10, 11, 12, 13, 7],
    SV: [1, 2, 3, 4, 9, 10, 12, 13],
    PA: [1, 2, 3, 4, 6, 9, 12],
    FA: [1, 2, 3, 4, 7, 8, 9, 13],
  };
  return map[type] || [1, 3, 9, 11];
}

function ctrlsForId(id, type, idx0) {
  const pool = ctrlPool(type);
  const seed = [...id].reduce((a, c) => a + c.charCodeAt(0), 0) + idx0;
  const n = 4 + (seed % 4);
  const out = [];
  for (let j = 0; j < n; j++) {
    const cid = pool[(seed + j * 17) % pool.length];
    if (!out.includes(cid)) out.push(cid);
  }
  return out.slice(0, Math.min(n, pool.length)).sort((a, b) => a - b);
}

function main() {
  const counters = {};
  const valueLines = [];
  const baseCount = PLM_ASSETS_BASE.length;
  for (let i = 0; i < baseCount; i++) {
    valueLines.push(buildRow(i + 700, counters, PLM_ASSETS_BASE[i], 'base'));
  }
  let extraIdx = 0;
  while (valueLines.length < TARGET_TOTAL) {
    const tplRow = EXTRA_TEMPLATES[extraIdx % EXTRA_TEMPLATES.length];
    valueLines.push(buildRow(extraIdx + 880, counters, tplRow, 'extra'));
    extraIdx++;
  }

  const insertHeader = `-- ============================================================
-- 4. ASSET SEED — ${valueLines.length} contextualized records (+ CIA questionnaire 1–5,
--    ISO 27005 multi-risk JSON with threats[]/vulnerabilities[] bands 1–5, owners,
--    max-based classification, MBSS/firewall payloads) + controls
-- ============================================================

DELETE FROM public."AssetControls";
DELETE FROM public."Assets";

INSERT INTO public."Assets" (
  id, status, type, name, group_name, hostname, server, custodian, description,
  ip_address, environment, department, pii, spi, corp, "ciaC", "ciaI", "ciaA", "ciaScore", "ciaClass",
  "riskCategory", "riskDesc", prob, sev, inherit, residual,
  "actionType", "actionStatus", "actionPlan", "actionOwner", "actionDate",
  asset_owners, classification_justification, risk_basis_json, asset_risks_json, cia_questionnaire_json,
  mbss_json, firewall_json
) VALUES
${valueLines.join(',\n')};
`;

  const ctrlLines = [];
  const idsFromValues = [];
  const typeById = {};

  for (let i = 0; i < valueLines.length; i++) {
    const m = valueLines[i].match(/^\('([A-Za-z]+-\d{3})', 'Approved', '([A-Za-z]{2})',/);
    if (m) {
      idsFromValues.push(m[1]);
      typeById[m[1]] = m[2];
    }
  }

  idsFromValues.forEach((aid, ix) => {
    const t = typeById[aid];
    const ctrls = ctrlsForId(aid, t, ix + 900);
    for (const cid of ctrls) ctrlLines.push(`('${aid}', ${cid})`);
  });

  const ctrlBlock = `
INSERT INTO public."AssetControls" (asset_id, ctrl_id) VALUES
  ${ctrlLines.join(',\n  ')}
ON CONFLICT DO NOTHING;
`;

  const assetBlock = insertHeader + '\n' + ctrlBlock;

  let master = fs.readFileSync(masterPath, 'utf8');
  master = master.replace(/--\s+•\s+\d+\s+PLM-contextualized asset records/, `--   • ${valueLines.length} contextualized asset records`);
  master = master.replace(/--\s+•\s+\d+\s+contextualized asset records/, `--   • ${valueLines.length} contextualized asset records`);

  const startRe = /-- ============================================================\r?\n-- 4\. (?:PLM )?ASSET SEED/;
  const tailRe = /\r?\n-- ============================================================\r?\n-- 5\. ACTION-PLAN/;
  const startMatch = master.match(startRe);
  const i0 = startMatch ? startMatch.index : -1;
  const tailMatch = i0 >= 0 ? master.slice(i0).match(tailRe) : null;
  const i5 = tailMatch ? i0 + tailMatch.index : -1;
  if (i0 < 0 || i5 < 0) {
    console.error('Could not locate PLM asset seed block boundaries in master_setup.sql');
    process.exit(1);
  }
  master = master.slice(0, i0) + assetBlock.trimEnd() + master.slice(i5);

  fs.writeFileSync(masterPath, master);
  console.log('Updated', masterPath, 'with', valueLines.length, 'assets and', ctrlLines.length, 'control mappings.');
}

main();
