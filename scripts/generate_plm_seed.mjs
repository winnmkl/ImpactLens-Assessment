/**
 * Generates supabase/seed_plm_assets.sql — run: node scripts/generate_plm_seed.mjs
 * For the full ISRA JSON + 100+ asset block embedded in master_setup.sql,
 * use: node scripts/regenerate_master_asset_seed.mjs (replaces section 4 of supabase/master_setup.sql).
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(__dirname, '..', 'supabase', 'seed_plm_assets.sql');

const PLM_ASSETS = [
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

function esc(s) { return (s || '').replace(/'/g, "''"); }

function row(type, name, group, host, server, cust, desc, ip, env, dept, risk, prob, sev, inh, res, idx) {
  const id = `${type}-${String(idx).padStart(3, '0')}`;
  const profiles = { IA: { pii: 'Y', spi: 'Y', corp: 'Y', c: 3, i: 3, a: 3 }, PhA: { pii: 'N', spi: 'N', corp: 'N', c: 1, i: 1, a: 2 },
    PA: { pii: 'Y', spi: 'N', corp: 'Y', c: 3, i: 2, a: 2 }, SA: { pii: 'N', spi: 'N', corp: 'Y', c: 2, i: 3, a: 3 },
    SV: { pii: 'N', spi: 'N', corp: 'Y', c: 2, i: 2, a: 3 }, FA: { pii: 'Y', spi: 'Y', corp: 'Y', c: 3, i: 3, a: 3 } };
  const p = profiles[type];
  const score = p.c + p.i + p.a;
  const classes = { 3: 'Public', 4: 'Internal Use', 5: 'Internal Use', 6: 'Confidential', 7: 'Confidential', 8: 'Restricted', 9: 'Restricted' };
  return `('${id}', 'Approved', '${type}', '${esc(name)}', '${esc(group)}', '${esc(host)}', '${esc(server)}', '${esc(cust)}', '${esc(desc)}', '${esc(ip)}', '${esc(env)}', '${esc(dept)}', '${p.pii}', '${p.spi}', '${p.corp}', ${p.c}, ${p.i}, ${p.a}, ${score}, '${classes[score]}', '${risk}', '${esc(desc.slice(0, 80))}', ${prob}, ${sev}, '${inh}', '${res}', 'Mitigate', 'In Progress', 'PLM ISMS mitigation in progress.', 'Asset Owner', '2026-12-31')`;
}

const counters = { IA: 0, PhA: 0, PA: 0, SA: 0, SV: 0, FA: 0 };
const lines = PLM_ASSETS.map(([type, ...rest]) => {
  counters[type]++;
  return row(type, ...rest, counters[type]);
});

const sql = `-- PLM Enterprise Asset Seed (${lines.length} assets) — Pamantasan ng Lungsod ng Maynila
-- Run AFTER enterprise_setup.sql. Clears and reloads demo assets (optional).

DELETE FROM public."AssetControls";
DELETE FROM public."Assets";

INSERT INTO public."Assets" (
  id, status, type, name, group_name, hostname, server, custodian, description,
  ip_address, environment, department, pii, spi, corp, "ciaC", "ciaI", "ciaA", "ciaScore", "ciaClass",
  "riskCategory", "riskDesc", prob, sev, inherit, residual,
  "actionType", "actionStatus", "actionPlan", "actionOwner", "actionDate"
) VALUES
${lines.join(',\n')};
`;

fs.writeFileSync(out, sql);
console.log('Wrote', lines.length, 'assets to', out);
