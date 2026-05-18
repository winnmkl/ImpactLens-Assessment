# ImpactLens — Demo script (inputs & calculations)

Use one coherent story across **three logins**: Standard User → Info Sec → Admin (CISO). Approx. **15–22 minutes** if you pause for questions.

**Reference:** formulas and matrices are spelled out in [`CALCULATION_README.md`](./CALCULATION_README.md).

---

## Cast & prerequisites

| Role | Purpose in demo |
|------|------------------|
| **Standard User** | Creates **Draft** via **Section 01** only (classification & risk cards are hidden). |
| **Info Sec** | Opens **Draft Queue**, completes **02–05** (threat, controls, residual, **MBSS / firewall**), submits **Pending**. |
| **Admin** | **Asset Approval** → approves (or edits if you want to show CISO override). |

**Tip:** Use a fresh draft ID or a unique asset name so it is easy to find in queues.

---

## Act 1 — Standard User (Insert record)

**Say:** *“Business users only register the asset on the network and org context. Risk, controls, and MBSS evidence are owned by Information Security.”*

### Section 01 — Primary details & network (enter exactly)

| Field | Value |
|-------|--------|
| **Asset type** | `IA` — Information Asset |
| **Asset name** | `PLM Student Records Web Portal` |
| **Group** | `Registrar / Admissions` |
| **Description** | `Web tier for enrolment, grades, and verification workflows; integrates to student DB.` |
| **Hostname** | `SRS-WEB-01` |
| **Server** | `IIS — VM-POOL-REG-02` |
| **Custodian** | `ICTO — Application Services` |
| **IP address** | `172.30.90.45` |
| **Environment** | `Internal` *(optional Act 2b: switch to **Internet Facing** before save — see §7)* |
| **Department** | `Registrar` |

**Action:** **Submit Draft →** (or equivalent save for user workflow).

**Say:** *“IA locks PII/SPI and CIA in the back end; the user does not edit those fields. Info Sec will see **Restricted-class** posture next.”*

---

## Act 2 — Info Sec (Draft queue → same asset)

Open the draft. Sections **02–05** appear.

### Section 02 — Data & classification (system-enforced for IA)

**Say:** *“For IA the app fixes sensitivity to match policy.”*

| Field | Locked / expected |
|-------|-------------------|
| **PI / SPI / Corp** | Yes / Yes / Yes |
| **C / I / A** | 3 / 3 / 3 → **CIA sum = 9** → **Restricted** band |

**Calculation note:** CIA **≥ 8** activates the **`restrictedClass`** mandatory set (controls **3, 4, 6, 7, 13**) with residual **floor Moderate** if any are missing (see §5).  
**PII = Y** also activates **`pii`** mandatory set (**1, 3, 6, 7**), same **Moderate** floor if gapped.

---

### Section 03 — Threat & controls

#### Step 2A — Show **compliance floor** (incomplete controls) — *matches on-screen “Mandatory Control Gaps”*

Use this beat when you want the UI to look exactly like the **Mandatory Control Gaps** panel (Restricted-class narrative + orange **Moderate** residual floor).

1. **Risk category:** `Cyber Security - External` → **Ransomware / Malware attacks** (`cyber_ext_ransomware`).  
   - This fills the template (**P = 4**, **S = 5**).

2. **Implemented controls:** check **only** these three (leave everything else off):
   - **C1** Documented procedures  
   - **C3** Role-Based Access Control (RBAC)  
   - **C6** Automated Information backup  

3. Scroll to **Mandatory Control Gaps**. **Say:** *“This panel is standards-driven — it’s separate from threat-by-threat math.”*

**What appears on screen (your demo screenshot pattern)**

| Panel element | Meaning |
|---------------|---------|
| **Restricted Classification (CIA ≥ 8)** | IA locks **C+I+A = 9** → **`restrictedClass`** baseline applies. |
| **Residual floor: Moderate** | Until required controls are ticked, residual **cannot fall below Moderate** (strictest gap wins). |
| Copy about ISO / NIST / MFA / backup / encryption / IR | Matches rationale strings for **`restrictedClass`** in code (`MANDATORY_CONTROLS.restrictedClass`). |
| **Missing: C4 — MFA** | Framework refs you may narrate: NIST PR.AA-03, ISO A.8.5, CIS 6.x, SOC 2 CC6.1, PCI 8.x *(shown per control in UI)*. |
| **Missing: C7 — Encryption** | NIST PR.DS-01/02, ISO A.8.24, CIS 3.x, SOC 2 CC6.x, PCI 3–4.x. |
| **Missing: C13 — Incident Response Plan** | NIST RS/RC.*, ISO A.5.24–27, CIS 17.x, SOC 2 CC7.x, PCI 12.10. |

**Why those three gaps:** **`restrictedClass`** requires **C3, C4, C6, C7, C13**. You satisfied **C3** and **C6** only → still missing **C4, C7, C13**.  
Separately, **`pii`** baseline requires **C1, C3, C6, C7** — with **C7** still off, that set also stays gapped until you enable encryption.

**Say / calculation:**

| Step | What the engine does |
|------|----------------------|
| **Base** | From template **P = 4**, **S = 5**. |
| **Escalations** *(Internal, ransomware)* | Restricted CIA + **`cyber_` threat:** **S ← max(S, 4)** → stays **5**. No **Internet-facing** bump yet. |
| **Inherent band** | Lookup **`INHERIT["5-4"]`** → **High** *(CALCULATION_README §1.1 — severity row **5**, probability column **4**)* |
| **Threat-side math** *(ransomware)* | Relevant control IDs include **1, 4, 6, 7, 9, 10, 11, 13**. Of those you only tick **C1** and **C6** → limited raw reduction vs checking MFA/encryption/IRP. |
| **Mandatory floors** | Gap on **`restrictedClass`** → **floor = Moderate**. Panel text: baseline-only controls **do not** reduce **P/S** until they’re threat-relevant **and** checked — but missing mandatory IDs **still cap** residual until closed (§8). |

**Audience sees:** Tags show three controls selected; **Mandatory Control Gaps** lists **C4, C7, C13**; **Residual** badge stays **Moderate** (or floor lifts displayed residual even if raw math suggests lower).

---

#### Step 2B — Complete controls + synergies + MBSS

1. Tick **at minimum** (closes **Restricted** and **PII** gaps given Step 2A):  
   **C4** (MFA), **C7** (Encryption), **C13** (IRP) — keep **C1, C3, C6** as already selected → full set **1,3,4,6,7,13**.  

2. For **ransomware-relevant** reductions and a strong story, also tick:  
   **C9** (EDR), **C10** (Firewall/WAF), **C11** (Vuln scanning).  

**Synergies you can cite** *(if every ID in the combo is checked **and** in the ransomware relevant set)*:

| Combo | Effect on math |
|-------|----------------|
| **C3 + C4** | +0.5 raw **probability** reduction (RBAC + MFA) |
| **C9 + C10** | +0.4 raw **probability** (EDR + Firewall) |
| **C11 + C9 + C13** | +0.3 raw **P**, +0.3 raw **S** (detect–respond loop) |

Weighted sums are then passed through **diminishing returns** (cannot drop below 1 or wipe more than **score − 1** per dimension) — CALCULATION_README §7.

**Say:** *“Floors disappeared because mandatory baselines are satisfied; residual now reflects weighted controls plus the saturation curve.”*  
*(Exact residual tier depends on live math — read the badges and **Residual P×S** fields.)*

---

### Section 04 — Residual risk & treatment

Suggested demo values:

| Field | Suggested value |
|-------|------------------|
| **Treatment** | `Mitigate` *(if residual still High/Moderate; **Accept** may be blocked — see §6)* |
| **Status** | `In Progress` |
| **Action plan** | `Phishing-resistant MFA rollout; immutable backup restore test Q2; quarterly vuln SLA review.` |
| **Owner** | `ICTO Information Security` |
| **Target date** | Pick a future date (~90 days) |

**Say:** *“Restricted + Moderate residual blocks **Accept** in the engine; High residual always blocks Accept.”*

---

### Section 05 — MBSS & firewall *(do not skip in demo)*

Set **endpoint MBSS**:

| Field | Value |
|-------|--------|
| **EDR / anti-malware** | `Y` |
| **Patch & vuln management** | `Y` |
| **Full-disk encryption** | `Y` |
| **Host firewall** | `Y` |
| **Admin / least-priv review** | `Y` |
| **Last review date** | Today *(or demo date)* |
| **Notes** | `Defender / Intune compliant; CIS L1 hardening.` |

Set **Perimeter**:

| Field | Value |
|-------|--------|
| **Scope** | `Network firewall` or `Host + perimeter` |
| **Default deny** | `Y` |
| **Change control** | `Y` |
| **Logging / SOC** | `Y` |
| **Rule review cadence** | `Quarterly` |
| **Overly permissive rules** | `N` *(if **Y**, C10 multiplier is reduced — good “what if” tweak)* |

**Calculation / narrative:**

- Evidence multiplies **only** contributions for controls **already checked** in §03 (**C9 ← EDR**, **C11 ← patch**, **C7 ← disk encryption**, **C3 ← admin review**, **C10 ← host firewall + perimeter answers** — CALCULATION_README §6).
- The **risk score strip** in §05 mirrors §04 (**inherent/residual** + P×S) so edits here stay aligned with live math.
- If MBSS contradicts controls (e.g. EDR=Y but C9 unchecked), an **alignment** note appears above the framework panel — fix for audit consistency.

**Action:** **Submit for Approval →**

---

## Act 3 — Admin (CISO)

**Say:** *“CISO verifies treatment is within appetite and evidence matches control claims.”*

1. **Asset Approval** queue → open the pending record.  
2. Optionally skim **05** MBSS/perimeter vs **C9/C10/C11**.  
3. **Approve.**

**Say:** *“Approved rows appear on the Asset Table and dashboards; exports include Sheets 08/09 (MBSS + firewall) for Info Sec / Admin packs.”*

---

## Quick calculation cheat sheet *(this scenario)*

| Topic | Demo line |
|-------|-----------|
| **Inherent** | Starts from **P,S** (+ escalations); band = **`INHERIT[S-P]`**. |
| **Relevant controls** | Only IDs in **`controlMap[threat]`** reduce **P/S** for that scenario. |
| **Mandatory floors** | **Restricted**: **3,4,6,7,13**. **PII**: **1,3,6,7**. **Internet-facing**: **10,11,13**. Strictest gap wins. |
| **Residual** | Weight × evidence multiplier → synergy bonuses → diminishing returns → then apply floor if any mandatory set incomplete. |
| **Treatment locks** | **High** residual → no **Accept**. **Restricted + Moderate** → no **Accept**. **FA** → **Accept** only if residual **Low** or **Very Low**. |

---

## Optional Act 2b — Internet-facing escalation

Before Info Sec finishes the draft **(or Standard User edits environment if permitted)**:

- Set **Environment** = **`Internet Facing`**.  
- **Availability** on IA may **lock to 3** (environment-driven in code).

**Extra rules:**

| Rule | Effect |
|------|--------|
| **Internet + `cyber_ext_*`** | **P ← P+1** (cap 5); **P ≥ 3** for external cyber threats. |
| **`internetFacing` baseline** | Requires **10, 11, 13** all checked — else **Moderate** floor |

**Say:** *“Same asset exposed to the internet picks up CIS-style perimeter and IR baselines plus likelihood bumps.”*

---

## Closing lines *(15 seconds)*

*“ImpactLens separates **intake** from **risk and evidence**. Math is transparent: escalation matrix → threat-scoped controls → MBSS/perimeter amplifiers → mandatory standards floors → appetite rules on acceptance.”*

---

## Document history

| Date | Notes |
|------|--------|
| 2026-05-18 | Initial demo script aligned with `app.js` + `CALCULATION_README.md`. |
| 2026-05-18 | Step 2A aligned with UI **Mandatory Control Gaps** screenshot (only **C1+C3+C6** → gaps **C4, C7, C13**, floor **Moderate**). |
