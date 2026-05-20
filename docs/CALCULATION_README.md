# ImpactLens — Risk calculation reference (May 2026)

This document is the **standalone, formula-level** description of the client-side risk engine. **Authoritative implementation:** `assets/scripts/app.js` — mainly `calculateRiskMath`, `runEnforcementEngine`, `getApplicableMandatorySets`, `mbssFwEvidenceMultiplierForControl`, and `readMbssFirewallEvidenceFromForm`.

For product context and standards citations, see **`README.md`** → *Risk-math engine* and **`docs/TOOL_OVERVIEW.md`**.

---

## 1. Variables and ratings

| Symbol | Meaning |
|--------|---------|
| **P** | Likelihood (probability), integer **1–5** (after inherent escalations). |
| **S** | Impact (severity), integer **1–5** (after inherent escalations). |
| **Inherent rating** | Qualitative band from **P×S** via fixed matrix **`INHERIT`** (key = `"S-P"`, severity first). |
| **Residual P / S** | Integers **≥ 1** after control reductions, **mandatory floors**, and display consistency rules. |
| **Residual rating** | From **`INHERIT`** using residual **S** and **P**, then possibly raised by **mandatory-control floors**. |

### 1.1 Inherent qualitative matrix (`INHERIT`)

Rows: **S** (severity). Columns: **P** (probability).

| S \\ P | 1 | 2 | 3 | 4 | 5 |
|--------|-----|-----|-----|-----|-----|
| **5** | Moderate | Moderate | High | High | High |
| **4** | Low | Moderate | Moderate | High | High |
| **3** | Low | Moderate | Moderate | Moderate | High |
| **2** | Low | Low | Moderate | Moderate | Moderate |
| **1** | Very Low | Low | Low | Low | Moderate |

---

## 2. Inherent risk (before controls)

1. Read **P** and **S** from the form (defaults **3** if missing).
2. Apply **inherent escalations** (order as in code — all use the post-step values):

   | Condition | Effect |
   |-----------|--------|
   | Environment = **Internet Facing** and threat starts with `cyber_ext` | `P = min(5, P + 1)` |
   | PII **or** SPI = **Y** and threat is `cyber_ext_leak` or `legal_dpa` | `S = 5` |
   | CIA sum **≥ 8** and (threat starts with `cyber_` **or** threat = `hr_insider`) | `S = max(S, 4)` |
   | Asset type = **FA** and threat starts with `cyber_` | `S = 5` |
   | Internet Facing **and** threat starts with `cyber_ext` | `P = max(P, 3)` |

3. **Inherent rating** = `INHERIT[String(S) + '-' + String(P)]` (default **Moderate** if key missing).

---

## 3. Threat-relevant controls

Only controls in **`controlMap[threat]`** reduce **P** / **S** for that scenario. If the threat key is unknown, the code falls back to **all 13** controls.

**Active relevant set** = checked, non-disabled controls **∩** that relevant set.

**Note:** The UI can still enable controls that are **mandatory-baseline only** (not threat-relevant). Those may **lift floors** when checked but contribute **0** to the raw P/S reduction sum unless they appear in the relevant set for the threat.

---

## 4. Control weights (`CONTROL_WEIGHTS`)

Each checked **relevant** control **i** contributes raw terms **w<sub>p,i</sub> × m<sub>i</sub>** and **w<sub>s,i</sub> × m<sub>i</sub>** where **m<sub>i</sub>** is the **MBSS / firewall evidence multiplier** (§6). Synergies add separate bonuses to the raw sums (§5).

| Control # | Name | w<sub>p</sub> | w<sub>s</sub> |
|-----------|------|---------------|---------------|
| 1 | Documented procedures | 0.5 | 0.3 |
| 2 | Segregation of duties | 0.6 | 0.3 |
| 3 | RBAC | 0.9 | 0.4 |
| 4 | MFA | 1.0 | 0.4 |
| 5 | Physical controls | 0.7 | 0.4 |
| 6 | Automated backup | 0.0 | 1.2 |
| 7 | Encryption | 0.0 | 1.4 |
| 8 | Asset disposal | 0.3 | 0.5 |
| 9 | EDR | 0.6 | 0.7 |
| 10 | Firewall / WAF | 0.9 | 0.4 |
| 11 | Vulnerability mgmt | 0.9 | 0.3 |
| 12 | Segmentation | 0.7 | 0.5 |
| 13 | IRP | 0.0 | 1.1 |

---

## 5. Synergy bonuses (`CONTROL_SYNERGIES`)

When **all** listed control IDs are **active and relevant**, add to the **raw** reduction totals:

| Controls | Δ raw P | Δ raw S | Label (in UI feedback) |
|----------|--------|--------|-------------------------|
| 3, 4 | +0.5 | +0.0 | RBAC + MFA |
| 6, 13 | +0.0 | +0.5 | Backup + IRP (BCP-DR) |
| 9, 10 | +0.4 | +0.0 | EDR + Firewall |
| 7, 12 | +0.0 | +0.4 | Encryption + Segmentation |
| 11, 9, 13 | +0.3 | +0.3 | Vuln Mgmt + EDR + IRP |

---

## 6. MBSS and firewall evidence multipliers

Evidence **does not** create reduction by itself. For each relevant control **i** that is **checked**, the code multiplies its **weight contribution** by **m<sub>i</sub> = mbssFwEvidenceMultiplierForControl(i, ev)** where **ev** comes from MBSS Y/N fields and firewall review fields (`readMbssFirewallEvidenceFromForm`).

| Control | Evidence rule | Multiplier **m** (typical range) |
|---------|----------------|-----------------------------------|
| **9** (EDR) | MBSS EDR/EPP = **Y** | **1.18** |
| **11** (Vuln) | MBSS Patch current = **Y** | **1.15** |
| **7** (Encryption) | MBSS Disk encryption = **Y** | **1.12** |
| **3** (RBAC) | MBSS Admin privilege review = **Y** | **1.10** |
| **10** (Firewall) | Composable bonus capped at **+0.20** over base 1.0: host firewall **+0.07**; default-deny **and** logging **and not** permissive **+0.12**; else default-deny **or** logging **+0.05**; documented firewall scope (not “None documented”) **+0.04**. **Cap:** `min(bonus, 0.2)` so **m ≤ 1.2**. If perimeter “overly permissive” = **Y**, multiply **m × 0.9**. |

If no rule applies, **m = 1**.

**Alignment (Info Sec / Admin):** `collectMbssFwAlignmentMessages` lists mismatches (e.g. EDR = Y but C9 off, or C9 on but EDR = N). Overly permissive rules with C10 on also warn that the C10 multiplier is damped.

---

## 7. Diminishing returns (saturating curve)

Let **rawP** = sum of weighted P terms (including synergies) and **rawS** = sum of weighted S terms.

For each dimension, with **score** = current **P** or **S** (before residual subtraction):

\[
\text{cap} = \max(0,\ \text{score} - 1)
\]

\[
\text{reduction} = \min\!\left(\text{cap},\ \text{cap} \cdot \bigl(1 - e^{-\text{raw} / 2}\bigr)\right)
\]

So **reduction ∈ [0, score − 1]** and stacks **sub-linearly** (constant **k = 2** in the exponent).

Then:

- **resP** = `max(1, round(P − reductionP))`
- **resS** = `max(1, round(S − reductionS))`
- **Residual rating (pre-floor)** = `INHERIT[resS + '-' + resP]` (default **Low** if missing).

---

## 8. Mandatory-control floors

`getApplicableMandatorySets` may attach one or more baselines:

| Baseline key | When it applies | Required control IDs | Floor |
|--------------|-----------------|----------------------|-------|
| `restrictedClass` | CIA sum **≥ 8** | 3, 4, 6, 7, 13 | Moderate |
| `confidentialClass` | CIA **6–7** (and not Restricted rule) | 3, 7, 13 | Moderate |
| `fa` | Asset type **FA** **and** `isPciInScopeFaAsset()` — internet-facing, `cyber_*` / payment-related threat; **not** petty-cash `phys_theft` ledgers | 4, 7, 11, 12 (MFA, Encryption, Vuln mgmt, Segmentation) | High |
| `pii` | PII or SPI = **Y** | 1, 3, 6, 7 | Moderate |
| `internetFacing` | Environment = Internet Facing | 10, 11, 13 | Moderate |

**FA floor** controls in code: `ids: [4, 7, 11, 12]` — MFA, Encryption, Vuln, Segmentation (**not** 3 in FA row).

If **any** required ID is **unchecked**, that set is “in gap”. Among all applicable sets with gaps, the engine keeps the **strictest floor** using rank: Very Low &lt; Low &lt; Moderate &lt; High.

If **RESIDUAL_FLOOR_RANK[residualRating] < RESIDUAL_FLOOR_RANK[floor]**:

1. **residualRating** is set to **floor**.
2. **resP / resS** are bumped so the display stays consistent with the floor:
   - **High:** `resP = max(resP, 4)`, `resS = max(resS, 4)`
   - **Moderate:** both **≥ 3**
   - **Low:** both **≥ 2**

---

## 9. Risk-appetite / treatment locks

After math, the **Treatment Type** dropdown may disable **Accept** when:

- Residual rating = **High**, or
- Type = **FA** and residual is not **Low** or **Very Low**, or
- CIA sum **≥ 8** and residual = **Moderate**

(Action-plan section visibility is also tied to Accept / Very Low in code.)

---

## 10. UI mirrors (MBSS section)

`syncMbssFirewallScoreMirrors()` copies **#r-inherit**, **#r-residual**, and the P×S display fields into **`#mbss-risk-score-strip`** so assessors see the same live ratings while editing MBSS/firewall. Values always match the main risk section after `calculateRiskMath()` runs.

---

## 12. Dashboard / register roll-up (v2.1)

Portfolio metrics (`renderDashboard`, nav action badge, residual donuts) use **`effectiveAssetResidual()` / `reportingAssetResidualTier()`** — worst **paired** scenario from `asset_risks_json`, not a live mandatory-floor pass over incomplete `AssetControls`.

**Why:** Live floor recompute on every approved asset without full control coverage inflates the register to ~100% Moderate/High. Seeded demo data targets ~18% elevated (7 High + 14 Moderate of 117).

**Register gap hint:** `liveRegisterMetricsForAsset()` still runs per row; if control gaps would raise the floor above the stored tier, UI shows **↑ control gap floor**.

---

## 11. Change control

When you change formulas, update **`docs/CALCULATION_README.md`** in the same change as **`app.js`**, and bump the `app.js?v=` / `main.css?v=` query strings in **`index.html`** so browsers load the new logic.
