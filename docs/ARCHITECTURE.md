# ImpactLens Architecture

## System Overview

ImpactLens is a **client-side only, localStorage-backed** web application for conducting Information Security Risk Assessments (IAR). It requires no backend server or database.

### Key Principles
- ✅ **Zero Server Dependency**: Pure client-side application
- ✅ **Data Privacy**: All data stored locally in browser
- ✅ **No Registration**: Works immediately upon opening
- ✅ **Offline Capable**: Functions without internet (except CDN libraries)
- ✅ **Responsive Design**: Desktop, tablet, and mobile ready

---

## Technology Stack

### **Frontend**
| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Markup** | HTML5 Semantic | Page structure and forms |
| **Styling** | CSS3 + CSS Variables | Modern responsive design with theming |
| **Logic** | Vanilla JavaScript (ES6) | No framework dependencies |
| **Database** | AlaSQL | In-browser SQL engine |
| **Export** | XLSX.js | Excel workbook generation |

### **Libraries (CDN)**
```html
<!-- Math/Analysis -->
<script src="https://cdn.jsdelivr.net/npm/alasql@4.2.2/dist/alasql.min.js"></script>

<!-- Export -->
<script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js"></script>

<!-- Fonts -->
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&family=Bebas+Neue&display=swap">
```

---

## Data Model

### **Core Tables (AlaSQL)**

#### **Assets Table**
Stores all registered organizational assets with risk profiles.

```sql
CREATE TABLE Assets (
    id STRING PRIMARY KEY,           -- IA-001, PhA-002, etc.
    type STRING,                     -- IA, PhA, PA, SA, SV, FA
    name STRING,                     -- Asset name
    group_name STRING,               -- Department/unit
    owner STRING,                    -- Asset owner
    user_name STRING,                -- Primary user
    custodian STRING,                -- IT custodian
    description STRING,              -- Asset description
    pii STRING,                      -- Y/N: Contains personal info
    spi STRING,                      -- Y/N: Contains sensitive PI
    corp STRING,                     -- Y/N: Contains corporate info
    ciaC INT,                        -- Confidentiality score (1-3)
    ciaI INT,                        -- Integrity score (1-3)
    ciaA INT,                        -- Availability score (1-3)
    ciaScore INT,                    -- Total CIA score (3-9)
    ciaClass STRING,                 -- Public/Internal/Confidential/Restricted
    riskDesc STRING,                 -- Risk description
    prob INT,                        -- Probability (1-5)
    sev INT,                         -- Severity (1-5)
    inherit STRING,                  -- Inherent risk level
    effectiveness STRING,            -- Control effectiveness rating
    residual STRING,                 -- Residual risk level
    actionPlan STRING,               -- Mitigation plan text
    actionOwner STRING,              -- Owner of action plan
    actionDate STRING                -- Target completion date
);
```

#### **AssetControls Table**
Many-to-many mapping between assets and implemented controls.

```sql
CREATE TABLE AssetControls (
    asset_id STRING,                 -- FK to Assets.id
    ctrl_id INT                      -- Control ID (1-8)
);
```

#### **ReportData Table**
Metadata for generating Excel reports and sign-offs.

```sql
CREATE TABLE ReportData (
    id INT PRIMARY KEY,              -- Single record (id=1)
    docDate STRING,                  -- Approval date
    docVersion STRING,               -- Version number
    docAuthor STRING,                -- Document author
    docApproval STRING,              -- Approval authority
    docDesc STRING,                  -- Modification description
    revHigh STRING,                  -- Revision highlights
    initHigh STRING,                 -- Initial highlights
    prepName STRING,                 -- Prepared by name
    prepTitle STRING,                -- Prepared by title
    revName STRING,                  -- Reviewed by name
    revTitle STRING,                 -- Reviewed by title
    appName STRING,                  -- Approved by name
    appTitle STRING                  -- Approved by title
);
```

### **Control Library**
Pre-defined security controls available for selection:

```javascript
const CTRL_NAMES = [
    1: "Documented operating procedures",
    2: "Segregation of duties",
    3: "Access restriction",
    4: "Removal of access (off-boarding)",
    5: "Physical entry controls",
    6: "Information backup",
    7: "Encryption",
    8: "Asset disposal procedures"
];
```

---

## Risk Assessment Matrices

### **CIA Classification**
Combines Confidentiality, Integrity, and Availability scores to determine information classification.

```
Score Range → Classification
3            → Public
4-5          → Internal Use
6-7          → Confidential
8-9          → Restricted
```

### **Inherent Risk Matrix (5×5)**
Combines probability and severity to assess inherent (pre-control) risk.

```
Severity ↓ / Probability →   1-Rare  2-Unlikely  3-Possible  4-Likely  5-Certain
5-High                         Mod      Mod         High        High      High
4-Major                        Low      Mod         Mod         High      High
3-Moderate                     Low      Mod         Mod         Mod       High
2-Minor                        Low      Low         Mod         Mod       Mod
1-Insignificant                VL       Low         Low         Low       Mod
```

### **Residual Risk Matrix**
Applies control effectiveness to determine remaining risk after mitigation.

```
Control Effectiveness ↓ / Inherent Risk →   VL    Low   Mod   High
Fully Effective                              VL    Low   Low   Low
Substantially Effective                      Low   Low   Mod   Mod
Partially Effective                          Low   Mod   Mod   High
Ineffective                                  Low   Mod   High  High
```

---

## File Structure & Code Organization

```
index.html                    ← DOM markup only (clean separation)
├── Header
├── Navigation
├── Main content (7 sections)
└── Notification system

assets/styles/main.css        ← All styling (3500+ lines)
├── CSS Variables (themes)
├── Core Layout (header, sidebar, main)
├── Components (cards, buttons, badges)
├── Forms (inputs, selects, multi-select)
├── Data Viz (charts, matrices, tables)
└── Utilities (animations, responsive)

assets/scripts/app.js         ← All JavaScript (1000+ lines)
├── Database initialization
├── Constants & lookups
├── Navigation logic
├── Form calculations
├── CRUD operations
├── UI rendering
├── Export functions
└── Event handlers
```

---

## Data Flow & State Management

### **Create Flow**
```
User fills form
    ↓
Form validation (type, name required)
    ↓
Generate auto ID or use existing
    ↓
Calculate CIA score & classification
    ↓
Calculate inherent risk (prob × sev)
    ↓
Calculate residual risk (inherent + effectiveness)
    ↓
AlaSQL INSERT to Assets table
    ↓
Insert selected controls to AssetControls
    ↓
persistDB() → Save to localStorage
    ↓
clearForm()
    ↓
Navigate to register, renderRegister()
    ↓
notify() → Show success toast
```

### **Read Flow**
```
showSection('dashboard')
    ↓
renderDashboard()
    ↓
Query AlaSQL tables
    ↓
Format data as HTML
    ↓
Inject into DOM
    ↓
Apply CSS classes
    ↓
Render complete
```

### **Update Flow**
```
User clicks Edit button
    ↓
editAsset(id)
    ↓
Query AlaSQL for asset record
    ↓
Populate form fields
    ↓
Show action plan section if needed
    ↓
Set editingId global variable
    ↓
Change form title to UPDATE
    ↓
User modifies and saves
    ↓
saveAssetToDB() detects editingId
    ↓
DELETE old record
    ↓
INSERT new record (same ID)
    ↓
persistDB()
```

### **Delete Flow**
```
User clicks Delete button
    ↓
confirm() dialog
    ↓
DELETE from Assets where id = ?
    ↓
DELETE from AssetControls where asset_id = ?
    ↓
persistDB()
    ↓
Re-render all affected sections
    ↓
notify()
```

---

## Persistence Layer

### **localStorage Keys**
All data persists in three JSON strings in browser localStorage:

```javascript
localStorage.getItem('impactlens_assets')     // Asset records (JSON array)
localStorage.getItem('impactlens_controls')   // Control mappings (JSON array)
localStorage.getItem('impactlens_report')     // Report metadata (JSON array)
localStorage.getItem('impactlens_initialized') // First-run flag
```

### **Sync Pattern**
```javascript
// Any time data changes:
persistDB() {
    localStorage.setItem('impactlens_assets', 
        JSON.stringify(alasql('SELECT * FROM Assets')));
    localStorage.setItem('impactlens_controls', 
        JSON.stringify(alasql('SELECT * FROM AssetControls')));
    localStorage.setItem('impactlens_report', 
        JSON.stringify(alasql('SELECT * FROM ReportData')));
}
```

### **Data Lifetime**
- **Survives**: Page reloads, browser restarts
- **Lost on**: Browser cache clear, private/incognito mode end, localStorage disabled
- **First Run**: Sample asset (IA-001) inserted, never re-populated

---

## UI Architecture

### **Section-Based Navigation**
Each major view is a hidden `<div class="section">` that is shown/hidden via CSS:

```html
<div id="sec-dashboard" class="section active"><!-- Dashboard --></div>
<div id="sec-add" class="section"><!-- Add Asset Form --></div>
<div id="sec-register" class="section"><!-- Asset Table --></div>
<div id="sec-risk" class="section"><!-- Risk Register --></div>
<div id="sec-controls" class="section"><!-- Control Metrics --></div>
<div id="sec-actions" class="section"><!-- Action Plans --></div>
<div id="sec-report" class="section"><!-- Reporting --></div>
<div id="sec-guidelines" class="section"><!-- Guidelines --></div>
```

### **Navigation Pattern**
```javascript
showSection(name) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    
    // Show selected section
    document.getElementById('sec-' + name).classList.add('active');
    
    // Update active nav item
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    [find matching nav item].classList.add('active');
    
    // Trigger rendering functions
    if (name === 'dashboard') renderDashboard();
    if (name === 'register') renderRegister();
    // ... etc
}
```

---

## Export System

### **Excel Workbook Structure**
Generated workbook contains 4 sheets:

#### **1. Document History**
```
| DATE APPROVED | VERSION NO. | DESCRIPTION | CREATED/MODIFIED BY | APPROVAL |
```

#### **2. Highlights**
```
| Revision Highlights |
| Initial Overall Highlights |
```

#### **3. IAR_Data**
Complete asset register with all fields:
```
| ID | Name | Type | Group | Owner | ... | Inherent | Controls | Residual | Action Plan |
```

#### **4. SIGN OFF**
```
| PREPARED BY (Name, Title) |
| REVIEWED BY (Name, Title) |
| APPROVED BY (Name, Title) |
```

### **Export Process**
```javascript
exportDataXLSX() {
    1. Query AlaSQL: SELECT * FROM Assets
    2. Query AlaSQL: SELECT * FROM AssetControls
    3. Query AlaSQL: SELECT * FROM ReportData
    4. Format data as XLSX workbook
    5. Generate 4 sheets with proper formatting
    6. Use XLSX.writeFile() to trigger browser download
    7. File: ImpactLens_IAR_Export.xlsx
}
```

---

## Risk Calculation Engine

### **Inherent Risk Calculation**
```javascript
function getInherit() {
    const p = document.getElementById('f-prob').value;  // 1-5
    const s = document.getElementById('f-sev').value;   // 1-5
    const rating = INHERIT[s + '-' + p];                // Lookup table
    const score = p * s;                                // 1-25
    return { p, s, rating, score };
}
```

### **Residual Risk Calculation**
```javascript
function updateResidual() {
    const { rating: inherit } = getInherit();
    const effectiveness = document.getElementById('f-effectiveness').value;
    const residual = RESIDUAL[effectiveness][inherit.replace(' ', '_')];
    // Result: 'Very Low' | 'Low' | 'Moderate' | 'High'
}
```

### **Risk-Based Action Triggers**
```javascript
// Show action plan section only for High/Moderate risks
const ap = document.getElementById('action-plan-section');
ap.style.display = (residual === 'High' || residual === 'Moderate') 
    ? 'block' 
    : 'none';
```

---

## Performance Considerations

### **Optimization Techniques**
1. **Lazy Rendering**: Only render visible section on navigation
2. **Query Caching**: Queries executed on demand, not polling
3. **DOM Batching**: Use `.innerHTML` for multiple element updates
4. **Event Delegation**: Single click handler for dropdown instead of per-item
5. **CSS Classes**: Use class toggling instead of inline styles where possible

### **Data Limits**
- **Realistic**: 500-1000 assets (localStorage ~10MB limit)
- **Performance**: Under 100ms for typical queries
- **Export Time**: <1 second for 500-asset workbook

---

## Browser Storage Model

### **LocalStorage Quota**
- Chrome/Edge: 10MB per origin
- Firefox: 10MB per origin
- Safari: 5MB per origin
- Mobile: Variable (typically 5-10MB)

### **Estimation**
Average asset record: ~500 bytes
500 assets: ~250KB (well within limits)

---

## Security Considerations

### **Client-Side Only**
- ✅ No server = no network transmission of sensitive risk data
- ⚠️ Data only as secure as user's device
- ⚠️ Private browsing mode: Data lost on session end

### **Recommendations**
- Use on trusted devices only
- Regular exports for backup
- Consider encrypted local storage plugin for sensitive deployments
- Educate users on localStorage limitations

---

## Testing & Validation

### **Test Scenarios**
1. **Asset Creation**: Add asset of each type (IA, PhA, PA, SA, SV, FA)
2. **Risk Calculation**: Verify inherent & residual calculations
3. **Control Tracking**: Add/remove controls, verify in export
4. **Excel Export**: Validate workbook structure & data
5. **Persistence**: Reload page, verify data persists
6. **Multi-Asset**: Test with 50+ assets for performance

### **Edge Cases**
- Empty form submissions (caught by validation)
- Duplicate asset IDs (prevented by SQL PRIMARY KEY)
- Missing enum values (defaults to fallback)
- localStorage disabled (graceful degradation)

---

## Future Enhancements

Possible improvements for future versions:

- [ ] Backend API integration for team collaboration
- [ ] Real-time cloud sync
- [ ] Advanced charting library (Chart.js, D3.js)
- [ ] Multi-user permissions & audit trail
- [ ] Risk trend analysis over time
- [ ] API integrations (Jira, ServiceNow)
- [ ] Mobile app (React Native)
- [ ] Accessibility improvements (WCAG AAA)
- [ ] Dark mode toggle
- [ ] Multi-language support

---

## Deployment Checklist

Before production deployment:

- [ ] Test on Chrome, Firefox, Safari, Edge
- [ ] Verify all export functionality
- [ ] Check localStorage quota warnings
- [ ] Mobile responsiveness testing
- [ ] Performance profiling (Chrome DevTools)
- [ ] Accessibility audit (axe DevTools)
- [ ] Documentation review
- [ ] Create setup guide for users

---

**Architecture Last Updated: April 2026**
