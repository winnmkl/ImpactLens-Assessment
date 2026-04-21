# ImpactLens — Risk Assessment Tool

A comprehensive Information Security Risk Assessment (IAR) management system for tracking, analyzing, and mitigating security risks across organizational assets.

## 🎯 Overview

**ImpactLens** is a standalone web-based risk assessment platform that enables security professionals to:

- Register and categorize information and physical assets
- Conduct inherent and residual risk assessments using probability/severity matrices
- Track implemented security controls and their effectiveness
- Generate action plans for high and moderate residual risks
- Export comprehensive Excel reports for management review and sign-offs

## 📁 Project Structure

```
ImpactLens-Assessment/
├── index.html                    # Main HTML entry point
├── assets/
│   ├── styles/
│   │   └── main.css             # All styling (5000+ lines, organized by section)
│   ├── scripts/
│   │   └── app.js               # Complete application logic
│   └── images/                  # Reserved for future icons/assets
├── docs/                        # Documentation
├── .gitignore                   # Git ignore rules
└── README.md                    # This file
```

## 🚀 Quick Start

### 1. Clone or Download
```bash
git clone <repository-url>
cd ImpactLens-Assessment
```

### 2. Run Locally
No build step required! Simply open `index.html` in a modern web browser:
```bash
# Using Python 3
python -m http.server 8000

# Using Node.js
npx http-server

# Or just double-click index.html
```

### 3. Access the App
Navigate to `http://localhost:8000` or open the file directly in your browser.

## 🏗️ Architecture

### **Frontend Stack**
- **HTML5**: Semantic markup with section-based navigation
- **CSS3**: Modern design with CSS variables for theming
- **JavaScript (ES6)**: Vanilla JS, no frameworks required
- **AlaSQL**: In-browser SQL database for asset management
- **XLSX**: Excel export functionality
- **Google Fonts**: IBM Plex (Mono/Sans) + Bebas Neue

### **Data Storage**
All data is stored **locally in browser localStorage** (no server required):
- `impactlens_assets` — Asset registry
- `impactlens_controls` — Control implementation tracking
- `impactlens_report` — Report metadata and sign-offs

## 📊 Core Features

### **Dashboard**
- Real-time metric cards (Total Assets, High Risk Count, Moderate Risk Count, PII Assets)
- Asset Type Breakdown (bar charts)
- Residual Risk Distribution
- Information Classification analysis
- Top 5 Risk Assets widget

### **Asset Management**
- Add/Edit/Delete information, physical, software, service, people, and financial assets
- Classify assets by Confidentiality, Integrity, and Availability (CIA)
- Identify and track risks for each asset
- Select and track implemented controls
- Calculate control effectiveness

### **Risk Assessment**
- **Inherent Risk Matrix**: 5×5 probability/severity heatmap
- **Risk Templates**: Pre-populated risk scenarios from standards-based categories
- **Residual Risk Calculation**: Based on inherent risk + control effectiveness
- **Action Planning**: Required for High and Moderate residual risks

### **Control Metrics**
- Track control implementation coverage across all assets
- Visualize control effectiveness distribution
- Aggregate security posture metrics

### **Reporting**
- Document history (version, author, approval dates)
- Executive highlights (revision and initial)
- Official sign-off sheet (Prepared By / Reviewed By / Approved By)
- **Export to Excel**: Multi-sheet workbook with IAR data, history, highlights, and sign-offs

## 🔐 Risk Assessment Framework

### **Inherent Risk Calculation**
Risk Score = Probability (1–5) × Severity (1–5)

### **Residual Risk Matrix**
Residual Risk = f(Inherent Risk, Control Effectiveness)

| Control Effectiveness | Very Low | Low | Moderate | High |
|-|-|-|-|-|
| **Fully Effective** | V.Low | Low | Low | Low |
| **Substantially Effective** | Low | Low | Moderate | Moderate |
| **Partially Effective** | Low | Moderate | Moderate | High |
| **Ineffective** | Low | Moderate | High | High |

### **Pre-Defined Risk Templates**
- **Physical Security**: Theft, facility destruction
- **Human Resources**: Insider threats, accidental deletion
- **Cyber External**: Ransomware, data breaches, DDoS, supply chain
- **Cyber Internal**: Unauthorized admin access, unpatched vulnerabilities
- **Compliance**: Data Privacy Act violations

## 🎨 Design System

### **Color Palette**
- **Accent**: `#c8ff00` (Neon Lime)
- **Accent2**: `#00d4ff` (Cyan)
- **Danger**: `#ff4444` (Red)
- **Warn**: `#ff9900` (Orange)
- **Success**: `#00cc77` (Green)
- **Purple**: `#aa44ff`

### **Typography**
- **Display**: Bebas Neue (headings)
- **Sans**: IBM Plex Sans (body)
- **Mono**: IBM Plex Mono (data, labels)

## 📋 Asset Types

| ID | Type | Examples |
|-|-|-|
| **IA** | Information Asset | Databases, documentation, business processes |
| **PhA** | Physical Asset | Servers, magnetic media, facilities |
| **PA** | People Asset | Employees, contractors, consultants |
| **SA** | Software Asset | Applications, development tools |
| **SV** | Service Asset | Cloud services, technical services |
| **FA** | Financial Asset | Cash, stocks, intellectual property |

## 📤 Export Format

**Excel Workbook** (`ImpactLens_IAR_Export.xlsx`) includes:
1. **Document History** — Versioning and approval metadata
2. **Highlights** — Executive summary and revision notes
3. **IAR Data** — Complete asset register with risk assessments
4. **Sign-Off** — Official approvals (Prepared/Reviewed/Approved)

## 🛠️ Development Guide

### **File Organization**
- `index.html` — DOM structure only (no inline styles or scripts)
- `assets/styles/main.css` — All CSS (~3500 lines, well-organized)
- `assets/scripts/app.js` — All JavaScript (~1000+ lines, modular functions)

### **Adding New Features**
1. **New page section**: Add a `<div id="sec-name" class="section">` to HTML
2. **Navigation**: Add nav item that calls `showSection('name')`
3. **Logic**: Add rendering functions to `app.js`
4. **Styling**: Update `main.css` with new component classes

### **Key Functions in `app.js`**
- `showSection(name)` — Navigate between pages
- `saveAssetToDB()` — Create/update asset
- `deleteAsset(id)` — Remove asset
- `renderDashboard()`, `renderRegister()`, `renderRiskRegister()` — UI rendering
- `exportDataXLSX()` — Excel export
- `applyRiskTemplate()` — Pre-populate risk scenarios

## 🔄 Data Flow

```
User Input → Form Validation → AlaSQL Insert → localStorage Sync → UI Re-render → Visual Feedback
```

## 💾 Persistence

- **Auto-save**: All changes save to browser localStorage immediately
- **Data survives**: Page reloads, browser restarts (until cache cleared)
- **Sample data**: Pre-populated on first run (one time only)

## 🌐 Browser Support

- ✅ Chrome/Edge (90+)
- ✅ Firefox (88+)
- ✅ Safari (14+)
- ✅ Mobile browsers (iOS Safari, Chrome Android)

## 📝 Sample Data

On first launch, the app seeds with:
- **Asset**: PLM Student Registry System (IA-001)
- **Risk**: Potential SQL injection vulnerability
- **Inherent Risk**: High (Probability: 3, Severity: 4)
- **Controls**: Documented procedures, Access restriction, Backup
- **Residual Risk**: High (control effectiveness: Partially)

## 🚀 Deployment Options

### **Option 1: GitHub Pages**
```bash
git add .
git commit -m "Initial commit"
git push origin main
# Enable GitHub Pages in repository settings
```

### **Option 2: Static Hosting**
- Netlify, Vercel, Firebase Hosting
- AWS S3 + CloudFront
- Any static file server

### **Option 3: Self-Hosted**
```bash
# Docker example
docker run -v $(pwd):/usr/share/nginx/html -p 8080:80 nginx
```

## 📚 Documentation

Additional guides available in `/docs/`:
- `ARCHITECTURE.md` — System design and data model
- `USER_GUIDE.md` — Step-by-step usage instructions
- `API_REFERENCE.md` — Function documentation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License — see `LICENSE` file for details.

## 🆘 Support

- **Issues**: GitHub Issues tracker
- **Email**: support@impactlens.io
- **Documentation**: Full guides in `/docs/`

## 🎓 References

This tool aligns with:
- ISO 27005:2022 (Information security risk management)
- NIST Cybersecurity Framework (Risk Assessment)
- Information Asset Register (IAR) standards
- Data Privacy Act (DPA) compliance

---

**Built with ❤️ for security professionals.**

*Last Updated: April 2026*
