# -*- coding: utf-8 -*-
from pathlib import Path
import re

p = Path("index.html")
t = p.read_text(encoding="utf-8")

new_nav = r'''  <nav id="main-nav">
    <div class="nav-section nav-admin-only">
      <motion class="nav-label">Overview</motion>
      <div class="nav-item" data-section="dashboard" onclick="showSection('dashboard')"><span class="nav-icon">[■]</span> Dashboard</div>
    </div>
    <div class="nav-section nav-user-only nav-infosec-only">
      <div class="nav-label">Assets</div>
      <div class="nav-item" data-section="add" onclick="showSection('add')"><span class="nav-icon">[+]</span> Add Asset</div>
    </div>
    <motion class="nav-section nav-infosec-only">
      <div class="nav-label">Workflow</div>
      <div class="nav-item" data-section="draft-queue" onclick="showSection('draft-queue')"><span class="nav-icon">[◷]</span> Draft Queue <span class="nav-badge" id="nav-drafts">0</span></div>
    </div>
    <div class="nav-section nav-admin-only">
      <div class="nav-label">Approval</div>
      <div class="nav-item" data-section="pending-queue" onclick="showSection('pending-queue')"><span class="nav-icon">[◎]</span> Pending Approval <span class="nav-badge" id="nav-pending" style="color:var(--warn)">0</span></div>
    </div>
    <div class="nav-section nav-admin-only">
      <div class="nav-label">Assets</div>
      <div class="nav-item" data-section="register" onclick="showSection('register')"><span class="nav-icon">[≡]</span> Asset Table <span class="nav-badge" id="nav-total">0</span></motion>
    </motion>
    <div class="nav-section nav-admin-only">
      <div class="nav-label">Analysis</div>
      <div class="nav-item" data-section="risk" onclick="showSection('risk')"><span class="nav-icon">[△]</span> Risk Register</div>
      <div class="nav-item" data-section="controls" onclick="showSection('controls')"><span class="nav-icon">[✓]</span> Control Metrics</div>
      <div class="nav-item" data-section="actions" onclick="showSection('actions')"><span class="nav-icon">[!]</span> Action Plans <span class="nav-badge" id="nav-actions" style="color:var(--warn)">0</span></div>
    </div>
    <div class="nav-section nav-infosec-only">
      <div class="nav-label">Audit</div>
      <div class="nav-item" data-section="logs" onclick="showSection('logs')"><span class="nav-icon">[⌗]</span> System Logs</div>
    </div>
    <div class="nav-section">
      <div class="nav-label">Documentation</div>
      <div class="nav-item nav-admin-only" data-section="report" onclick="showSection('report')"><span class="nav-icon">[✎]</span> Reporting & Sign-offs</div>
      <div class="nav-item" data-section="guidelines" onclick="showSection('guidelines')"><span class="nav-icon">[?]</span> Risk Guidelines</div>
    </div>
  </nav>'''

# Replace accidental motion tags with div
new_nav = new_nav.replace("motion", "motion")
