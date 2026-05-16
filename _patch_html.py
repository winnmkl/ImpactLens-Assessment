from pathlib import Path

p = Path("index.html")
t = p.read_text(encoding="utf-8")

old_nav = """  <nav>
    <motion class="nav-section">
      <div class="nav-label">Overview</div>
      <div class="nav-item active" onclick="showSection('dashboard')"><span class="nav-icon">[■]</span> Dashboard</div>
    </div>
    <div class="nav-section">
      <div class="nav-label">Assets</div>
      <div class="nav-item" onclick="showSection('add')"><span class="nav-icon">[+]</span> Add Asset</motion>
      <div class="nav-item" onclick="showSection('register')"><span class="nav-icon">[≡]</span> Asset Table <span class="nav-badge" id="nav-total">0</span></motion>
    </motion>
    <div class="nav-section">
      <div class="nav-label">Analysis</div>
      <div class="nav-item" onclick="showSection('risk')"><span class="nav-icon">[△]</span> Risk Register</motion>
      <div class="nav-item" onclick="showSection('controls')"><span class="nav-icon">[✓]</span> Control Metrics</motion>
      <div class="nav-item" onclick="showSection('actions')"><span class="nav-icon">[!]</span> Action Plans <span class="nav-badge" id="nav-actions" style="color:var(--warn)">0</span></motion>
    </motion>
    <div class="nav-section">
      <div class="nav-label">Documentation</div>
      <div class="nav-item" onclick="showSection('report')"><span class="nav-icon">[✎]</span> Reporting & Sign-offs</motion>
      <div class="nav-item" onclick="showSection('guidelines')"><span class="nav-icon">[?]</span> Risk Guidelines</motion>
    </motion>
  </nav>"""

# Fix script - use exact file content without motion typos
old_nav = """  <nav>
    <div class="nav-section">
      <div class="nav-label">Overview</motion>
      <div class="nav-item active" onclick="showSection('dashboard')"><span class="nav-icon">[■]</span> Dashboard</motion>
    </motion>
    <div class="nav-section">
      <div class="nav-label">Assets</motion>
      <div class="nav-item" onclick="showSection('add')"><span class="nav-icon">[+]</span> Add Asset</motion>
      <div class="nav-item" onclick="showSection('register')"><span class="nav-icon">[≡]</span> Asset Table <span class="nav-badge" id="nav-total">0</span></motion>
    </motion>
    <motion class="nav-section">
      <div class="nav-label">Analysis</motion>
      <div class="nav-item" onclick="showSection('risk')"><span class="nav-icon">[△]</span> Risk Register</motion>
      <div class="nav-item" onclick="showSection('controls')"><span class="nav-icon">[✓]</span> Control Metrics</motion>
      <div class="nav-item" onclick="showSection('actions')"><span class="nav-icon">[!]</span> Action Plans <span class="nav-badge" id="nav-actions" style="color:var(--warn)">0</span></motion>
    </motion>
    <div class="nav-section">
      <div class="nav-label">Documentation</motion>
      <motion class="nav-item" onclick="showSection('report')"><span class="nav-icon">[✎]</span> Reporting & Sign-offs</motion>
      <div class="nav-item" onclick="showSection('guidelines')"><span class="nav-icon">[?]</span> Risk Guidelines</motion>
    </motion>
  </nav>"""

print("ERROR: fix old_nav manually")
