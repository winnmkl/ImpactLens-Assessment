from pathlib import Path
import re

d = "d" + "i" + "v"
open_tag = "<" + d
close_tag = "</" + d + ">"

def el(cls, content, attrs=""):
    a = f' class="{cls}"' if cls else ""
    extra = (" " + attrs.strip()) if attrs else ""
    return f"{open_tag}{a}{extra}>{content}{close_tag}"

p = Path("index.html")
t = p.read_text(encoding="utf-8")

new_nav = f"""  <nav id="main-nav">
    {el("nav-section nav-admin-only", el("nav-label", "Overview") + el("nav-item", '<span class="nav-icon">[■]</span> Dashboard', 'data-section="dashboard" onclick="showSection(\\'dashboard\\')"'))}
    {el("nav-section nav-user-only nav-infosec-only", el("nav-label", "Assets") + el("nav-item", '<span class="nav-icon">[+]</span> Add Asset', 'data-section="add" onclick="showSection(\\'add\\')"'))}
    {el("nav-section nav-infosec-only", el("nav-label", "Workflow") + el("nav-item", '<span class="nav-icon">[◷]</span> Draft Queue <span class="nav-badge" id="nav-drafts">0</span>', 'data-section="draft-queue" onclick="showSection(\\'draft-queue\\')"'))}
    {el("nav-section nav-admin-only", el("nav-label", "Approval") + el("nav-item", '<span class="nav-icon">[◎]</span> Pending Approval <span class="nav-badge" id="nav-pending" style="color:var(--warn)">0</span>', 'data-section="pending-queue" onclick="showSection(\\'pending-queue\\')"'))}
    {el("nav-section nav-admin-only", el("nav-label", "Assets") + el("nav-item", '<span class="nav-icon">[≡]</span> Asset Table <span class="nav-badge" id="nav-total">0</span>', 'data-section="register" onclick="showSection(\\'register\\')"'))}
    {el("nav-section nav-admin-only", el("nav-label", "Analysis") + el("nav-item", '<span class="nav-icon">[△]</span> Risk Register', 'data-section="risk" onclick="showSection(\\'risk\\')"') + el("nav-item", '<span class="nav-icon">[✓]</span> Control Metrics', 'data-section="controls" onclick="showSection(\\'controls\\')"') + el("nav-item", '<span class="nav-icon">[!]</span> Action Plans <span class="nav-badge" id="nav-actions" style="color:var(--warn)">0</span>', 'data-section="actions" onclick="showSection(\\'actions\\')"'))}
    {el("nav-section nav-infosec-only", el("nav-label", "Audit") + el("nav-item", '<span class="nav-icon">[⌗]</span> System Logs', 'data-section="logs" onclick="showSection(\\'logs\\')"'))}
    {el("nav-section", el("nav-label", "Documentation") + el("nav-item nav-admin-only", '<span class="nav-icon">[✎]</span> Reporting & Sign-offs', 'data-section="report" onclick="showSection(\\'report\\')"') + el("nav-item", '<span class="nav-icon">[?]</span> Risk Guidelines', 'data-section="guidelines" onclick="showSection(\\'guidelines\\')"'))}
  </nav>"""

t2, n = re.subn(r"  <nav>.*?</nav>", new_nav, t, count=1, flags=re.DOTALL)
if n != 1:
    raise SystemExit(f"nav replace failed: {n}")

t2 = t2.replace('id="sec-dashboard" class="section active"', 'id="sec-dashboard" class="section"')

t2 = t2.replace(
    '<motion id="sec-add" class="section">\n      <div class="page-header"><div><div class="page-title" id="form-title">INSERT <span>RECORD</span></div></div></motion>',
    f'<{d} id="sec-add" class="section">\n      <{d} class="page-header"><{d}><{d} class="page-title" id="form-title">INSERT <span>RECORD</span></{d}><p class="page-desc">Workflow: <span id="form-workflow-status" class="badge badge-type">Draft</span></p></{d}></{d}>',
)

# sec-add fix without motion typo in search
t2 = t2.replace(
    '<div id="sec-add" class="section">\n      <div class="page-header"><motion><div class="page-title" id="form-title">INSERT <span>RECORD</span></div></div></div>',
    f'<{d} id="sec-add" class="section">\n      <{d} class="page-header"><{d}><{d} class="page-title" id="form-title">INSERT <span>RECORD</span></{d}><p class="page-desc">Workflow: <span id="form-workflow-status" class="badge badge-type">Draft</span></p></{d}></{d}>',
)

t2 = t2.replace(
    '<motion class="card">\n        <div class="card-header">02 — Data & Classification',
    f'<{d} class="card role-locked-section" id="sec-classification">\n        <{d} class="card-header">02 — Data & Classification',
)
t2 = t2.replace(
    '<div class="card">\n        <div class="card-header">03 — Threat & Controls',
    f'<{d} class="card role-locked-section" id="sec-risk-controls">\n        <{d} class="card-header">03 — Threat & Controls',
)
t2 = t2.replace(
    '<div class="card">\n        <motion class="card-header">04 — Residual risk & action plan</motion>',
    f'<{d} class="card role-locked-section" id="sec-action-plan">\n        <{d} class="card-header">04 — Residual risk & action plan</{d}>',
)
t2 = t2.replace(
    '<div class="card">\n        <div class="card-header">04 — Residual risk & action plan</motion>',
    f'<{d} class="card role-locked-section" id="sec-action-plan">\n        <{d} class="card-header">04 — Residual risk & action plan</{d}>',
)

insert_queues = f'''
    <{d} id="sec-draft-queue" class="section">
      <{d} class="page-header"><{d}><{d} class="page-title">DRAFT <span>QUEUE</span></{d}><{d} class="page-desc">// Assets awaiting Info Sec cybersecurity profiling</{d}></{d}></{d}>
      <{d} class="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Submitted By</th><th>Actions</th></tr></thead><tbody id="draft-queue-body"></tbody></table></{d}>
    </{d}>

    <{d} id="sec-pending-queue" class="section">
      <{d} class="page-header"><{d}><{d} class="page-title">PENDING <span>APPROVAL</span></{d}><{d} class="page-desc">// CISO review queue — approve or reject Info Sec assessments</{d}></{d}></{d}>
      <{d} id="pending-queue-content"></{d}>
    </{d}>

    <{d} id="sec-logs" class="section">
      <{d} class="page-header"><{d}><{d} class="page-title">SYSTEM <span>LOGS</span></{d}><{d} class="page-desc">// Audit trail of workflow events</{d}></{d}></{d}>
      <{d} class="table-wrap"><table><thead><tr><th>Time</th><th>User</th><th>Role</th><th>Action</th><th>Asset</th><th>Details</th></tr></thead><tbody id="logs-body"></tbody></table></{d}>
    </{d}>
'''

t2 = t2.replace('    <div id="sec-register" class="section">', insert_queues + '\n    <div id="sec-register" class="section">')

t2 = t2.replace(
    '<button class="btn btn-primary" onclick="saveAssetToDB()">Save Asset →</button>',
    '<button class="btn btn-primary" id="btn-save-asset" onclick="saveAssetToDB()">Save Asset →</button>',
)

t2 = t2.replace(
    '  </main>\n</div>\n\n<div id="notification"',
    f'  </main>\n</div>\n</{d}>\n\n<div id="notification"',
)

# Fix sec-add header if not yet patched
if 'form-workflow-status' not in t2:
    t2 = t2.replace(
        '<div id="sec-add" class="section">\n      <div class="page-header"><div><motion class="page-title" id="form-title">INSERT <span>RECORD</span></div></motion></motion>',
        f'<{d} id="sec-add" class="section">\n      <{d} class="page-header"><{d}><{d} class="page-title" id="form-title">INSERT <span>RECORD</span></{d}><p class="page-desc">Workflow: <span id="form-workflow-status" class="badge badge-type">Draft</span></p></{d}></{d}>',
    )
    t2 = t2.replace(
        '<div id="sec-add" class="section">\n      <div class="page-header"><div><motion class="page-title" id="form-title">INSERT <span>RECORD</span></motion></motion></motion>',
        f'<{d} id="sec-add" class="section">\n      <{d} class="page-header"><{d}><{d} class="page-title" id="form-title">INSERT <span>RECORD</span></{d}><p class="page-desc">Workflow: <span id="form-workflow-status" class="badge badge-type">Draft</span></p></{d}></{d}>',
    )

# classification card
if 'id="sec-classification"' not in t2:
    t2 = t2.replace(
        '\n      <div class="card">\n        <div class="card-header">02 — Data & Classification',
        f'\n      <{d} class="card role-locked-section" id="sec-classification">\n        <{d} class="card-header">02 — Data & Classification',
        1,
    )
if 'id="sec-risk-controls"' not in t2:
    t2 = t2.replace(
        '\n      <div class="card">\n        <div class="card-header">03 — Threat & Controls',
        f'\n      <{d} class="card role-locked-section" id="sec-risk-controls">\n        <{d} class="card-header">03 — Threat & Controls',
        1,
    )
if 'id="sec-action-plan"' not in t2:
    t2 = t2.replace(
        '\n      <div class="card">\n        <div class="card-header">04 — Residual risk & action plan',
        f'\n      <{d} class="card role-locked-section" id="sec-action-plan">\n        <{d} class="card-header">04 — Residual risk & action plan',
        1,
    )

p.write_text(t2, encoding="utf-8")
print("index.html patched OK")
