#!/usr/bin/env python3
"""Generate an interactive HTML viewer for all app catalog entries."""

import json
import os
import yaml

APPS_DIR = os.path.join(os.path.dirname(__file__), '..', 'apps')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'output')


def load_apps():
    apps = []
    for fname in sorted(os.listdir(APPS_DIR)):
        if not fname.endswith('.yaml'):
            continue
        with open(os.path.join(APPS_DIR, fname)) as f:
            data = yaml.safe_load(f)
            if data:
                data['_filename'] = fname
                apps.append(data)
    return apps


def extract_iocs(app):
    """Flatten IOCs into a simple dict for the JS side."""
    iocs = app.get('iocs', {})
    result = {
        'network_status': '',
        'host_status': '',
        'hostname_patterns': [],
        'keyword_patterns': [],
        'host_paths': [],
        'bundle_ids': [],
        'process_names': [],
    }
    net = iocs.get('network', {})
    if net:
        result['network_status'] = net.get('status', '')
        for hp in net.get('hostname_patterns', []):
            result['hostname_patterns'].append({
                'pattern': hp.get('pattern', ''),
                'match': hp.get('match', ''),
                'role': hp.get('role', ''),
            })
        for kp in net.get('keyword_patterns', []):
            result['keyword_patterns'].append({
                'pattern': kp.get('pattern', ''),
                'match': kp.get('match', ''),
            })
    host = iocs.get('host', {})
    if host:
        result['host_status'] = host.get('status', '')
        result['host_paths'] = host.get('paths', [])
        result['bundle_ids'] = host.get('bundle_ids', [])
        result['process_names'] = host.get('process_names', [])
    return result


def build_app_record(app):
    ioc_data = extract_iocs(app)
    return {
        'id': app.get('id', ''),
        'name': app.get('name', ''),
        'category': app.get('category', ''),
        'product_shape': app.get('product_shape', []),
        'product_type': app.get('product_type', []),
        'severity': app.get('severity', ''),
        'priority_score': app.get('priority_score', 0),
        'notes': app.get('notes', ''),
        'references': app.get('references', []),
        'iocs': ioc_data,
        '_filename': app.get('_filename', ''),
    }


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>App Catalog Viewer</title>
<style>
:root {
  --bg: #0f1117;
  --surface: #181a20;
  --surface2: #23262f;
  --border: #2d3039;
  --text: #e4e4e7;
  --text2: #a1a1aa;
  --accent: #6366f1;
  --accent2: #818cf8;
  --critical: #ef4444;
  --high: #f97316;
  --medium: #eab308;
  --low: #22c55e;
  --draft: #64748b;
  --reviewed: #22c55e;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: var(--bg); color: var(--text); min-height: 100vh; }

.header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 24px; position: sticky; top: 0; z-index: 100; }
.header h1 { font-size: 20px; font-weight: 600; margin-bottom: 8px; }
.header-stats { display: flex; gap: 16px; font-size: 13px; color: var(--text2); flex-wrap: wrap; }
.header-stats span { background: var(--surface2); padding: 2px 10px; border-radius: 4px; }
.header-stats .count { color: var(--accent2); font-weight: 600; }

.toolbar { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 24px; position: sticky; top: 72px; z-index: 99; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.search-box { flex: 1; min-width: 200px; padding: 8px 12px; background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 14px; outline: none; }
.search-box:focus { border-color: var(--accent); }
.search-box::placeholder { color: var(--text2); }

select.filter-select { padding: 8px 12px; background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 13px; cursor: pointer; outline: none; }
select.filter-select:focus { border-color: var(--accent); }

.btn { padding: 8px 14px; border: 1px solid var(--border); border-radius: 6px; background: var(--surface2); color: var(--text); font-size: 13px; cursor: pointer; transition: all 0.15s; white-space: nowrap; }
.btn:hover { background: var(--accent); border-color: var(--accent); color: #fff; }
.btn.active { background: var(--accent); border-color: var(--accent); color: #fff; }
.btn-danger { border-color: var(--critical); color: var(--critical); }
.btn-danger:hover { background: var(--critical); color: #fff; }

.selection-bar { background: var(--accent); color: #fff; padding: 8px 24px; font-size: 13px; display: none; align-items: center; gap: 12px; position: sticky; top: 120px; z-index: 98; }
.selection-bar.visible { display: flex; }

.content { padding: 16px 24px; }

table { width: 100%; border-collapse: collapse; font-size: 13px; }
thead { position: sticky; top: 168px; z-index: 50; }
th { background: var(--surface2); padding: 10px 12px; text-align: left; border-bottom: 2px solid var(--border); font-weight: 600; cursor: pointer; user-select: none; white-space: nowrap; }
th:hover { color: var(--accent2); }
th .sort-arrow { margin-left: 4px; font-size: 10px; }
td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:hover td { background: var(--surface); }
tr.selected td { background: rgba(99,102,241,0.12); }

.cb-cell { width: 36px; text-align: center; }
input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer; }

.sev-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
.sev-critical { background: rgba(239,68,68,0.15); color: var(--critical); }
.sev-high { background: rgba(249,115,22,0.15); color: var(--high); }
.sev-medium { background: rgba(234,179,8,0.15); color: var(--medium); }
.sev-low { background: rgba(34,197,94,0.15); color: var(--low); }

.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; vertical-align: middle; }
.status-reviewed { background: var(--reviewed); }
.status-draft { background: var(--draft); }

.tag { display: inline-block; padding: 1px 6px; margin: 1px 2px; border-radius: 3px; font-size: 11px; background: var(--surface2); border: 1px solid var(--border); }
.tag-shape { border-color: rgba(99,102,241,0.3); color: var(--accent2); }
.tag-type { border-color: rgba(234,179,8,0.3); color: var(--medium); }

.ioc-cell { max-width: 320px; }
.ioc-patterns { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 11px; line-height: 1.6; color: var(--text2); }
.ioc-patterns .hostname { color: var(--accent2); }
.ioc-patterns .path { color: #94a3b8; }
.ioc-copy-btn { display: inline-block; margin-left: 4px; padding: 0 4px; font-size: 10px; color: var(--text2); cursor: pointer; border: 1px solid var(--border); border-radius: 3px; background: transparent; }
.ioc-copy-btn:hover { background: var(--accent); color: #fff; border-color: var(--accent); }

.expand-btn { cursor: pointer; color: var(--accent2); font-size: 11px; border: none; background: none; padding: 2px 4px; }
.expand-btn:hover { text-decoration: underline; }

.detail-row td { background: var(--surface) !important; padding: 12px 24px; }
.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; font-size: 12px; }
.detail-section h4 { font-size: 12px; font-weight: 600; margin-bottom: 6px; color: var(--accent2); }
.detail-section pre { background: var(--surface2); padding: 8px; border-radius: 4px; overflow-x: auto; font-size: 11px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }
.detail-section a { color: var(--accent2); text-decoration: none; }
.detail-section a:hover { text-decoration: underline; }

.modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 200; justify-content: center; align-items: center; }
.modal-overlay.visible { display: flex; }
.modal { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; }
.modal h3 { margin-bottom: 12px; }
.modal pre { background: var(--surface2); padding: 12px; border-radius: 6px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 60vh; }
.modal .btn { margin-top: 12px; }

.toast { position: fixed; bottom: 24px; right: 24px; background: var(--accent); color: #fff; padding: 10px 20px; border-radius: 8px; font-size: 13px; z-index: 300; opacity: 0; transition: opacity 0.3s; pointer-events: none; }
.toast.show { opacity: 1; }

.no-results { text-align: center; padding: 48px; color: var(--text2); font-size: 16px; }

@media (max-width: 900px) {
  .toolbar { flex-direction: column; }
  .detail-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<div class="header">
  <h1>App Catalog Viewer</h1>
  <div class="header-stats" id="headerStats"></div>
</div>

<div class="toolbar" id="toolbar">
  <input type="text" class="search-box" id="searchBox" placeholder="Search by name, ID, category, IOC pattern...">
  <select class="filter-select" id="filterCategory"><option value="">All Categories</option></select>
  <select class="filter-select" id="filterSeverity"><option value="">All Severities</option></select>
  <select class="filter-select" id="filterShape"><option value="">All Shapes</option></select>
  <select class="filter-select" id="filterStatus"><option value="">All IOC Status</option></select>
  <button class="btn" id="btnSelectAll">Select All Visible</button>
  <button class="btn" id="btnClearSelection">Clear Selection</button>
  <button class="btn" id="btnExportCSV">Export CSV</button>
  <button class="btn" id="btnExportJSON">Export JSON</button>
  <button class="btn" id="btnCopyIOCs">Copy IOCs</button>
  <button class="btn" id="btnExpandAll">Expand All</button>
</div>

<div class="selection-bar" id="selectionBar">
  <span id="selectionCount">0 selected</span>
  <button class="btn" onclick="copySelectedIOCs('network')">Copy Network IOCs</button>
  <button class="btn" onclick="copySelectedIOCs('host')">Copy Host IOCs</button>
  <button class="btn" onclick="copySelectedIOCs('all')">Copy All IOCs</button>
  <button class="btn" onclick="exportSelected('csv')">Export Selected CSV</button>
  <button class="btn" onclick="exportSelected('json')">Export Selected JSON</button>
  <button class="btn btn-danger" onclick="clearSelection()">Clear</button>
</div>

<div class="content">
  <table id="appTable">
    <thead>
      <tr>
        <th class="cb-cell"><input type="checkbox" id="selectAllCb" title="Select all visible"></th>
        <th data-sort="name">Name <span class="sort-arrow"></span></th>
        <th data-sort="category">Category <span class="sort-arrow"></span></th>
        <th data-sort="severity">Severity <span class="sort-arrow"></span></th>
        <th data-sort="priority_score">Priority <span class="sort-arrow"></span></th>
        <th>Shape</th>
        <th>Type</th>
        <th>Network IOCs</th>
        <th>Host IOCs</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody id="appTableBody"></tbody>
  </table>
  <div class="no-results" id="noResults" style="display:none;">No matching apps found.</div>
</div>

<div class="modal-overlay" id="modalOverlay">
  <div class="modal">
    <h3 id="modalTitle"></h3>
    <pre id="modalContent"></pre>
    <button class="btn" onclick="copyModalContent()">Copy to Clipboard</button>
    <button class="btn" onclick="closeModal()">Close</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const APP_DATA = __APP_DATA__;

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
let sortKey = 'name';
let sortAsc = true;
let selectedIds = new Set();
let expandedIds = new Set();
let allExpanded = false;
let filteredApps = [...APP_DATA];

function init() {
  populateFilters();
  renderStats();
  renderTable();
  bindEvents();
}

function populateFilters() {
  const cats = [...new Set(APP_DATA.map(a => a.category))].filter(Boolean).sort();
  const sevs = ['critical', 'high', 'medium', 'low'];
  const shapes = [...new Set(APP_DATA.flatMap(a => a.product_shape))].filter(Boolean).sort();
  const statuses = ['reviewed', 'draft'];

  const catSel = document.getElementById('filterCategory');
  cats.forEach(c => { const o = document.createElement('option'); o.value = c; o.textContent = c; catSel.appendChild(o); });

  const sevSel = document.getElementById('filterSeverity');
  sevs.forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = s.toUpperCase(); sevSel.appendChild(o); });

  const shapeSel = document.getElementById('filterShape');
  shapes.forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = s; shapeSel.appendChild(o); });

  const statusSel = document.getElementById('filterStatus');
  statuses.forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = s.charAt(0).toUpperCase() + s.slice(1); statusSel.appendChild(o); });
}

function renderStats() {
  const total = APP_DATA.length;
  const cats = new Set(APP_DATA.map(a => a.category)).size;
  const reviewed = APP_DATA.filter(a => a.iocs.network_status === 'reviewed' || a.iocs.host_status === 'reviewed').length;
  const draft = APP_DATA.filter(a => (a.iocs.network_status === 'draft' || a.iocs.host_status === 'draft') && a.iocs.network_status !== 'reviewed' && a.iocs.host_status !== 'reviewed').length;
  const crit = APP_DATA.filter(a => a.severity === 'critical').length;
  const high = APP_DATA.filter(a => a.severity === 'high').length;
  const el = document.getElementById('headerStats');
  el.innerHTML = `
    <span>Total: <span class="count">${total}</span></span>
    <span>Categories: <span class="count">${cats}</span></span>
    <span>Reviewed: <span class="count">${reviewed}</span></span>
    <span>Draft: <span class="count">${draft}</span></span>
    <span>Critical: <span class="count">${crit}</span></span>
    <span>High: <span class="count">${high}</span></span>
    <span>Showing: <span class="count" id="showingCount">${filteredApps.length}</span></span>
  `;
}

function getFilteredApps() {
  const q = document.getElementById('searchBox').value.toLowerCase().trim();
  const cat = document.getElementById('filterCategory').value;
  const sev = document.getElementById('filterSeverity').value;
  const shape = document.getElementById('filterShape').value;
  const status = document.getElementById('filterStatus').value;

  return APP_DATA.filter(a => {
    if (cat && a.category !== cat) return false;
    if (sev && a.severity !== sev) return false;
    if (shape && !a.product_shape.includes(shape)) return false;
    if (status) {
      const hasStatus = a.iocs.network_status === status || a.iocs.host_status === status;
      if (!hasStatus) return false;
    }
    if (q) {
      const searchable = [
        a.id, a.name, a.category, a.severity,
        ...a.product_shape, ...a.product_type,
        a.notes || '',
        ...a.iocs.hostname_patterns.map(h => h.pattern),
        ...a.iocs.keyword_patterns.map(k => k.pattern),
        ...a.iocs.host_paths,
        ...a.iocs.bundle_ids,
        ...a.iocs.process_names,
      ].join(' ').toLowerCase();
      if (!searchable.includes(q)) return false;
    }
    return true;
  });
}

function sortApps(apps) {
  return apps.sort((a, b) => {
    let va, vb;
    if (sortKey === 'severity') {
      va = SEV_ORDER[a.severity] ?? 9;
      vb = SEV_ORDER[b.severity] ?? 9;
    } else if (sortKey === 'priority_score') {
      va = a.priority_score || 0;
      vb = b.priority_score || 0;
    } else {
      va = (a[sortKey] || '').toString().toLowerCase();
      vb = (b[sortKey] || '').toString().toLowerCase();
    }
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  });
}

function renderTable() {
  filteredApps = sortApps(getFilteredApps());
  const tbody = document.getElementById('appTableBody');
  tbody.innerHTML = '';
  const showCount = document.getElementById('showingCount');
  if (showCount) showCount.textContent = filteredApps.length;

  if (filteredApps.length === 0) {
    document.getElementById('noResults').style.display = 'block';
  } else {
    document.getElementById('noResults').style.display = 'none';
  }

  filteredApps.forEach(app => {
    const tr = document.createElement('tr');
    tr.dataset.id = app.id;
    if (selectedIds.has(app.id)) tr.classList.add('selected');

    const netPatterns = app.iocs.hostname_patterns.map(h =>
      `<span class="hostname">${esc(h.pattern)}</span> <span style="color:#64748b">(${esc(h.match)}, ${esc(h.role)})</span>`
    ).join('<br>');
    const hostPaths = app.iocs.host_paths.slice(0, 3).map(p => `<span class="path">${esc(p)}</span>`).join('<br>');
    const moreHost = app.iocs.host_paths.length > 3 ? `<br><span style="color:var(--text2)">+${app.iocs.host_paths.length - 3} more</span>` : '';
    const bundleStr = app.iocs.bundle_ids.length ? '<br>' + app.iocs.bundle_ids.map(b => `<span class="path">${esc(b)}</span>`).join(', ') : '';

    tr.innerHTML = `
      <td class="cb-cell"><input type="checkbox" class="row-cb" data-id="${esc(app.id)}" ${selectedIds.has(app.id) ? 'checked' : ''}></td>
      <td><strong>${esc(app.name)}</strong><br><span style="color:var(--text2);font-size:11px">${esc(app.id)}</span></td>
      <td>${esc(app.category)}</td>
      <td><span class="sev-badge sev-${app.severity}">${esc(app.severity)}</span></td>
      <td>${app.priority_score || '-'}</td>
      <td>${app.product_shape.map(s => `<span class="tag tag-shape">${esc(s)}</span>`).join(' ')}</td>
      <td>${app.product_type.map(t => `<span class="tag tag-type">${esc(t)}</span>`).join(' ')}</td>
      <td class="ioc-cell">
        <span class="status-dot status-${app.iocs.network_status || 'draft'}"></span>${esc(app.iocs.network_status || 'none')}
        ${netPatterns ? '<button class="ioc-copy-btn" onclick="copyAppIOC(event,\'' + app.id + '\',\'network\')" title="Copy network IOCs">copy</button>' : ''}
        <div class="ioc-patterns">${netPatterns || '<span style="color:var(--draft)">-</span>'}</div>
      </td>
      <td class="ioc-cell">
        <span class="status-dot status-${app.iocs.host_status || 'draft'}"></span>${esc(app.iocs.host_status || 'none')}
        ${hostPaths ? '<button class="ioc-copy-btn" onclick="copyAppIOC(event,\'' + app.id + '\',\'host\')" title="Copy host IOCs">copy</button>' : ''}
        <div class="ioc-patterns">${hostPaths}${moreHost}${bundleStr || ''}</div>
      </td>
      <td><button class="expand-btn" onclick="toggleDetail('${esc(app.id)}')">detail</button></td>
    `;
    tbody.appendChild(tr);

    if (expandedIds.has(app.id) || allExpanded) {
      const detailTr = buildDetailRow(app);
      tbody.appendChild(detailTr);
    }
  });
  updateSelectionBar();
}

function buildDetailRow(app) {
  const tr = document.createElement('tr');
  tr.classList.add('detail-row');
  tr.dataset.detailFor = app.id;

  const allHostPaths = app.iocs.host_paths.map(p => esc(p)).join('\n');
  const allNetPatterns = app.iocs.hostname_patterns.map(h => `${h.pattern} (${h.match}, ${h.role})`).join('\n');
  const allKeywords = app.iocs.keyword_patterns.map(k => `${k.pattern} (${k.match})`).join('\n');
  const refs = (app.references || []).map(r => `<a href="${esc(r.url)}" target="_blank">${esc(r.kind || 'link')}</a>: ${esc(r.summary || '')}`).join('<br>');

  tr.innerHTML = `<td colspan="10"><div class="detail-grid">
    <div class="detail-section">
      <h4>Network IOCs</h4>
      <pre>${allNetPatterns || 'None'}</pre>
      <h4 style="margin-top:8px">Keyword Patterns</h4>
      <pre>${allKeywords || 'None'}</pre>
    </div>
    <div class="detail-section">
      <h4>Host Paths</h4>
      <pre>${allHostPaths || 'None'}</pre>
      <h4 style="margin-top:8px">Bundle IDs</h4>
      <pre>${app.iocs.bundle_ids.join('\n') || 'None'}</pre>
      <h4 style="margin-top:8px">Process Names</h4>
      <pre>${app.iocs.process_names.join('\n') || 'None'}</pre>
    </div>
    <div class="detail-section" style="grid-column:1/-1">
      <h4>Notes</h4>
      <pre>${esc(app.notes || 'None')}</pre>
      ${refs ? '<h4 style="margin-top:8px">References</h4><div style="font-size:12px;line-height:1.8">' + refs + '</div>' : ''}
    </div>
  </div></td>`;
  return tr;
}

function toggleDetail(id) {
  if (expandedIds.has(id)) {
    expandedIds.delete(id);
  } else {
    expandedIds.add(id);
  }
  renderTable();
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function bindEvents() {
  document.getElementById('searchBox').addEventListener('input', debounce(renderTable, 200));
  document.getElementById('filterCategory').addEventListener('change', renderTable);
  document.getElementById('filterSeverity').addEventListener('change', renderTable);
  document.getElementById('filterShape').addEventListener('change', renderTable);
  document.getElementById('filterStatus').addEventListener('change', renderTable);

  document.getElementById('selectAllCb').addEventListener('change', function() {
    if (this.checked) {
      filteredApps.forEach(a => selectedIds.add(a.id));
    } else {
      filteredApps.forEach(a => selectedIds.delete(a.id));
    }
    renderTable();
  });

  document.getElementById('appTableBody').addEventListener('change', function(e) {
    if (e.target.classList.contains('row-cb')) {
      const id = e.target.dataset.id;
      if (e.target.checked) selectedIds.add(id); else selectedIds.delete(id);
      e.target.closest('tr').classList.toggle('selected', e.target.checked);
      updateSelectionBar();
    }
  });

  document.getElementById('btnSelectAll').addEventListener('click', () => {
    filteredApps.forEach(a => selectedIds.add(a.id));
    renderTable();
  });
  document.getElementById('btnClearSelection').addEventListener('click', clearSelection);

  document.getElementById('btnExportCSV').addEventListener('click', () => exportFiltered('csv'));
  document.getElementById('btnExportJSON').addEventListener('click', () => exportFiltered('json'));
  document.getElementById('btnCopyIOCs').addEventListener('click', () => {
    const apps = filteredApps.length ? filteredApps : APP_DATA;
    const text = buildIOCText(apps, 'all');
    copyToClipboard(text);
    showToast(`Copied IOCs for ${apps.length} apps`);
  });

  document.getElementById('btnExpandAll').addEventListener('click', () => {
    allExpanded = !allExpanded;
    if (!allExpanded) expandedIds.clear();
    document.getElementById('btnExpandAll').textContent = allExpanded ? 'Collapse All' : 'Expand All';
    renderTable();
  });

  document.querySelectorAll('th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (sortKey === key) sortAsc = !sortAsc; else { sortKey = key; sortAsc = true; }
      document.querySelectorAll('th .sort-arrow').forEach(s => s.textContent = '');
      th.querySelector('.sort-arrow').textContent = sortAsc ? '\u25B2' : '\u25BC';
      renderTable();
    });
  });

  document.getElementById('modalOverlay').addEventListener('click', function(e) {
    if (e.target === this) closeModal();
  });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
}

function updateSelectionBar() {
  const bar = document.getElementById('selectionBar');
  const count = selectedIds.size;
  document.getElementById('selectionCount').textContent = `${count} selected`;
  bar.classList.toggle('visible', count > 0);
}

function clearSelection() {
  selectedIds.clear();
  renderTable();
}

function getSelectedApps() {
  return APP_DATA.filter(a => selectedIds.has(a.id));
}

function buildIOCText(apps, type) {
  const lines = [];
  apps.forEach(app => {
    const parts = [];
    if (type === 'network' || type === 'all') {
      app.iocs.hostname_patterns.forEach(h => parts.push(h.pattern));
      app.iocs.keyword_patterns.forEach(k => parts.push(k.pattern));
    }
    if (type === 'host' || type === 'all') {
      app.iocs.host_paths.forEach(p => parts.push(p));
      app.iocs.bundle_ids.forEach(b => parts.push(b));
      app.iocs.process_names.forEach(p => parts.push(p));
    }
    if (parts.length) {
      lines.push(`# ${app.name} (${app.id})`);
      parts.forEach(p => lines.push(p));
      lines.push('');
    }
  });
  return lines.join('\n');
}

function copySelectedIOCs(type) {
  const apps = getSelectedApps();
  if (!apps.length) { showToast('No apps selected'); return; }
  const text = buildIOCText(apps, type);
  copyToClipboard(text);
  showToast(`Copied ${type} IOCs for ${apps.length} apps`);
}

function copyAppIOC(event, id, type) {
  event.stopPropagation();
  const app = APP_DATA.find(a => a.id === id);
  if (!app) return;
  const text = buildIOCText([app], type);
  copyToClipboard(text);
  showToast(`Copied ${type} IOCs for ${app.name}`);
}

function exportFiltered(format) {
  const apps = filteredApps.length ? filteredApps : APP_DATA;
  doExport(apps, format, 'catalog_filtered');
}

function exportSelected(format) {
  const apps = getSelectedApps();
  if (!apps.length) { showToast('No apps selected'); return; }
  doExport(apps, format, 'catalog_selected');
}

function doExport(apps, format, prefix) {
  if (format === 'json') {
    const blob = new Blob([JSON.stringify(apps, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `${prefix}.json`);
  } else {
    const headers = ['id','name','category','severity','priority_score','product_shape','product_type','network_status','hostname_patterns','host_status','host_paths','bundle_ids','process_names','notes'];
    const rows = apps.map(a => [
      a.id, a.name, a.category, a.severity, a.priority_score,
      a.product_shape.join(';'), a.product_type.join(';'),
      a.iocs.network_status,
      a.iocs.hostname_patterns.map(h => h.pattern).join(';'),
      a.iocs.host_status,
      a.iocs.host_paths.join(';'),
      a.iocs.bundle_ids.join(';'),
      a.iocs.process_names.join(';'),
      (a.notes || '').replace(/"/g, '""')
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    downloadBlob(blob, `${prefix}.csv`);
  }
  showToast(`Exported ${apps.length} apps as ${format.toUpperCase()}`);
}

function downloadBlob(blob, name) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}

function openModal(title, content) {
  document.getElementById('modalTitle').textContent = title;
  document.getElementById('modalContent').textContent = content;
  document.getElementById('modalOverlay').classList.add('visible');
}
function closeModal() { document.getElementById('modalOverlay').classList.remove('visible'); }
function copyModalContent() {
  copyToClipboard(document.getElementById('modalContent').textContent);
  showToast('Copied to clipboard');
}

function debounce(fn, ms) { let t; return function(...a) { clearTimeout(t); t = setTimeout(() => fn.apply(this, a), ms); }; }

init();
</script>
</body>
</html>
"""


def generate():
    apps = load_apps()
    records = [build_app_record(a) for a in apps]
    app_json = json.dumps(records, ensure_ascii=False)
    html = HTML_TEMPLATE.replace('__APP_DATA__', app_json)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, 'app_catalog_viewer.html')
    with open(out_path, 'w') as f:
        f.write(html)
    print(f'Generated {out_path} with {len(records)} apps')


if __name__ == '__main__':
    generate()
