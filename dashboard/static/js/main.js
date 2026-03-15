/* NetWatch — Main JavaScript */

// ── WebSocket connection ─────────────────────────────────────
const nwSocket = io({ transports: ['websocket', 'polling'] });

nwSocket.on('connect', () => {
  document.getElementById('connection-status').className = 'status-dot online';
  document.getElementById('connection-text').textContent = 'Connected';
});
nwSocket.on('disconnect', () => {
  document.getElementById('connection-status').className = 'status-dot offline';
  document.getElementById('connection-text').textContent = 'Disconnected';
});
nwSocket.on('init_data', data => {
  updateTopBar(data.stats);
  updateAlertBadge(data.stats.unacked_alerts || 0);
});
nwSocket.on('alert_event', alert => {
  showToast(`🚨 ${alert.title}`, alert.severity);
  updateAlertBadge('+1');
});
nwSocket.on('device_event', () => refreshTopBar());
nwSocket.on('scan_complete', data => {
  const el = document.getElementById('last-scan');
  if (el) el.textContent = `Last scan: just now (${data.device_count} devices)`;
});

// ── Top bar updates ──────────────────────────────────────────
function updateTopBar(stats) {
  const el = document.getElementById('active-device-count');
  if (el) el.textContent = `${stats.active_devices || 0} active devices`;
  updateAlertBadge(stats.unacked_alerts || 0);
}

function updateAlertBadge(count) {
  const badge = document.getElementById('nav-alert-badge');
  const chip  = document.getElementById('unacked-alert-count');
  const n = typeof count === 'string' ? parseInt(chip?.textContent) + 1 : count;
  if (badge) { badge.textContent = n; badge.classList.toggle('hidden', n === 0); }
  if (chip)  { chip.textContent = `${n} alert${n!==1?'s':''}`; chip.classList.toggle('hidden', n === 0); }
}

async function refreshTopBar() {
  try {
    const res  = await fetch('/api/status');
    const data = await res.json();
    updateTopBar(data.stats);
  } catch(e) {}
}
refreshTopBar();
setInterval(refreshTopBar, 30000);

// ── Utility functions ────────────────────────────────────────
function timeAgo(isoString) {
  if (!isoString) return '—';
  const diff = (Date.now() - new Date(isoString + 'Z').getTime()) / 1000;
  if (diff < 60)    return `${Math.floor(diff)}s ago`;
  if (diff < 3600)  return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B','KB','MB','GB'];
  let i = 0, v = bytes;
  while (v >= 1024 && i < units.length-1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function severityClass(s) {
  return {CRITICAL:'text-red', HIGH:'text-red', MEDIUM:'text-yellow', LOW:'text-accent'}[s] || '';
}

// ── Toast notifications ──────────────────────────────────────
function showToast(msg, severity='INFO') {
  const colors = {CRITICAL:'#f85149',HIGH:'#e3954b',MEDIUM:'#d29922',LOW:'#58a6ff',INFO:'#3fb950'};
  const toast  = document.createElement('div');
  toast.style.cssText = `
    position:fixed;bottom:24px;right:24px;background:#21262d;border:1px solid ${colors[severity]||'#30363d'};
    border-left:4px solid ${colors[severity]||'#30363d'};color:#e6edf3;padding:12px 18px;
    border-radius:8px;font-size:13px;z-index:9999;max-width:360px;
    animation:slideIn .3s ease;box-shadow:0 4px 20px rgba(0,0,0,.5);
  `;
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 5000);
}

// ── Chart helpers ────────────────────────────────────────────
const _charts = {};
function renderPieChart(canvasId, dataObj) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  if (_charts[canvasId]) _charts[canvasId].destroy();
  const labels = Object.keys(dataObj);
  const values = Object.values(dataObj);
  const colors = ['#58a6ff','#3fb950','#d29922','#f85149','#bc8cff','#e3954b','#39d353','#ff7b72'];
  _charts[canvasId] = new Chart(canvas.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: colors.slice(0, labels.length), borderWidth: 1, borderColor: '#21262d' }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'right', labels: { color: '#8b949e', boxWidth: 12, padding: 12 } } }
    }
  });
}

function renderLineChart(canvasId, labels, datasets) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  if (_charts[canvasId]) _charts[canvasId].destroy();
  _charts[canvasId] = new Chart(canvas.getContext('2d'), {
    type: 'line',
    data: { labels, datasets },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' }, beginAtZero: true }
      },
      plugins: { legend: { labels: { color: '#8b949e' } } }
    }
  });
}

function renderBarChart(canvasId, labels, data, label='Count') {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  if (_charts[canvasId]) _charts[canvasId].destroy();
  _charts[canvasId] = new Chart(canvas.getContext('2d'), {
    type: 'bar',
    data: { labels, datasets: [{ label, data, backgroundColor: '#58a6ff88', borderColor: '#58a6ff', borderWidth: 1 }] },
    options: {
      responsive: true, maintainAspectRatio: false, indexAxis: 'y',
      scales: {
        x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#8b949e', font: { size: 11 } }, grid: { color: '#21262d' } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

// ── Table filter helper ──────────────────────────────────────
function filterTable(inputId, tableId) {
  const input = document.getElementById(inputId);
  const table = document.getElementById(tableId);
  if (!input || !table) return;
  input.addEventListener('keyup', () => {
    const filter = input.value.toLowerCase();
    Array.from(table.querySelectorAll('tbody tr')).forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(filter) ? '' : 'none';
    });
  });
}

// CSS animation for toasts
const style = document.createElement('style');
style.textContent = `@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }`;
document.head.appendChild(style);
