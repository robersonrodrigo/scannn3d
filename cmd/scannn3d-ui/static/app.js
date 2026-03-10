const form = document.getElementById('scan-form');
const jobsEl = document.getElementById('jobs');
const reportEl = document.getElementById('report');
const extEl = document.getElementById('external-tools');
const execEl = document.getElementById('execution-status');
const kpiEl = document.getElementById('kpi-banner');

let selectedJob = null;
let severityChart = null;
let moduleChart = null;

function autoPayload(target) {
  return {
    target,
    endpoints: ['/'],
    crawl: true,
    crawl_depth: 1,
    method: 'GET',
    body: '',
    headers: { Accept: 'application/json' },
    rate: 12,
    burst: 12,
    concurrency: 8,
    timeout_ms: 10000,
    insecure_tls: false,
    scope_hosts: [],
    modules: ['all'],
    external_tools: ['all'],
    dirsearch_enabled: true,
    dirsearch_profile: 'auto',
    dirsearch_intensity: 'balanced',
    format: 'both',
    auth_type: 'none',
    verbose: false
  };
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const target = new FormData(form).get('target')?.trim();
  if (!target) return;

  const res = await fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(autoPayload(target))
  });

  const json = await res.json();
  if (res.ok && json.id) {
    selectedJob = json.id;
    await refreshJobs();
  }
});

async function refreshJobs() {
  const res = await fetch('/api/jobs');
  if (!res.ok) return;
  const jobs = await res.json();

  jobsEl.innerHTML = jobs.map(job => `
    <div class="job ${selectedJob === job.id ? 'active' : ''}" onclick="selectJob('${job.id}')">
      <strong>${job.id}</strong>
      <div class="status ${job.status}">${job.status}</div>
      <div class="meta">${new Date(job.started_at).toLocaleString()}</div>
      <div class="meta">${job.config.target}</div>
      ${job.error ? `<div class="error">${job.error}</div>` : ''}
    </div>
  `).join('');

  if (selectedJob) await refreshReport();
}

window.selectJob = (id) => {
  selectedJob = id;
  refreshJobs();
};

async function refreshReport() {
  if (!selectedJob) return;
  const res = await fetch(`/api/jobs/${selectedJob}`);
  if (!res.ok) return;
  const job = await res.json();

  renderKPIs(job);
  renderCharts(job);
  renderExecution(job);
  renderExternal(job);

  if (!job.report) {
    reportEl.innerHTML = `<p class="meta">Aguardando geração do relatório final...</p>`;
    return;
  }

  const findings = job.report.findings || [];

  let html = `
    <div class="finding-row header">
      <div>Findings</div>
      <div>Severity</div>
      <div>Module</div>
      <div>Path</div>
      <div>Detected</div>
      <div>Status</div>
    </div>
  `;

  html += findings.map(f => `
    <div class="finding-wrapper">
      <div class="finding-row" onclick="this.nextElementSibling.toggleAttribute('open')">
        <div style="font-weight:600">${f.title}</div>
        <div><span class="severity-tag ${f.severity}">${f.severity}</span></div>
        <div class="meta">${f.module}</div>
        <div class="meta" style="font-family:monospace">${f.endpoint}</div>
        <div class="meta">${new Date(f.timestamp || Date.now()).toLocaleTimeString()}</div>
        <div class="meta" style="color:var(--accent-mint)">Active</div>
      </div>
      <div class="finding-details" style="display:none; padding: 20px; background: rgba(0,0,0,0.2); border-bottom: 1px solid var(--border)">
        <p>${f.description}</p>
        <div class="meta"><strong>Evidence:</strong> ${f.evidence}</div>
        ${f.raw_request ? `
          <details class="evidence-block" style="margin-top:10px">
            <summary style="cursor:pointer; color:var(--accent-blue)">Raw Request</summary>
            <pre style="margin-top:10px">${escapeHtml(f.raw_request)}</pre>
          </details>
        ` : ''}
        ${f.raw_response ? `
          <details class="evidence-block" style="margin-top:10px">
            <summary style="cursor:pointer; color:var(--accent-blue)">Raw Response</summary>
            <pre style="margin-top:10px">${escapeHtml(f.raw_response)}</pre>
          </details>
        ` : ''}
        <p style="margin-top:15px; font-size:0.9rem; color:var(--accent-mint)"><strong>Recommendation:</strong> ${f.recommendation}</p>
      </div>
    </div>
  `).join('');

  reportEl.innerHTML = html;

  // Manual toggle logic since we can't easily use <details> for a table row look
  reportEl.querySelectorAll('.finding-row').forEach(row => {
    row.addEventListener('click', () => {
      const details = row.nextElementSibling;
      details.style.display = details.style.display === 'none' ? 'block' : 'none';
    });
  });
}

function renderKPIs(job) {
  const summary = job.report?.summary || {};
  const bySev = summary.by_severity || {};

  kpiEl.innerHTML = `
    <div class="kpi-card">
      <div class="kpi-header">
        <div class="label">TOTAL FINDINGS</div>
        <div class="kpi-trend" style="color:var(--accent-amber)">+12%</div>
      </div>
      <div class="value" style="color:var(--accent-amber)">${summary.total || 0}</div>
      <div class="kpi-tag">Amber</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-header">
        <div class="label">HIGH SEVERITY</div>
        <div class="kpi-trend" style="color:var(--accent-red)">+5%</div>
      </div>
      <div class="value" style="color:var(--accent-red)">${(bySev.critical || 0) + (bySev.high || 0)}</div>
      <div class="kpi-tag">Soft Red</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-header">
        <div class="label">LAST SCAN DURATION</div>
        <div class="kpi-trend" style="color:var(--accent-mint)">Mint</div>
      </div>
      <div class="value" style="color:var(--accent-mint)">${summary.elapsed_ms ? formatDuration(summary.elapsed_ms) : '--'}</div>
      <div class="kpi-tag">${job.config.target}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-header">
        <div class="label">TARGET URL</div>
      </div>
      <div class="value" style="font-size:1.1rem; margin-top:18px; color:var(--accent-blue); overflow:hidden; text-overflow:ellipsis; white-space:nowrap">${job.config.target}</div>
      <div class="kpi-tag">Status: ${job.status}</div>
    </div>
  `;
}

function formatDuration(ms) {
  const seconds = Math.floor((ms / 1000) % 60);
  const minutes = Math.floor((ms / (1000 * 60)) % 60);
  const hours = Math.floor((ms / (1000 * 60 * 60)) % 24);
  return `${hours.toString().padStart(2, '0')}h ${minutes.toString().padStart(2, '0')}m ${seconds.toString().padStart(2, '0')}s`;
}

function renderCharts(job) {
  const summary = job.report?.summary;
  if (!summary) return;

  // Severity Chart
  const sevData = summary.by_severity || {};
  const sevLabels = ['critical', 'high', 'medium', 'low'];
  const sevValues = sevLabels.map(l => sevData[l] || 0);

  if (!severityChart) {
    severityChart = new Chart(document.getElementById('severity-chart'), {
      type: 'doughnut',
      data: {
        labels: sevLabels,
        datasets: [{
          data: sevValues,
          backgroundColor: ['#ff8383', '#ff9f43', '#ffd166', '#43e5b5'],
          borderWidth: 0
        }]
      },
      options: { plugins: { legend: { position: 'bottom', labels: { color: '#9ac1ca' } } } }
    });
  } else {
    severityChart.data.datasets[0].data = sevValues;
    severityChart.update();
  }

  // Module Chart
  const modData = summary.by_module || {};
  const modLabels = Object.keys(modData);
  const modValues = Object.values(modData);

  if (!moduleChart) {
    moduleChart = new Chart(document.getElementById('module-chart'), {
      type: 'bar',
      data: {
        labels: modLabels,
        datasets: [{
          label: 'Achados',
          data: modValues,
          backgroundColor: '#2fc1ff'
        }]
      },
      options: {
        scales: {
          y: { beginAtZero: true, grid: { color: '#2f5862' }, ticks: { color: '#9ac1ca' } },
          x: { ticks: { color: '#9ac1ca' } }
        },
        plugins: { legend: { display: false } }
      }
    });
  } else {
    moduleChart.data.labels = modLabels;
    moduleChart.data.datasets[0].data = modValues;
    moduleChart.update();
  }
}

function renderExecution(job) {
  const progress = Number(job.progress || 0);
  execEl.innerHTML = `
    <div class="finding" style="border-style:dashed">
      <h4 style="margin:0">Fluxo de Escaneamento</h4>
      <div class="meta" style="margin:8px 0">Fase atual: <strong>${job.phase || 'inicializando'}</strong></div>
      <div class="progress-wrap"><div class="progress-bar" style="width:${progress}%"></div></div>
      <div class="meta">${progress}% concluído</div>
    </div>
  `;
}

function renderExternal(job) {
  const external = job.external_results || [];
  if (!external.length) {
    extEl.innerHTML = '';
    return;
  }
  extEl.innerHTML = `
    <div class="finding">
      <h4>Ferramentas Externas</h4>
      ${external.map(t => `
        <div style="margin-bottom:8px; font-size:0.9rem">
          <strong>${t.tool}</strong>: <span class="status ${t.status}">${t.status}</span>
          <div class="meta">${t.message || ''}</div>
        </div>
      `).join('')}
    </div>
  `;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

setInterval(refreshJobs, 3000);
refreshJobs();
