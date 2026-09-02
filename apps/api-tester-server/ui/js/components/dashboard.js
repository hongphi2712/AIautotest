import { getSelected, getLive, getProxy, getActiveSession, subscribe } from '../store.js';
import { apiGet, colorStatus, formatStatus } from '../api.js';
import './sidebar.js';

const TEMPLATE = `
  <div class="dash-body">
    <div class="dash-main">
      <div class="task-header">
        <h2 id="dash-task-title">Executive Security Control Center</h2>
        <div class="th-meta">
          <span id="dash-status">Status: <b>idle</b></span>
          <span id="dash-progress">Requests: 0</span>
          <span id="dash-findings">Findings: 0</span>
        </div>
      </div>

      <div class="task-tabs">
        <button class="active" data-pane="dash-summary">Summary</button>
        <button data-pane="dash-config">Configuration</button>
        <button data-pane="dash-progress">Progress & Runs</button>
        <button data-pane="dash-log">System Log</button>
      </div>

      <!-- TAB 1: SUMMARY -->
      <div id="dash-summary" class="task-pane active">
        <div class="summary-grid">
          <div class="stat">
            <div class="s-val" id="stat-flows">0</div>
            <div class="s-label">Flows Captured</div>
          </div>
          <div class="stat">
            <div class="s-val" id="stat-anomalies" style="color: #dc2626;">0</div>
            <div class="s-label">Anomalies & Leaks</div>
          </div>
          <div class="stat">
            <div class="s-val" id="stat-findings" style="color: #ea580c;">0</div>
            <div class="s-label">Security Findings</div>
          </div>
          <div class="stat">
            <div class="s-val" id="stat-proxy">Stopped</div>
            <div class="s-label">Proxy Status</div>
          </div>
        </div>

        <div class="dash-actions-bar">
          <button class="btn primary" id="act-new-scan">Run Security Test</button>
          <button class="btn" id="act-ai-plan">Generate AI Test Plan</button>
          <button class="btn" id="act-export-json">Export Findings (JSON)</button>
        </div>

        <div id="dash-session-card" class="session-card" style="display:none">
          <div class="sc-header">
            <span class="session-dot active"></span>
            <strong id="sc-name"></strong>
            <span class="session-badge" id="sc-flows"></span>
          </div>
          <div class="sc-meta" id="sc-meta"></div>
          <button class="btn" id="sc-view-history" style="margin-top: 8px;">View in HTTP History</button>
        </div>

        <div class="panel-section" style="margin: 16px;">
          <h3 style="margin-bottom: 8px; font-size: 13px; font-weight: 600; color: var(--text);">Security Signals & Observed Vulnerabilities</h3>
          <div id="dash-findings-table-wrap">
            <p class="muted" style="font-size: 12px;">No security findings recorded yet. Start proxy or execute a security test plan to analyze traffic.</p>
          </div>
        </div>

        <div id="dash-empty" class="empty">
          <h3>No Traffic Captured Yet</h3>
          <p>Start the proxy and browse to a target host to begin capturing HTTP traffic. All requests are automatically scanned for passwords, Gitleaks secrets, and debug leaks.</p>
        </div>
      </div>

      <!-- TAB 3: CONFIGURATION -->
      <div id="dash-config" class="task-pane">
        <div class="panel-section" style="padding: 16px;">
          <h3 style="font-size: 14px; margin-bottom: 12px;">System & Engine Configuration</h3>
          <div class="field-grid" style="max-width: 600px;">
            <label>Storage Engine</label><span>SQLite (~/.api-tester/db.sqlite)</span>
            <label>AI Provider</label><span id="cfg-ai-provider">DeepSeek (Chat / Reasoner)</span>
            <label>Gitleaks Engine</label><span>CLI Pipe Inspector (gitleaks detect --pipe)</span>
            <label>Security Rules</label><span>CWE-215, CWE-209, CWE-284, Overfetching</span>
            <label>Proxy Listener</label><span id="cfg-proxy-addr">127.0.0.1:8080</span>
          </div>
        </div>
      </div>

      <!-- TAB 4: PROGRESS & RUNS -->
      <div id="dash-progress" class="task-pane">
        <div class="panel-section" style="padding: 16px;">
          <h3 style="font-size: 14px; margin-bottom: 12px;">Active Security Test Runs</h3>
          <div id="dash-runs-list">
            <p class="muted" style="font-size: 12px;">No active execution runs. Select a Security Plan to start automated payload injection.</p>
          </div>
        </div>
      </div>

      <!-- TAB 5: SYSTEM LOG -->
      <div id="dash-log" class="task-pane">
        <div class="panel-section" style="padding: 16px;">
          <h3 style="font-size: 14px; margin-bottom: 8px;">System Execution Log</h3>
          <pre id="sys-log-console" style="background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 4px; font-family: monospace; font-size: 11px; height: 320px; overflow-y: auto;">[INFO] System initialized. Ready for HTTP Proxy interception.</pre>
        </div>
      </div>
    </div>

    <aside class="sidebar">
      <task-sidebar></task-sidebar>
    </aside>
  </div>
`;

export class DashboardView extends HTMLElement {
  connectedCallback() {
    this.innerHTML = TEMPLATE;
    this.flowCount = 0;
    this.anomalyCount = 0;

    this.querySelectorAll('.task-tabs button').forEach((btn) => {
      btn.addEventListener('click', () => {
        this.querySelectorAll('.task-tabs button').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        this.querySelectorAll('.task-pane').forEach((p) => p.classList.toggle('active', p.id === btn.dataset.pane));
        if (btn.dataset.pane === 'dash-progress') {
          this.loadRuns();
        }
      });
    });

    this.onHealth = (event) => {
      this.flowCount = event.detail.flows || 0;
      this.refresh();
    };
    window.addEventListener('app:health', this.onHealth);

    this.querySelector('#sc-view-history').addEventListener('click', () => {
      window.dispatchEvent(new CustomEvent('app:navigate', { detail: { view: 'proxy' } }));
      const subtab = document.querySelector('[data-subtab="http-history"]');
      if (subtab) subtab.click();
    });

    this.querySelector('#act-new-scan').addEventListener('click', () => {
      window.dispatchEvent(new CustomEvent('app:navigate', { detail: { view: 'security' } }));
    });

    this.querySelector('#act-ai-plan').addEventListener('click', () => {
      window.dispatchEvent(new CustomEvent('app:navigate', { detail: { view: 'security' } }));
    });

    this.querySelector('#act-export-json').addEventListener('click', () => this.exportFindings());
    this.unsubscribe = subscribe(() => this.refresh());
    this.refresh();
    this.loadAnomaliesAndFindings();
  }

  disconnectedCallback() {
    window.removeEventListener('app:health', this.onHealth);
    if (this.unsubscribe) this.unsubscribe();
  }

  async refresh() {
    const task = getSelected() || (getLive() || { name: 'Live Passive Proxy Monitor', status: 'idle', requests: 0, findings: 0 });
    this.querySelector('#dash-task-title').textContent = task.name;
    this.querySelector('#dash-status').innerHTML = 'Status: <b>' + task.status + '</b>';
    this.querySelector('#dash-progress').textContent = 'Requests: ' + task.requests;
    this.querySelector('#dash-findings').textContent = 'Findings: ' + task.findings;
    this.querySelector('#stat-findings').textContent = task.findings;
    this.querySelector('#stat-flows').textContent = this.flowCount;
    this.querySelector('#stat-proxy').textContent = getProxy().running ? 'Running' : 'Stopped';
    this.querySelector('#cfg-proxy-addr').textContent = getProxy().address || '127.0.0.1:8080';
    this.querySelector('#dash-empty').style.display = this.flowCount > 0 ? 'none' : '';
    this.renderSessionCard();
  }

  async loadAnomaliesAndFindings() {
    try {
      const flows = await apiGet('/api/flows');
      let anomalyCount = 0;
      const suspiciousFlows = [];
      (flows || []).forEach((f) => {
        if (f.is_suspicious) {
          anomalyCount += (f.security_signals ? f.security_signals.length : 1);
          suspiciousFlows.push(f);
        }
      });
      this.anomalyCount = anomalyCount;
      const anomalyStat = this.querySelector('#stat-anomalies');
      if (anomalyStat) anomalyStat.textContent = String(anomalyCount);

      const tableWrap = this.querySelector('#dash-findings-table-wrap');
      if (!tableWrap) return;

      if (!suspiciousFlows.length) {
        tableWrap.innerHTML = '<p class="muted" style="font-size: 12px;">No anomalous flows detected yet in current capture session.</p>';
        return;
      }

      let html = '<table class="data-table" style="width: 100%; font-size: 12px; border-collapse: collapse;">' +
        '<thead><tr style="text-align: left; border-bottom: 1px solid var(--border);"><th style="padding: 6px;">Method</th><th style="padding: 6px;">Host & Path</th><th style="padding: 6px;">Status</th><th style="padding: 6px;">Security Signals</th></tr></thead><tbody>';

      suspiciousFlows.slice(0, 10).forEach((f) => {
        const signals = (f.security_signals || []).map(s => '<span class="badge danger" style="margin-right: 4px; padding: 2px 6px; background: #dc2626; color: #fff; font-size: 10px; border-radius: 3px;">' + this.esc(s) + '</span>').join('');
        html += '<tr style="border-bottom: 1px solid var(--border);">' +
          '<td style="padding: 6px; font-weight: 600;">' + this.esc(f.method) + '</td>' +
          '<td style="padding: 6px;">' + this.esc(f.host + f.path) + '</td>' +
          '<td style="padding: 6px;">' + formatStatus(f.status) + '</td>' +
          '<td style="padding: 6px;">' + signals + '</td>' +
          '</tr>';
      });
      html += '</tbody></table>';
      tableWrap.innerHTML = html;
    } catch { /* suppress fetch errors */ }
  }

  async loadRuns() {
    const container = this.querySelector('#dash-runs-list');
    if (!container) return;
    try {
      const plans = await apiGet('/api/security/plans');
      if (!plans || !plans.length) {
        container.innerHTML = '<p class="muted" style="font-size: 12px;">No security plans created yet. Navigate to Security view to generate an AI plan.</p>';
        return;
      }
      let html = '<div style="display: flex; flex-direction: column; gap: 8px;">';
      plans.forEach((p) => {
        html += '<div style="border: 1px solid var(--border); border-radius: 4px; padding: 10px; background: var(--panel); display: flex; align-items: center; justify-content: space-between;">' +
          '<div>' +
          '<strong style="font-size: 13px;">' + this.esc(p.name || 'Security Test Plan') + '</strong>' +
          '<div class="muted" style="font-size: 11px;">Status: ' + this.esc(p.status || 'draft') + ' · Base URL: ' + this.esc(p.base_url || '') + '</div>' +
          '</div>' +
          '<button class="btn btn-sm primary" onclick="window.dispatchEvent(new CustomEvent(\'app:navigate\', { detail: { view: \'security\' } }))">View Plan</button>' +
          '</div>';
      });
      html += '</div>';
      container.innerHTML = html;
    } catch (err) {
      container.innerHTML = '<p class="muted" style="font-size: 12px;">Error loading security plans: ' + this.esc(err.message) + '</p>';
    }
  }

  async exportFindings() {
    try {
      const flows = await apiGet('/api/flows');
      const suspicious = (flows || []).filter(f => f.is_suspicious);
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(suspicious, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", "security_findings_report.json");
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } catch (error) {
      alert("Failed to export report: " + error);
    }
  }

  renderSessionCard() {
    const card = this.querySelector('#dash-session-card');
    if (!card) return;
    const session = getActiveSession();
    if (session) {
      card.style.display = '';
      this.querySelector('#sc-name').textContent = session.name || 'capture';
      this.querySelector('#sc-flows').textContent = (session.flow_count || 0) + ' flows';
      const started = session.start_time ? new Date(session.start_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
      const elapsed = session.start_time ? this.formatElapsed(session.start_time) : '';
      this.querySelector('#sc-meta').textContent = (session.target_host || '') + ' · Started ' + started + ' · ' + elapsed;
    } else {
      card.style.display = 'none';
    }
  }

  formatElapsed(startTs) {
    if (!startTs) return '';
    const ms = Date.now() - new Date(startTs).getTime();
    const mins = Math.floor(ms / 60000);
    if (mins < 60) return mins + 'm elapsed';
    const hrs = Math.floor(mins / 60);
    return hrs + 'h ' + (mins % 60) + 'm elapsed';
  }

  esc(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }
}

if (!customElements.get('dashboard-view')) customElements.define('dashboard-view', DashboardView);
