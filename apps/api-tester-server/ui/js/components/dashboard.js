import { getSelected, getLive, getProxy, subscribe } from '../store.js';
import './sidebar.js';

const TEMPLATE = `
  <div class="dash-body">
    <div class="dash-main">
      <div class="task-header">
        <h2 id="dash-task-title">Live passive crawl from Proxy</h2>
        <div class="th-meta">
          <span id="dash-status">Status: <b>idle</b></span>
          <span id="dash-progress">Requests: 0</span>
          <span id="dash-findings">Findings: 0</span>
        </div>
      </div>
      <div class="task-tabs">
        <button class="active" data-pane="dash-summary">Summary</button>
        <button data-pane="dash-sitemap">Site map</button>
        <button data-pane="dash-config">Config</button>
        <button data-pane="dash-progress">Progress</button>
        <button data-pane="dash-log">Log</button>
      </div>
      <div id="dash-summary" class="task-pane active">
        <div class="summary-grid">
          <div class="stat"><div class="s-val" id="stat-flows">0</div><div class="s-label">Flows captured</div></div>
          <div class="stat"><div class="s-val" id="stat-reqs">0</div><div class="s-label">Requests</div></div>
          <div class="stat"><div class="s-val" id="stat-findings">0</div><div class="s-label">Findings</div></div>
          <div class="stat"><div class="s-val" id="stat-proxy">Stopped</div><div class="s-label">Proxy</div></div>
        </div>
        <div id="dash-empty" class="empty">
          <div class="big">ⓘ</div>
          <h3>No traffic captured yet</h3>
          <p>Start the proxy and browse to a target to begin a live passive crawl. Captured requests appear in HTTP history and are persisted to SQLite.</p>
        </div>
      </div>
      <div id="dash-sitemap" class="task-pane"><div class="empty"><h3>Site map</h3><p>Captured hosts and endpoints will be listed here.</p></div></div>
      <div id="dash-config" class="task-pane"><div class="empty"><h3>Task configuration</h3><p>Scope and capture settings live in <code>~/.api-tester/config.json</code>.</p></div></div>
      <div id="dash-progress" class="task-pane"><div class="empty"><h3>Task progress</h3><p>Progress is reported here as scans run.</p></div></div>
      <div id="dash-log" class="task-pane"><div class="empty"><h3>Task log</h3><p>Log output appears here.</p></div></div>
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
    this.querySelectorAll('.task-tabs button').forEach((btn) => {
      btn.addEventListener('click', () => {
        this.querySelectorAll('.task-tabs button').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        this.querySelectorAll('.task-pane').forEach((p) => p.classList.toggle('active', p.id === btn.dataset.pane));
      });
    });
    this.onHealth = (event) => {
      this.flowCount = event.detail.flows || 0;
      this.refresh();
    };
    window.addEventListener('app:health', this.onHealth);
    this.unsubscribe = subscribe(() => this.refresh());
    this.refresh();
  }

  disconnectedCallback() {
    window.removeEventListener('app:health', this.onHealth);
    if (this.unsubscribe) this.unsubscribe();
  }

  refresh() {
    const task = getSelected() || (getLive() || { name: 'Live passive crawl from Proxy', status: 'idle', requests: 0, findings: 0 });
    this.querySelector('#dash-task-title').textContent = task.name;
    this.querySelector('#dash-status').innerHTML = 'Status: <b>' + task.status + '</b>';
    this.querySelector('#dash-progress').textContent = 'Requests: ' + task.requests;
    this.querySelector('#dash-findings').textContent = 'Findings: ' + task.findings;
    this.querySelector('#stat-reqs').textContent = task.requests;
    this.querySelector('#stat-findings').textContent = task.findings;
    this.querySelector('#stat-flows').textContent = this.flowCount;
    this.querySelector('#stat-proxy').textContent = getProxy().running ? 'Running' : 'Stopped';
    this.querySelector('#dash-empty').style.display = this.flowCount > 0 ? 'none' : '';
  }
}

customElements.define('dashboard-view', DashboardView);
