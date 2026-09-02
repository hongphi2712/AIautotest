import { apiGet, apiPost, apiDelete, showError, openBrowser } from '../api.js';
import { getProxy, getActiveSession, getSessions, subscribe } from '../store.js';

const TEMPLATE = `
  <div class="proxy-grid">
    <div class="proxy-col">
      <div class="panel session-panel">
        <div class="panel-header-row">
          <h3>Capture Session</h3>
          <div class="header-actions">
            <button id="session-stop" class="btn danger btn-sm" disabled>End Session</button>
            <button id="session-start" class="btn primary btn-sm">New Session</button>
            <button id="session-clear-all" class="btn danger btn-sm">Clear All</button>
          </div>
        </div>
        <div id="session-active" class="session-active-card"></div>
        <div class="session-history">
          <div class="history-header">
            <h4>Recent Sessions (Max 4)</h4>
          </div>
          <div id="session-list" class="session-list-container"></div>
        </div>
      </div>

      <div class="panel">
        <h3>Proxy Listener</h3>
        <div class="field-grid">
          <label>Host</label><input id="px-host" value="127.0.0.1">
          <label>Port</label><input id="px-port" value="8080">
          <label>HTTPS Interception</label><span class="muted">Enabled (MITM, per-host certificates)</span>
        </div>
        <div class="row" style="margin-top: 12px">
          <button id="px-toggle" class="btn primary">Start Proxy</button>
          <button class="btn" id="px-browser">Open Browser</button>
          <span id="px-status" class="muted">Proxy stopped</span>
        </div>
      </div>
    </div>

    <div class="proxy-col">
      <div class="panel">
        <h3>Scope & Interception Rules</h3>
        <p class="muted">Scope rules control which domains/hosts are captured into sessions. Out-of-scope traffic is forwarded as a blind tunnel and omitted from capture history.</p>
      </div>

      <div class="panel">
        <h3>Certificates</h3>
        <p class="muted">CA: <code id="ca-path">checking…</code></p>
        <div class="row" style="margin-top:8px">
          <span id="ca-status" class="muted">Checking…</span>
          <button id="ca-install" class="btn" disabled>Install CA</button>
        </div>
        <p class="muted" style="margin-top:8px">HTTPS interception signs per-host certificates with this CA. Install it into your trust store so the browser accepts the MITM certificates.</p>
      </div>
    </div>
  </div>
`;


export class ProxySettingsView extends HTMLElement {
  connectedCallback() {
    this.innerHTML = TEMPLATE;
    this.querySelector('#px-toggle').addEventListener('click', () => this.toggleProxy());
    this.querySelector('#px-browser').addEventListener('click', () => openBrowser());
    this.querySelector('#ca-install').addEventListener('click', () => this.installCa());
    this.querySelector('#session-stop').addEventListener('click', () => this.endSession());
    this.querySelector('#session-start').addEventListener('click', () => this.startSession());
    this.querySelector('#session-clear-all').addEventListener('click', () => this.clearAllSessions());
    this.unsubscribe = subscribe(() => { this.renderProxy(); this.renderSession(); });
    this.renderProxy();
    this.renderSession();
    this.refreshCertInfo();
  }

  disconnectedCallback() {
    if (this.unsubscribe) this.unsubscribe();
  }

  renderProxy() {
    const proxy = getProxy();
    const toggle = this.querySelector('#px-toggle');
    toggle.textContent = proxy.running ? 'Stop Proxy' : 'Start Proxy';
    toggle.className = 'btn ' + (proxy.running ? 'danger' : 'primary');
    this.querySelector('#px-status').textContent = proxy.running ? 'Proxy listening on ' + proxy.address : 'Proxy stopped';
  }

  async toggleProxy() {
    const button = this.querySelector('#px-toggle');
    button.disabled = true;
    try {
      const status = await apiGet('/api/proxy/status');
      if (status.running) {
        await apiPost('/api/proxy/stop');
      } else {
        await apiPost('/api/proxy/start');
      }
      window.dispatchEvent(new CustomEvent('app:refresh-proxy'));
      await this.refreshCertInfo();
    } catch (error) {
      showError('Proxy error: ' + error);
    } finally {
      button.disabled = false;
    }
  }

  renderSession() {
    const active = getActiveSession();
    const sessions = getSessions();
    const activeCard = this.querySelector('#session-active');
    const stopBtn = this.querySelector('#session-stop');
    const startBtn = this.querySelector('#session-start');
    const list = this.querySelector('#session-list');

    if (active) {
      const elapsed = active.start_time ? this.formatElapsed(active.start_time) : '';
      activeCard.innerHTML =
        '<span class="session-dot active"></span>' +
        '<strong>' + this.esc(active.name || 'capture') + '</strong>' +
        '<span class="session-meta"> · ' + this.esc(active.target_host || '') + '</span>' +
        '<span class="session-meta"> · ' + this.esc(elapsed) + '</span>' +
        '<span class="session-badge">' + (active.flow_count || 0) + ' flows</span>';
      stopBtn.disabled = false;
      startBtn.disabled = true;
    } else {
      activeCard.innerHTML = '<span class="session-dot inactive"></span><span class="session-meta">No active session — start the proxy to begin capturing</span>';
      stopBtn.disabled = true;
      startBtn.disabled = false;
    }

    list.innerHTML = '';
    const past = sessions.filter((s) => s.id !== (active && active.id));
    if (!past.length) {
      list.innerHTML = '<p class="muted" style="font-size:12px">No previous sessions.</p>';
      return;
    }
    var self = this;
    past.slice(0, 4).forEach((s) => {
      const item = document.createElement('div');
      item.className = 'session-list-item';
      item.innerHTML =
        '<span class="session-dot inactive"></span>' +
        '<span class="session-name">' + this.esc(s.name || s.id.slice(0, 8)) + '</span>' +
        '<span class="session-meta">' + this.formatTime(s.start_time) + '</span>' +
        '<span class="session-badge">' + (s.flow_count || 0) + ' flows</span>';
      item.onclick = () => {
        window.dispatchEvent(new CustomEvent('app:select-session', { detail: s.id }));
        window.dispatchEvent(new CustomEvent('app:navigate', { detail: { view: 'proxy' } }));
        const subtab = document.querySelector('[data-subtab="http-history"]');
        if (subtab) subtab.click();
      };
      var delBtn = document.createElement('button');
      delBtn.className = 'session-delete-btn';
      delBtn.innerHTML = '✕';
      delBtn.title = 'Xóa phiên này';
      var sid = s.id;
      var sname = s.name || s.id.slice(0, 8);
      delBtn.addEventListener('click', function(ev) {
        ev.stopPropagation();
        if (window.confirm('Bạn có chắc muốn xóa phiên "' + sname + '"?')) {
          self.deleteSession(sid);
        }
      });
      item.appendChild(delBtn);
      list.appendChild(item);
    });

  }

  async startSession() {
    const defName = 'capture-' + new Date().toISOString().slice(0,16).replace('T',' ');
    const name = window.prompt('Tên session:', defName);
    if (name === null) return;
    const clean = (name || '').trim() || defName;
    // lấy target_host từ Base URL đã lưu (nếu có) để session gắn đúng host
    let target_host = '';
    try{
      const saved = localStorage.getItem('target.base_url');
      if(saved) target_host = new URL(saved).host;
    }catch{}
    try {
      await apiPost('/api/sessions/start', {name: clean, target_host});
      window.dispatchEvent(new CustomEvent('app:refresh-proxy'));
    } catch (error) {
      showError('Start session: ' + error);
    }
  }

  async endSession() {
    try {
      await apiPost('/api/sessions/stop');
      window.dispatchEvent(new CustomEvent('app:refresh-proxy'));
    } catch (error) {
      showError('End session: ' + error);
    }
  }

  async deleteSession(id) {
    try {
      await apiDelete('/api/sessions/' + encodeURIComponent(id));
      window.dispatchEvent(new CustomEvent('app:refresh-proxy'));
    } catch (error) {
      showError('Delete session: ' + error);
    }
  }

  async clearAllSessions() {
    if (!window.confirm('Xoa tat ca sessions?')) return;
    try {
      await apiPost('/api/sessions/clear');
      window.dispatchEvent(new CustomEvent('app:refresh-proxy'));
    } catch (error) {
      showError('Clear sessions: ' + error);
    }
  }

  esc(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }

  formatTime(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  formatElapsed(startTs) {
    if (!startTs) return '';
    const ms = Date.now() - new Date(startTs).getTime();
    const mins = Math.floor(ms / 60000);
    if (mins < 60) return mins + 'm';
    const hrs = Math.floor(mins / 60);
    return hrs + 'h ' + (mins % 60) + 'm';
  }
  async refreshCertInfo() {
    try {
      const info = await apiGet('/api/cert/info');
      this.querySelector('#ca-path').textContent = info.path;
      const status = this.querySelector('#ca-status');
      const button = this.querySelector('#ca-install');
      if (!info.exists) {
        status.textContent = 'Not generated yet â€” start the proxy first.';
        button.disabled = true;
        button.textContent = 'Install CA';
      } else if (info.installed) {
        status.textContent = 'Installed and trusted';
        button.disabled = true;
        button.textContent = 'Installed';
      } else {
        status.textContent = 'Generated but not trusted yet.';
        button.disabled = false;
        button.textContent = 'Install CA';
      }
    } catch (error) {
      this.querySelector('#ca-status').textContent = 'Error: ' + error;
    }
  }

  async installCa() {
    try {
      await apiPost('/api/cert/install');
      await this.refreshCertInfo();
    } catch (error) {
      showError('Install CA failed: ' + error);
    }
  }
}

if (!customElements.get('proxy-settings-view')) customElements.define('proxy-settings-view', ProxySettingsView);
