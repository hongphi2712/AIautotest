import { invoke, showError, openBrowser } from '../api.js';
import { getProxy, subscribe } from '../store.js';

const TEMPLATE = `
  <div class="panel">
    <h3>Proxy listener</h3>
    <div class="field-grid">
      <label>Host</label><input id="px-host" value="127.0.0.1">
      <label>Port</label><input id="px-port" value="8080">
      <label>HTTPS interception</label><span class="muted">Enabled (MITM, per-host certificates)</span>
    </div>
    <div class="row" style="margin-top: 12px">
      <button id="px-toggle" class="btn primary">Start Proxy</button>
      <button class="btn" id="px-browser">Open browser</button>
      <span id="px-status" class="muted">Proxy stopped</span>
    </div>
  </div>
  <div class="panel"><h3>Scope</h3><p class="muted">Scope include/exclude rules are loaded from configuration. Out-of-scope traffic is forwarded as a blind tunnel and never captured.</p></div>
  <div class="panel">
    <h3>Certificates</h3>
    <p class="muted">CA: <code id="ca-path">checking…</code></p>
    <div class="row" style="margin-top:8px">
      <span id="ca-status" class="muted">Checking…</span>
      <button id="ca-install" class="btn" disabled>Install CA</button>
    </div>
    <p class="muted" style="margin-top:8px">HTTPS interception signs per-host certificates with this CA. Install it into your trust store so the browser accepts the MITM certificates.</p>
  </div>
`;

export class ProxySettingsView extends HTMLElement {
  connectedCallback() {
    this.innerHTML = TEMPLATE;
    this.querySelector('#px-toggle').addEventListener('click', () => this.toggleProxy());
    this.querySelector('#px-browser').addEventListener('click', () => openBrowser());
    this.querySelector('#ca-install').addEventListener('click', () => this.installCa());
    this.unsubscribe = subscribe(() => this.renderProxy());
    this.renderProxy();
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
      const status = await invoke('proxy_status');
      if (status.running) {
        await invoke('stop_proxy');
      } else {
        await invoke('start_proxy');
      }
      window.dispatchEvent(new CustomEvent('app:refresh-proxy'));
      await this.refreshCertInfo();
    } catch (error) {
      showError('Proxy error: ' + error);
    } finally {
      button.disabled = false;
    }
  }

  async refreshCertInfo() {
    try {
      const info = await invoke('cert_info');
      this.querySelector('#ca-path').textContent = info.path;
      const status = this.querySelector('#ca-status');
      const button = this.querySelector('#ca-install');
      if (!info.exists) {
        status.textContent = 'Not generated yet — start the proxy first.';
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
      await invoke('install_ca');
      await this.refreshCertInfo();
    } catch (error) {
      showError('Install CA failed: ' + error);
    }
  }
}

customElements.define('proxy-settings-view', ProxySettingsView);
