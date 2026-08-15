import { invoke, showError } from './api.js';
import { setProxyStatus, setLiveFlowCount } from './store.js';

function showView(name) {
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === 'view-' + name));
  document.querySelectorAll('.wtabs .wt').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
}

export { showView };

function showBanner(message) {
  const banner = document.getElementById('error-banner');
  banner.textContent = message;
  banner.classList.add('visible');
  setTimeout(() => banner.classList.remove('visible'), 6000);
}

async function refreshHealth() {
  try {
    const health = await invoke('app_health');
    const flows = health.flows || 0;
    const sbFlows = document.getElementById('sb-flows');
    if (sbFlows) sbFlows.textContent = flows + ' captured';
    setLiveFlowCount(flows);
    window.dispatchEvent(new CustomEvent('app:health', { detail: { flows, last_error: health.last_error } }));
    if (health.last_error) {
      showBanner('Proxy error: ' + health.last_error);
    }
  } catch (error) {
    showError('Backend unavailable: ' + error);
  }
}

async function refreshProxyStatus() {
  try {
    const status = await invoke('proxy_status');
    setProxyStatus(status.running, status.address || '');
    const pill = document.getElementById('proxy-pill');
    if (pill) pill.classList.toggle('running', status.running);
    const pillText = document.getElementById('proxy-pill-text');
    if (pillText) pillText.textContent = status.running ? 'Proxy: ' + status.address : 'Proxy: stopped';
    const sbProxy = document.getElementById('sb-proxy');
    if (sbProxy) {
      sbProxy.textContent = status.running ? 'Proxy: ' + status.address : 'Proxy: stopped';
      sbProxy.className = status.running ? 'ok' : 'warn';
    }
    return status;
  } catch (error) {
    showError('Cannot reach backend: ' + error);
    return null;
  }
}

export function initShell() {
  document.querySelectorAll('.wtabs .wt').forEach((btn) => {
    btn.addEventListener('click', () => showView(btn.dataset.tab));
  });
  document.querySelectorAll('.proxy-subtab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.proxy-subtab').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.proxy-subpane').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('sub-' + btn.dataset.subtab).classList.add('active');
      window.dispatchEvent(new CustomEvent('app:subtab', { detail: btn.dataset.subtab }));
    });
  });
  window.addEventListener('app:error', (event) => showBanner(event.detail));
  window.addEventListener('app:navigate', (event) => showView(event.detail.view));
  window.addEventListener('app:refresh-proxy', () => refreshProxyStatus());

  refreshProxyStatus();
  refreshHealth();
  setInterval(() => { refreshHealth(); }, 2000);
}
