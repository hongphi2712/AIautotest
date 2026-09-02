import { apiGet, showError } from './api.js';
import { setProxyStatus, setLiveFlowCount, setSession, setSessions, getActiveSession } from './store.js';

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
    const health = await apiGet('/api/health');
    const flows = health.flows || 0;
    const sbFlows = document.getElementById('sb-flows');
    if (sbFlows) sbFlows.textContent = flows + ' captured';
    const sbSession = document.getElementById('sb-session');
    if (sbSession) {
      const session = getActiveSession();
      if (session) {
        sbSession.textContent = 'Session: ' + (session.name || session.id.slice(0, 8)) + ' (' + (session.flow_count || 0) + ')';
        sbSession.className = 'ok';
      } else {
        sbSession.textContent = 'Session: none';
        sbSession.className = 'muted';
      }
    }
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
    const status = await apiGet('/api/proxy/status');
    setProxyStatus(status.running, status.address || '');
    setSession(status.session_id || null);
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


async function fetchSessions() {
  try {
    const sessions = await apiGet('/api/sessions');
    setSessions(sessions || []);
  } catch {
    setSessions([]);
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
  window.addEventListener('app:refresh-proxy', () => { refreshProxyStatus(); fetchSessions(); });
  window.addEventListener('app:ws-proxy', (event) => {
    const running = event.detail && event.detail.running;
    const address = (event.detail && event.detail.address) || '';
    const pill = document.getElementById('proxy-pill');
    if (pill) pill.classList.toggle('running', running);
    const pillText = document.getElementById('proxy-pill-text');
    if (pillText) pillText.textContent = running ? 'Proxy: ' + address : 'Proxy: stopped';
    const sbProxy = document.getElementById('sb-proxy');
    if (sbProxy) {
      sbProxy.textContent = running ? 'Proxy: ' + address : 'Proxy: stopped';
      sbProxy.className = running ? 'ok' : 'warn';
    }
  });

  refreshProxyStatus();
  fetchSessions();
  refreshHealth();
  setInterval(() => { refreshHealth(); }, 2000);
}
