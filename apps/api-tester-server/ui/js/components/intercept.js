import {
  invoke, formatTime, colorStatus, toHex, formatHeaders, showError, openBrowser,
  buildMessage, contentTypeFromHeaders, isJsonContentType, highlightJson,
  parseQueryParams, parseBodyParams, parseCookies,
} from '../api.js';
import './message-viewer.js';

const TEMPLATE = `
  <div class="intercept-bar">
    <div class="intercept-left">
      <button class="btn intercept-on inactive" id="intercept-toggle">Intercept off</button>
      <button class="btn forward" id="intercept-forward">Forward</button>
      <button class="btn drop" id="intercept-drop">Drop</button>
    </div>
    <div class="intercept-right">
      <span class="request-info" id="intercept-request-info">No intercepted request</span>
      <button class="btn" id="intercept-browser">Open browser</button>
    </div>
  </div>
  <div id="intercept-warning" class="intercept-warning" style="display:none">Intercept is ON: requests/responses pause until you Forward or Drop them.</div>
  <div class="table-scroll" id="intercept-scroll" style="flex:1;min-height:180px">
    <table class="flows intercept-flows">
      <thead><tr>
        <th class="col-num">#</th><th class="col-time">Time</th><th class="col-type">Type</th><th class="col-direction">Direction</th><th class="col-method">Method</th><th class="col-url">URL</th><th class="col-status">Status</th><th class="col-length">Length</th>
      </tr></thead>
      <tbody id="intercept-tbody"></tbody>
    </table>
  </div>
  <message-viewer id="viewer" editable></message-viewer>
`;

export class InterceptView extends HTMLElement {
  connectedCallback() {
    this.innerHTML = TEMPLATE;
    this.interceptEnabled = false;
    this.interceptEntries = [];
    this.selectedInterceptId = null;
    this.timer = null;
    this.viewer = this.querySelector('#viewer');
    this.tbody = this.querySelector('#intercept-tbody');
    this.querySelector('#intercept-toggle').addEventListener('click', () => this.toggleIntercept());
    this.querySelector('#intercept-forward').addEventListener('click', () => this.forwardRequest());
    this.querySelector('#intercept-drop').addEventListener('click', () => this.dropRequest());
    this.querySelector('#intercept-browser').addEventListener('click', () => openBrowser());
    this.viewer.addEventListener('viewer-action', (event) => {
      if (event.detail === 'edit') this.showEditPane();
      else if (event.detail === 'apply') this.applyInterceptEdit();
      else if (event.detail === 'cancel') this.hideEditPane();
    });
    this.syncInterceptStatus();
  }

  disconnectedCallback() {
    this.stopInterceptPolling();
  }

  async syncInterceptStatus() {
    try {
      const status = await invoke('intercept_status');
      this.interceptEnabled = !!status.enabled;
      this.updateInterceptBar();
      if (this.interceptEnabled) {
        await invoke('intercept_set_scopes', { interceptRequests: true, interceptResponses: true });
        this.startInterceptPolling();
      }
    } catch (error) {
      showError('Intercept status: ' + error);
    }
  }

  async toggleIntercept() {
    this.interceptEnabled = !this.interceptEnabled;
    try {
      await invoke('intercept_set_enabled', { enabled: this.interceptEnabled });
    } catch (error) {
      showError('Intercept: ' + error);
      this.interceptEnabled = !this.interceptEnabled;
    }
    this.updateInterceptBar();
    if (this.interceptEnabled) {
      await invoke('intercept_set_scopes', { interceptRequests: true, interceptResponses: true });
      this.startInterceptPolling();
    } else {
      this.stopInterceptPolling();
      this.interceptEntries = [];
      this.selectedInterceptId = null;
      this.renderIntercepted();
    }
  }

  startInterceptPolling() {
    this.stopInterceptPolling();
    const poll = async () => {
      try {
        this.interceptEntries = await invoke('intercept_list');
      } catch (error) {
        this.interceptEntries = [];
      }
      this.renderIntercepted();
    };
    poll();
    this.timer = setInterval(poll, 1000);
  }

  stopInterceptPolling() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  updateInterceptBar() {
    const btn = this.querySelector('#intercept-toggle');
    btn.textContent = this.interceptEnabled ? 'Intercept on' : 'Intercept off';
    btn.classList.toggle('active', this.interceptEnabled);
    btn.classList.toggle('inactive', !this.interceptEnabled);
    this.querySelector('#intercept-warning').style.display = this.interceptEnabled ? '' : 'none';
  }

  selectedInterceptEntry() {
    if (this.selectedInterceptId) {
      const entry = this.interceptEntries.find((e) => e.id === this.selectedInterceptId);
      if (entry) return entry;
    }
    return this.interceptEntries[0] || null;
  }

  async forwardRequest() {
    const entry = this.selectedInterceptEntry();
    if (!entry) return;
    try {
      await invoke('intercept_forward', { id: entry.id, edit: null });
    } catch (error) {
      showError('Forward: ' + error);
      return;
    }
    this.interceptEntries = this.interceptEntries.filter((e) => e.id !== entry.id);
    if (this.selectedInterceptId === entry.id) this.selectedInterceptId = null;
    this.renderIntercepted();
  }

  async dropRequest() {
    const entry = this.selectedInterceptEntry();
    if (!entry) return;
    try {
      await invoke('intercept_drop', { id: entry.id });
    } catch (error) {
      showError('Drop: ' + error);
      return;
    }
    this.interceptEntries = this.interceptEntries.filter((e) => e.id !== entry.id);
    if (this.selectedInterceptId === entry.id) this.selectedInterceptId = null;
    this.renderIntercepted();
  }

  async applyInterceptEdit() {
    const entry = this.selectedInterceptEntry();
    if (!entry) return;
    const q = (role) => this.viewer.querySelector('[data-role="' + role + '"]');
    let headers = entry.headers;
    try {
      const parsed = JSON.parse(q('edit-headers').value || '[]');
      if (Array.isArray(parsed)) {
        headers = parsed.map((h) => ({ name: String(h.name || ''), value: String(h.value || '') }));
      } else if (parsed && typeof parsed === 'object') {
        headers = Object.entries(parsed).map(([name, value]) => ({ name, value: String(value) }));
      }
    } catch (error) {
      showError('Headers must be valid JSON: ' + error);
      return;
    }
    let status = null;
    if (entry.kind === 'response') {
      const parsed = parseInt(q('edit-status').value, 10);
      status = Number.isNaN(parsed) ? entry.status : parsed;
    }
    const edit = {
      method: q('edit-method').value,
      url: q('edit-url').value,
      status,
      reason: entry.reason,
      headers,
      body: q('edit-body').value,
    };
    try {
      await invoke('intercept_forward', { id: entry.id, edit });
    } catch (error) {
      showError('Apply edits: ' + error);
      return;
    }
    this.interceptEntries = this.interceptEntries.filter((e) => e.id !== entry.id);
    if (this.selectedInterceptId === entry.id) this.selectedInterceptId = null;
    this.renderIntercepted();
  }

  renderIntercepted() {
    const info = this.querySelector('#intercept-request-info');
    const first = this.interceptEntries[0];
    const last = this.interceptEntries[this.interceptEntries.length - 1];
    const fingerprint = this.interceptEntries.length + ':' + (first ? first.id : '') + ':' + (last ? last.id : '');
    if (fingerprint === this._interceptFp) return;
    this._interceptFp = fingerprint;
    this.tbody.innerHTML = '';
    if (!this.interceptEntries.length) {
      info.textContent = 'No intercepted request';
      return;
    }
    info.textContent = this.interceptEntries.length + ' item(s) held';
    this.interceptEntries.forEach((f, i) => {
      const tr = document.createElement('tr');
      const type = 'HTTP';
      const direction = f.kind === 'response' ? '&rarr; Response' : '&rarr; Request';
      const status = f.kind === 'response' ? (f.status || '-') : '-';
      tr.innerHTML = `<td class="col-num">${i + 1}</td><td class="col-time">${formatTime(f.timestamp)}</td><td class="col-type">${type}</td><td class="col-direction">${direction}</td><td class="col-method method ${f.method}">${f.method}</td><td class="col-url" title="${f.url}">${f.url}</td><td class="col-status ${colorStatus(f.status || 0)}">${status}</td><td class="col-length">${f.body_len || 0}</td>`;
      tr.onclick = () => this.showInterceptDetail(f.id);
      this.tbody.appendChild(tr);
    });
  }

  async showInterceptDetail(id) {
    this.selectedInterceptId = id;
    let f;
    try {
      f = await invoke('intercept_detail', { id });
    } catch (error) {
      showError('Intercept detail: ' + error);
      return;
    }
    if (!f) {
      // Entry already forwarded/dropped since the last poll.
      this.selectedInterceptId = null;
      return;
    }
    const requestInfo = this.querySelector('#intercept-request-info');
    let host = '';
    try { host = new URL(f.url).host; } catch (error) {}
    requestInfo.textContent = (f.kind === 'response' ? 'Response from ' : 'Request to ') + host;

    let reqPath = f.url;
    try { const u = new URL(f.url); reqPath = u.pathname + u.search; } catch (error) {}
    const headers = formatHeaders(f.headers);
    const ct = contentTypeFromHeaders(f.headers);

    const reqMsg = buildMessage({
      method: f.method || 'GET', url: reqPath, headersText: headers,
      body: f.body || '', contentType: ct, date: f.timestamp,
    });
    let responseRaw = '(response not held)';
    let responsePretty = '(response not held)';
    let responsePrettyHtml = null;
    if (f.kind === 'response') {
      const respMsg = buildMessage({
        status: f.status || 0, reason: f.reason || '', headersText: headers,
        body: f.body || '', contentType: ct, date: f.timestamp,
      });
      responseRaw = respMsg.raw;
      responsePretty = respMsg.pretty;
      if (isJsonContentType(ct)) responsePrettyHtml = highlightJson(respMsg.pretty);
    }

    const sections = [
      {
        title: 'Request attributes',
        rows: [
          ['Method', f.method],
          ['URL', f.url],
          ['Status', f.status != null ? String(f.status) : '-'],
          ['Length', String(f.body_len || (f.body ? f.body.length : 0))],
        ],
      },
      { title: 'Query parameters', rows: parseQueryParams(f.url).map((p) => [p.name, p.value]) },
      { title: 'Body parameters', rows: parseBodyParams(ct, f.body || '').map((p) => [p.name, p.value]) },
      { title: 'Cookies', rows: parseCookies(f.headers, f.kind === 'response').map((c) => [c.name, c.value]) },
      { title: f.kind === 'response' ? 'Response headers' : 'Request headers', rows: f.headers.map((h) => [h.name, h.value]) },
    ];

    this.viewer.data = {
      requestRaw: reqMsg.raw,
      requestPretty: reqMsg.pretty,
      requestPrettyHtml: isJsonContentType(ct) ? highlightJson(reqMsg.pretty) : null,
      responseRaw,
      responsePretty,
      responsePrettyHtml,
      requestHex: toHex(f.body || ''),
      responseHex: f.kind === 'response' ? toHex(f.body || '') : '',
      responseRender: f.kind === 'response' ? (f.body || '<p>(empty response)</p>') : '<p>(response not held)</p>',
      inspectorSections: sections,
    };

    const q = (role) => this.viewer.querySelector('[data-role="' + role + '"]');
    q('edit-method').value = f.method;
    q('edit-url').value = f.url;
    q('edit-status-row').style.display = f.kind === 'response' ? '' : 'none';
    q('edit-status').value = f.status != null ? f.status : '';
    q('edit-headers').value = JSON.stringify(f.headers, null, 2);
    q('edit-body').value = f.body || '';
    this.hideEditPane();
  }

  showEditPane() {
    this.viewer.editOverlay.classList.add('active');
  }

  hideEditPane() {
    this.viewer.editOverlay.classList.remove('active');
  }
}

customElements.define('intercept-view', InterceptView);
