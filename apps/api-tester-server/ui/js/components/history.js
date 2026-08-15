import {
  apiGet, formatStatus, colorStatus, formatTime, shortCookies, shortUrl, toHex,
  formatHeaders, showError, buildMessage, contentTypeFromHeaders, isJsonContentType, highlightJson,
  parseQueryParams, parseBodyParams,
} from '../api.js';
import './message-viewer.js';

const TEMPLATE = `
  <div class="logger-wrap">
    <div class="toolbar">
      <strong>HTTP history</strong>
      <select id="f-method"><option value="">All methods</option><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option><option>OPTIONS</option></select>
      <input id="f-host" placeholder="Filter host...">
      <input id="f-search" placeholder="Search path/host...">
      <button id="refresh">Refresh</button>
      <button id="to-repeater">Send to Repeater</button>
      <span id="count" class="muted" style="margin-left:auto">0 requests</span>
    </div>
    <div class="table-scroll" id="table-scroll">
      <table class="flows">
        <thead><tr>
          <th class="col-num">#</th><th class="col-host">Host</th><th class="col-method">Method</th><th class="col-url">URL</th><th class="col-status">Status</th><th class="col-length">Length</th><th class="col-mime">MIME</th><th class="col-cookies">Cookies</th><th class="col-time" data-sort="time">Time</th>
        </tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
    <div id="detail">
      <div id="detail-title" class="history-detail-bar">Select a request</div>
      <message-viewer id="viewer"></message-viewer>
    </div>
  </div>
`;

export class HistoryView extends HTMLElement {
  connectedCallback() {
    this.innerHTML = TEMPLATE;
    this.currentFlows = [];
    this.selectedFlow = null;
    this.sortKey = null;
    this.sortDir = 1;
    this.viewer = this.querySelector('#viewer');
    this.tbody = this.querySelector('#tbody');

    ['f-method', 'f-host', 'f-search'].forEach((id) => {
      const input = this.querySelector('#' + id);
      input.addEventListener('input', () => this.render());
      input.addEventListener('change', () => this.render());
    });
    this.querySelector('#refresh').addEventListener('click', () => this.loadFlows());
    this.querySelector('#to-repeater').addEventListener('click', () => this.sendSelectedToRepeater());
    this.querySelectorAll('th[data-sort]').forEach((th) => th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (this.sortKey !== key) { this.sortKey = key; this.sortDir = 1; }
      else if (this.sortDir === 1) { this.sortDir = -1; }
      else { this.sortKey = null; this.sortDir = 1; }
      this.render();
    }));

    window.addEventListener('app:subtab', (event) => {
      if (event.detail === 'http-history') this.loadFlows();
    });
    this.onWsFlow = (event) => {
      const flow = event.detail && event.detail.flow;
      if (!flow) return;
      if (this.currentFlows.some((f) => f.id === flow.id)) return;
      this.currentFlows.unshift(flow);
      this.render();
    };
    window.addEventListener('app:ws-flow', this.onWsFlow);

    this.loadFlows();
    this.timer = setInterval(() => this.loadFlows(), 2000);
  }

  disconnectedCallback() {
    if (this.timer) clearInterval(this.timer);
    window.removeEventListener('app:ws-flow', this.onWsFlow);
  }

  async loadFlows() {
    if (this.offsetParent === null) return;
    try {
      this.currentFlows = await apiGet('/api/flows');
      this.render();
    } catch (error) {
      showError('Dashboard API unavailable: ' + error);
    }
  }

  sortValue(f, key) {
    if (key === 'time') return new Date(f.timestamp).getTime();
    return '';
  }

  sorted(flows) {
    if (!this.sortKey) return flows;
    return [...flows].sort((a, b) => (this.sortValue(a, this.sortKey) < this.sortValue(b, this.sortKey) ? -1 : 1) * this.sortDir);
  }

  filtered() {
    const method = this.querySelector('#f-method').value.toLowerCase();
    const host = this.querySelector('#f-host').value.trim().toLowerCase();
    const q = this.querySelector('#f-search').value.trim().toLowerCase();
    return this.currentFlows.filter((f) =>
      (!method || f.method.toLowerCase() === method) &&
      (!host || f.host.toLowerCase().includes(host)) &&
      (!q || f.host.toLowerCase().includes(q) || f.full_url.toLowerCase().includes(q))
    );
  }

  render() {
    const scroll = this.querySelector('#table-scroll');
    if (!scroll || scroll.offsetParent === null) return;
    const flows = this.sorted(this.filtered());
    // Skip the rebuild (2s poll) when nothing changed: same row count and the
    // same first/last rows (sort + filter changes alter at least one of them).
    const fingerprint = flows.length + ':' + (flows[0]?.id || '') + ':' + (flows[flows.length - 1]?.id || '');
    if (fingerprint === this._renderFingerprint) return;
    this._renderFingerprint = fingerprint;
    this.querySelector('#count').textContent = flows.length + ' requests';
    this.tbody.innerHTML = '';
    if (!flows.length) return;
    const fragment = document.createDocumentFragment();
    for (let i = 0; i < flows.length; i++) {
      const f = flows[i];
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="col-num">${i + 1}</td>
        <td class="col-host">${f.host}</td>
        <td class="col-method method ${f.method}">${f.method}</td>
        <td class="col-url" title="${f.full_url}">${shortUrl(f)}</td>
        <td class="col-status ${colorStatus(f.status)}">${formatStatus(f.status)}</td>
        <td class="col-length">${f.length}</td>
        <td class="col-mime">${f.content_type || '-'}</td>
        <td class="col-cookies">${shortCookies(f.cookies)}</td>
        <td class="col-time" title="${f.timestamp}">${formatTime(f.timestamp)}</td>`;
      tr.onclick = () => {
        this.querySelectorAll('#tbody tr').forEach((r) => r.classList.remove('selected'));
        tr.classList.add('selected');
        this.showDetail(f.id);
      };
      fragment.appendChild(tr);
    }
    this.tbody.appendChild(fragment);
  }

  async showDetail(id) {
    try {
      const f = await apiGet('/api/flows/' + encodeURIComponent(id));
      if (!f) return;
      this.selectedFlow = f;
      this.querySelector('#detail-title').textContent = f.method + ' ' + f.full_url + '  |  HTTP ' + formatStatus(f.status) + '  |  ' + f.length + ' chars';

      const query = f.path.includes('?') ? f.path.split('?')[1] : '';
      const requestHeaders = formatHeaders(f.request_headers);
      const responseHeaders = formatHeaders(f.response_headers);
      const reqCt = contentTypeFromHeaders(f.request_headers);
      const respCt = contentTypeFromHeaders(f.response_headers);
      const reqMsg = buildMessage({
        method: f.method, url: f.path, headersText: requestHeaders,
        body: f.request_body || '', contentType: reqCt, date: f.timestamp,
      });
      const respMsg = buildMessage({
        status: f.status, headersText: responseHeaders,
        body: f.response_body || '', contentType: respCt, date: f.timestamp,
      });

      const cookies = Object.entries(f.request_cookie_values || {})
        .concat(Object.entries(f.response_cookie_values || {}));
      const sections = [
        {
          title: 'Request attributes',
          rows: [
            ['Method', f.method],
            ['Path', f.path],
            ['Status', formatStatus(f.status)],
            ['Length', String(f.length)],
            ['MIME', f.content_type || '-'],
          ],
        },
        { title: 'Query parameters', rows: parseQueryParams(f.full_url).map((p) => [p.name, p.value]) },
        { title: 'Body parameters', rows: parseBodyParams(reqCt, f.request_body || '').map((p) => [p.name, p.value]) },
        { title: 'Cookies', rows: cookies },
        { title: 'Request headers', rows: Object.entries(f.request_headers || {}) },
        { title: 'Response headers', rows: Object.entries(f.response_headers || {}) },
      ];

      this.viewer.data = {
        requestRaw: reqMsg.raw,
        requestPretty: reqMsg.pretty,
        requestPrettyHtml: isJsonContentType(reqCt) ? highlightJson(reqMsg.pretty) : null,
        responseRaw: respMsg.raw,
        responsePretty: respMsg.pretty,
        responsePrettyHtml: isJsonContentType(respCt) ? highlightJson(respMsg.pretty) : null,
        requestHex: toHex(f.request_body || ''),
        responseHex: toHex(f.response_body || ''),
        responseRender: f.response_body || '<p>(empty response)</p>',
        inspectorSections: sections,
      };
      const sbSelection = document.getElementById('sb-selection');
      if (sbSelection) sbSelection.textContent = 'Selected: ' + f.method + ' ' + f.path;
    } catch (error) {
      showError('Could not load flow: ' + error);
    }
  }

  sendSelectedToRepeater() {
    if (!this.selectedFlow) { showError('Select a request in HTTP history first.'); return; }
    window.dispatchEvent(new CustomEvent('app:repeater-load', { detail: this.selectedFlow }));
  }
}

customElements.define('history-view', HistoryView);
