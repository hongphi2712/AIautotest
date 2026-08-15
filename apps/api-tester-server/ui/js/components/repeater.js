import {
  invoke, toHex, escapeHtml, showError, formatHeaders, parseHttpRequest, parseQueryParams,
  parseBodyParams, parseCookies, renderHttpWire, contentTypeFromHeaders, httpStartLine,
} from '../api.js';
import './inspector-panel.js';

const STATUS_REASONS = {
  200: 'OK', 201: 'Created', 202: 'Accepted', 204: 'No Content', 206: 'Partial Content',
  301: 'Moved Permanently', 302: 'Found', 303: 'See Other', 304: 'Not Modified', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
  408: 'Request Timeout', 409: 'Conflict', 410: 'Gone', 415: 'Unsupported Media Type', 422: 'Unprocessable Entity',
  429: 'Too Many Requests', 500: 'Internal Server Error', 501: 'Not Implemented', 502: 'Bad Gateway',
  503: 'Service Unavailable', 504: 'Gateway Timeout',
};

function statusReason(code) {
  return STATUS_REASONS[code] || '';
}

function tabName(method, path) {
  const short = path.length > 34 ? path.slice(0, 31) + '...' : path;
  return `${method} ${short}`;
}

function caretOffset(element) {
  const selection = window.getSelection();
  if (!selection.rangeCount) return 0;
  const range = selection.getRangeAt(0);
  const clone = range.cloneRange();
  clone.selectNodeContents(element);
  clone.setEnd(range.endContainer, range.endOffset);
  return clone.toString().length;
}

function setCaret(element, offset) {
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
  let remaining = offset;
  let node = walker.nextNode();
  let target = element;
  let pos = 0;
  while (node) {
    const length = node.textContent.length;
    if (remaining <= length) {
      target = node;
      pos = remaining;
      break;
    }
    remaining -= length;
    node = walker.nextNode();
  }
  const range = document.createRange();
  range.setStart(target, pos);
  range.collapse(true);
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
}

const TEMPLATE = `
  <div class="tab-bar">
    <div class="rep-tabs" id="tabs"></div>
    <button class="add-tab" id="add-tab" title="New tab">+</button>
    <div class="tab-tools">
      <input id="target" class="target" placeholder="Target">
      <button class="btn primary" id="send">Send</button>
    </div>
  </div>
  <div class="repeater-body">
    <div class="repeater-request">
      <div class="rv-header"><span class="rv-title">Request</span>
        <div class="subtabs" id="req-tabs">
          <button class="subtab active" data-reqtab="pretty">Pretty</button>
          <button class="subtab" data-reqtab="raw">Raw</button>
          <button class="subtab" data-reqtab="hex">Hex</button>
        </div>
      </div>
      <div class="http-editor" id="req-editor-wrap">
        <div class="http-line-nums" id="req-lines"></div>
        <pre class="http-body" id="req-editor" contenteditable="true" spellcheck="false"></pre>
      </div>
      <pre id="req-hex" class="http-body" hidden></pre>
      <div class="search-bar">
        <input type="search" id="search" placeholder="Search request...">
        <span id="search-count" class="muted"></span>
      </div>
      <div class="status-bar">
        <span id="status" class="muted">Ready</span>
        <span style="margin-left:auto"></span>
      </div>
    </div>
    <div class="repeater-response">
      <div class="rv-header"><span class="rv-title">Response</span>
        <div class="subtabs" id="resp-tabs">
          <button class="subtab active" data-resptab="pretty">Pretty</button>
          <button class="subtab" data-resptab="raw">Raw</button>
          <button class="subtab" data-resptab="hex">Hex</button>
          <button class="subtab" data-resptab="render">Render</button>
        </div>
      </div>
      <div class="resp-view">
        <pre id="resp-pretty" class="http-body"></pre>
        <pre id="resp-raw" class="http-body" hidden></pre>
        <pre id="resp-hex" class="http-body" hidden></pre>
        <iframe id="resp-render" class="render-frame" sandbox="" hidden></iframe>
      </div>
    </div>
    <inspector-panel id="inspector"></inspector-panel>
  </div>
`;

export class RepeaterView extends HTMLElement {
  connectedCallback() {
    this.innerHTML = TEMPLATE;
    this.tabs = [];
    this.activeTabId = null;
    this.editorMode = 'pretty';
    this.respMode = 'pretty';
    this.tabSeq = 0;
    this.targetEdited = false;

    this.reqEditor = this.querySelector('#req-editor');
    this.reqEditor.addEventListener('input', () => this.onEditorInput());
    this.reqEditor.addEventListener('scroll', () => {
      this.querySelector('#req-lines').scrollTop = this.reqEditor.scrollTop;
    });
    const target = this.querySelector('#target');
    target.addEventListener('input', () => { this.targetEdited = true; });
    target.addEventListener('focus', () => { this.targetEdited = true; });
    this.querySelector('#add-tab').addEventListener('click', () => this.newTab(''));
    this.querySelector('#send').addEventListener('click', () => this.send());
    this.querySelector('#search').addEventListener('input', (e) => this.applySearch(e.target.value));
    this.querySelector('#req-tabs').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-reqtab]');
      if (btn) this.setReqTab(btn.dataset.reqtab);
    });
    this.querySelector('#resp-tabs').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-resptab]');
      if (btn) this.setRespTab(btn.dataset.resptab);
    });

    this.newTab('');

    this.onLoad = (event) => {
      const flow = event.detail;
      this.newTab(buildRequestWire(flow));
      window.dispatchEvent(new CustomEvent('app:navigate', { detail: { view: 'repeater' } }));
    };
    window.addEventListener('app:repeater-load', this.onLoad);
  }

  disconnectedCallback() {
    window.removeEventListener('app:repeater-load', this.onLoad);
  }

  currentTab() {
    return this.tabs.find((tab) => tab.id === this.activeTabId) || null;
  }

  newTab(requestText) {
    const tab = {
      id: 'tab-' + (++this.tabSeq),
      name: 'New request',
      requestText: requestText || 'GET / HTTP/1.1\nHost: example.com\n\n',
      response: null,
    };
    this.tabs.push(tab);
    this.selectTab(tab.id);
  }

  selectTab(id) {
    if (this.currentTab()) {
      this.currentTab().requestText = this.reqEditor.textContent;
    }
    this.activeTabId = id;
    const tab = this.currentTab();
    this.renderTabs();
    this.reqEditor.textContent = tab.requestText;
    this.refreshEditor();
    this.renderResponse(tab.response);
    this.updateTarget();
    this.updateInspector();
  }

  /// Re-applies the current request view (highlighted editor, plain editor,
  /// or hex) to the freshly loaded tab content.
  refreshEditor() {
    if (this.editorMode === 'hex') {
      const parsed = parseHttpRequest(this.reqEditor.textContent);
      this.querySelector('#req-hex').textContent = toHex(parsed.body);
    } else {
      this.renderEditor();
      this.updateLineNumbers();
    }
  }

  closeTab(id) {
    const index = this.tabs.findIndex((tab) => tab.id === id);
    if (index === -1) return;
    this.tabs.splice(index, 1);
    if (!this.tabs.length) {
      this.newTab('');
      return;
    }
    const next = this.tabs[Math.max(0, index - 1)];
    this.selectTab(next.id);
  }

  renderTabs() {
    const container = this.querySelector('#tabs');
    container.innerHTML = '';
    this.tabs.forEach((tab) => {
      const btn = document.createElement('div');
      btn.className = 'rep-tab' + (tab.id === this.activeTabId ? ' active' : '');
      const label = document.createElement('span');
      label.className = 'rep-tab-label';
      label.textContent = tab.name;
      label.title = tab.requestText.split('\n')[0] || tab.name;
      const close = document.createElement('button');
      close.className = 'rep-tab-close';
      close.textContent = '\u00d7';
      close.addEventListener('click', (e) => {
        e.stopPropagation();
        this.closeTab(tab.id);
      });
      btn.appendChild(label);
      btn.appendChild(close);
      btn.addEventListener('click', () => this.selectTab(tab.id));
      container.appendChild(btn);
    });
  }

  renderEditor() {
    const text = this.reqEditor.textContent;
    if (this.editorMode === 'pretty') {
      this.reqEditor.innerHTML = renderHttpWire(text, 'request');
    } else {
      this.reqEditor.innerHTML = escapeHtml(text);
    }
  }

  onEditorInput() {
    const caret = caretOffset(this.reqEditor);
    const tab = this.currentTab();
    if (tab) tab.requestText = this.reqEditor.textContent;
    this.renderEditor();
    setCaret(this.reqEditor, caret);
    this.updateLineNumbers();
    this.updateTarget();
    this.scheduleInspectorUpdate();
  }

  scheduleInspectorUpdate() {
    clearTimeout(this._inspectorTimer);
    this._inspectorTimer = setTimeout(() => this.updateInspector(), 250);
  }

  setReqTab(mode) {
    if (this.currentTab()) {
      this.currentTab().requestText = this.reqEditor.textContent;
    }
    this.editorMode = mode;
    this.querySelectorAll('[data-reqtab]').forEach((b) => b.classList.toggle('active', b.dataset.reqtab === mode));
    const editorWrap = this.querySelector('#req-editor-wrap');
    const hexView = this.querySelector('#req-hex');
    if (mode === 'hex') {
      editorWrap.hidden = true;
      hexView.hidden = false;
      const parsed = parseHttpRequest(this.reqEditor.textContent);
      hexView.textContent = toHex(parsed.body);
    } else {
      editorWrap.hidden = false;
      hexView.hidden = true;
      this.renderEditor();
      this.updateLineNumbers();
    }
  }

  setRespTab(mode) {
    this.respMode = mode;
    this.querySelectorAll('[data-resptab]').forEach((b) => b.classList.toggle('active', b.dataset.resptab === mode));
    const ids = { pretty: 'resp-pretty', raw: 'resp-raw', hex: 'resp-hex', render: 'resp-render' };
    for (const key of Object.keys(ids)) {
      this.querySelector('#' + ids[key]).hidden = key !== mode;
    }
  }

  updateLineNumbers() {
    const count = this.reqEditor.textContent.split('\n').length;
    this.querySelector('#req-lines').textContent =
      Array.from({ length: count }, (_, i) => i + 1).join('\n');
  }

  updateTarget() {
    if (this.targetEdited) return;
    const parsed = parseHttpRequest(this.reqEditor.textContent);
    this.querySelector('#target').value = parsed.url;
  }

  applySearch(term) {
    const query = term.trim();
    const tab = this.currentTab();
    if (!tab) return;
    this.renderEditor();
    let count = 0;
    if (query) {
      const lower = query.toLowerCase();
      const walker = document.createTreeWalker(this.reqEditor, NodeFilter.SHOW_TEXT);
      const nodes = [];
      while (walker.nextNode()) nodes.push(walker.currentNode);
      nodes.forEach((node) => {
        const text = node.textContent;
        if (!text.toLowerCase().includes(lower)) return;
        const fragment = document.createDocumentFragment();
        let rest = text;
        while (true) {
          const idx = rest.toLowerCase().indexOf(lower);
          if (idx === -1) {
            fragment.appendChild(document.createTextNode(rest));
            break;
          }
          if (idx > 0) fragment.appendChild(document.createTextNode(rest.slice(0, idx)));
          const mark = document.createElement('mark');
          mark.className = 'search-hit';
          mark.textContent = rest.slice(idx, idx + query.length);
          fragment.appendChild(mark);
          count++;
          rest = rest.slice(idx + query.length);
        }
        node.parentNode.replaceChild(fragment, node);
      });
    }
    this.querySelector('#search-count').textContent = count
      ? count + ' highlight' + (count === 1 ? '' : 's')
      : '';
  }

  updateInspector() {
    const tab = this.currentTab();
    const panel = this.querySelector('#inspector');
    if (!tab) {
      panel.data = { sections: [] };
      return;
    }
    const parsed = parseHttpRequest(tab.requestText);
    const contentType = contentTypeFromHeaders(parsed.headers);
    const sections = [
      {
        title: 'Request attributes',
        rows: [
          ['Method', parsed.method],
          ['Path', parsed.path],
          ['Version', parsed.version],
          ['Host', parsed.headers.find((h) => h.name.toLowerCase() === 'host')?.value || '-'],
          ['Body length', String(parsed.body.length)],
        ],
      },
      { title: 'Query parameters', rows: parseQueryParams(parsed.url).map((p) => [p.name, p.value]) },
      { title: 'Body parameters', rows: parseBodyParams(contentType, parsed.body).map((p) => [p.name, p.value]) },
      { title: 'Cookies', rows: parseCookies(parsed.headers, false).map((c) => [c.name, c.value]) },
      { title: 'Headers', rows: parsed.headers.map((h) => [h.name, h.value]) },
    ];

    const response = tab.response;
    if (response) {
      const respCt = contentTypeFromHeaders(response.headers);
      sections.push({
        title: 'Response status',
        rows: [
          ['Status', String(response.status)],
          ['Length', String(response.body.length)],
          ['MIME', respCt || '-'],
        ],
      });
      sections.push({ title: 'Response headers', rows: response.headers });
      sections.push({
        title: 'Response cookies',
        rows: parseCookies(response.headers, true).map((c) => [c.name, c.value]),
      });
      sections.push({
        title: 'Response body parameters',
        rows: parseBodyParams(respCt, response.body).map((p) => [p.name, p.value]),
      });
    }
    panel.data = { sections };
  }

  async send() {
    const tab = this.currentTab();
    if (!tab) return;
    tab.requestText = this.reqEditor.textContent;
    const status = this.querySelector('#status');
    const parsed = parseHttpRequest(tab.requestText);
    // An explicitly edited Target overrides the URL derived from the request.
    let url = parsed.url;
    if (this.targetEdited) {
      const override = this.querySelector('#target').value.trim();
      if (override) url = override;
    }
    const headers = {};
    for (const header of parsed.headers) {
      const lower = header.name.toLowerCase();
      // Host/content-length/transfer-encoding are derived by reqwest from the
      // URL and body; sending a stale copy conflicts with the URL authority.
      if (lower === 'host' || lower === 'content-length' || lower === 'transfer-encoding') continue;
      headers[header.name] = header.value;
    }
    status.textContent = 'Sending...';
    try {
      const result = await invoke('repeater_send', {
        request: {
          method: parsed.method,
          url,
          headers,
          body: parsed.body,
        },
      });
      tab.response = {
        status: result.status,
        length: result.length,
        body: result.body,
        headers: result.headers || [],
      };
      tab.name = tabName(parsed.method, parsed.path);
      this.renderTabs();
      this.renderResponse(tab.response);
      this.updateInspector();
      status.textContent = result.error
        ? 'Request failed'
        : `HTTP ${result.status} | ${result.length} bytes`;
    } catch (error) {
      status.textContent = 'Request failed';
      showError('Repeater: ' + error);
    }
  }

  renderResponse(response) {
    const pretty = this.querySelector('#resp-pretty');
    const raw = this.querySelector('#resp-raw');
    const hex = this.querySelector('#resp-hex');
    const frame = this.querySelector('#resp-render');
    if (!response) {
      const placeholder = 'No response — send the request first.';
      pretty.innerHTML = escapeHtml(placeholder);
      raw.textContent = placeholder;
      hex.textContent = '';
      frame.srcdoc = '<p>(empty)</p>';
      return;
    }
    const headerText = response.headers.map(([name, value]) => `${name}: ${value}`).join('\n');
    const wire = `${httpStartLine({ status: response.status, reason: statusReason(response.status) })}\n${headerText}\n\n${response.body}`;
    pretty.innerHTML = renderHttpWire(wire, 'response');
    raw.textContent = wire;
    hex.textContent = toHex(response.body);
    const contentType = contentTypeFromHeaders(response.headers);
    frame.srcdoc = contentType.toLowerCase().includes('html')
      ? response.body
      : '<p>(response is not HTML)</p>';
  }
}

function buildRequestWire(flow) {
  const headers = formatHeaders(flow.request_headers || {});
  // Use the absolute URL so the scheme (http vs https) survives the round trip
  // into the Repeater; origin-form would default to plain http.
  return `${flow.method} ${flow.full_url} HTTP/1.1\n${headers}\n\n${flow.request_body || ''}`;
}

customElements.define('repeater-view', RepeaterView);
