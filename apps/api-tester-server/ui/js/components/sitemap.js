import {
  apiDeleteBody, apiGet, apiPut, buildMessage, contentTypeFromHeaders,
  formatHeaders, formatStatus, highlightJson, isJsonContentType, parseQueryParams,
  showError, toHex,
} from '../api.js';
import { getSessions, getActiveSessionId, subscribe } from '../store.js';
import './message-viewer.js';

const COLORS = new Set(['red', 'orange', 'yellow', 'green', 'cyan', 'blue', 'pink', 'magenta', 'gray']);
const COLOR_OPTIONS = [...COLORS]
  .map((color) => `<option value="${color}">${color}</option>`)
  .join('');

const TEMPLATE = `
  <div class="sitemap-wrap">
    <div class="toolbar">
      <strong>Site map</strong>
      <select id="sm-session"><option value="">All sessions</option></select>
      <select id="sm-method">
        <option value="">All methods</option>
        <option>GET</option><option>POST</option><option>PUT</option>
        <option>DELETE</option><option>PATCH</option><option>OPTIONS</option><option>HEAD</option>
      </select>
      <select id="sm-status">
        <option value="">All statuses</option>
        <option value="2">2xx</option><option value="3">3xx</option>
        <option value="4">4xx</option><option value="5">5xx</option><option value="0">N/A</option>
      </select>
      <input id="sm-host" placeholder="Filter host..." aria-label="Filter host">
      <input id="sm-search" placeholder="Search endpoint..." aria-label="Search endpoint">
      <label class="sm-scope-toggle"><input type="checkbox" id="sm-in-scope" disabled> In scope</label>
      <button id="sm-expand">Expand</button>
      <button id="sm-collapse">Collapse</button>
      <button id="sm-refresh">Refresh</button>
      <span id="sm-count" class="muted sm-count">0 endpoints</span>
    </div>

    <div class="sitemap-layout">
      <div id="sm-tree" class="sitemap-tree" tabindex="0"></div>
      <div class="sitemap-detail">
        <div class="sitemap-detail-tabs">
          <button data-panel="request" class="active">Request</button>
          <button data-panel="response">Response</button>
          <button data-panel="details">Details</button>
        </div>
        <div id="sm-pane-request" class="sitemap-message-pane active"></div>
        <div id="sm-pane-response" class="sitemap-message-pane"></div>
        <div id="sm-pane-details" class="sitemap-details-pane"></div>
        <div id="sm-empty-detail" class="empty sm-empty-detail">
          <div class="big">◎</div><h3>Select an endpoint</h3>
          <p>Choose a leaf node to inspect its latest request and response.</p>
        </div>
      </div>
    </div>

    <div id="sm-context" class="sitemap-context" hidden></div>

    <div id="sm-modal" class="sitemap-modal-overlay" hidden>
      <div class="sitemap-modal">
        <div class="sitemap-modal-head"><strong>Edit annotation</strong><button id="sm-annotation-close">×</button></div>
        <label class="sm-field">Highlight
          <select id="sm-annotation-color">
            <option value="">None</option>
            ${COLOR_OPTIONS}
          </select>
        </label>
        <label class="sm-field">Comment<textarea id="sm-annotation-comment" rows="5"></textarea></label>
        <div class="sitemap-modal-actions">
          <button id="sm-annotation-cancel">Cancel</button>
          <button id="sm-annotation-save" class="primary">Save</button>
        </div>
      </div>
    </div>
  </div>
`;

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function regexMatches(patterns, value) {
  if (!patterns || !patterns.length) return false;
  return patterns.some((pattern) => {
    try { return new RegExp(pattern, 'u').test(value); } catch { return false; }
  });
}

function matchesScope(scope, host, path) {
  if (!scope) return true;
  const pathNoQuery = path.split('?')[0];
  if (regexMatches(scope.exclude_hosts, host)) return false;
  if ((scope.include_hosts || []).length && !regexMatches(scope.include_hosts, host)) return false;
  if (regexMatches(scope.exclude_paths, pathNoQuery)) return false;
  if ((scope.include_paths || []).length && !regexMatches(scope.include_paths, pathNoQuery)) return false;
  return true;
}

function statusBucket(code) {
  return code >= 200 && code < 300 ? '2' : code >= 300 && code < 400 ? '3'
    : code >= 400 && code < 500 ? '4' : code >= 500 ? '5' : '0';
}

export class SitemapView extends HTMLElement {
  connectedCallback() {
    this.innerHTML = TEMPLATE;
    this.tree = { sites: [] };
    this.scope = null;
    this.expanded = new Set();
    this.selectedKey = null;
    this.selectedEndpoint = null;
    this.contextNode = null;
    this.annotationNode = null;
    this.flowCache = new Map();

    this.viewer = document.createElement('message-viewer');
    this.querySelector('#sm-pane-request').appendChild(this.viewer);
    this.showPanel('request');

    ['#sm-method', '#sm-host', '#sm-search'].forEach((id) => {
      const input = this.querySelector(id);
      input.addEventListener('input', () => this.renderTree());
      input.addEventListener('change', () => this.renderTree());
    });
    this.querySelector('#sm-status').addEventListener('change', () => this.renderTree());
    this.querySelector('#sm-in-scope').addEventListener('change', (event) => {
      if (!this.scope) event.target.checked = false;
      this.renderTree();
    });
    this.querySelector('#sm-expand').addEventListener('click', () => this.setAllExpanded(true));
    this.querySelector('#sm-collapse').addEventListener('click', () => this.setAllExpanded(false));
    this.querySelector('#sm-refresh').addEventListener('click', () => this.load());
    this.querySelector('#sm-session').addEventListener('change', () => this.load());

    this.querySelectorAll('.sitemap-detail-tabs button').forEach((tab) => {
      tab.addEventListener('click', () => this.showPanel(tab.dataset.panel));
    });

    this.querySelector('#sm-tree').addEventListener('click', (event) => {
      const row = event.target.closest('[data-key]');
      if (!row) return;
      const key = row.dataset.key;
      if (event.target.closest('.sm-caret')) this.toggleExpanded(key);
      else if (row.dataset.endpoint === 'true') this.selectEndpoint(key);
      else this.toggleExpanded(key);
    });
    this.querySelector('#sm-tree').addEventListener('contextmenu', (event) => {
      const row = event.target.closest('[data-node]');
      if (!row) return;
      event.preventDefault();
      this.openContextMenu(event.clientX, event.clientY, JSON.parse(row.dataset.node));
    });

    window.addEventListener('click', this.closeContextMenu = () => this.hideContextMenu());
    window.addEventListener('blur', this.closeContextMenu);
    window.addEventListener('keydown', this.onGlobalKey = (event) => {
      if (event.key !== 'Escape') return;
      this.hideContextMenu();
      this.closeAnnotationModal();
    });

    this.querySelector('#sm-context').addEventListener('click', (event) => {
      const item = event.target.closest('[data-action]');
      if (item) this.handleContextAction(item.dataset.action);
    });
    this.querySelector('#sm-annotation-close').addEventListener('click', () => this.closeAnnotationModal());
    this.querySelector('#sm-annotation-cancel').addEventListener('click', () => this.closeAnnotationModal());
    this.querySelector('#sm-annotation-save').addEventListener('click', () => this.saveAnnotation());
    this.querySelector('#sm-modal').addEventListener('click', (event) => {
      if (event.target === this.querySelector('#sm-modal')) this.closeAnnotationModal();
    });

    this.onWsFlow = () => this.scheduleReload();
    this.onWsCleared = () => {
      clearTimeout(this.reloadTimer);
      this.tree = { sites: [] };
      this.selectedKey = null;
      this.selectedEndpoint = null;
      this.expanded.clear();
      this.flowCache.clear();
      this.clearDetail();
      this.renderTree();
    };
    this.onNavigate = (event) => {
      if (event.detail?.view === 'target') this.load();
    };
    window.addEventListener('app:ws-flow', this.onWsFlow);
    window.addEventListener('app:ws-flows-cleared', this.onWsCleared);
    window.addEventListener('app:navigate', this.onNavigate);

    this._unsubscribe = subscribe(() => {
      this.renderSessionOptions();
      this.load();
    });

    this.renderSessionOptions();
    this.load();
  }

  disconnectedCallback() {
    clearTimeout(this.reloadTimer);
    if (this._unsubscribe) this._unsubscribe();
    window.removeEventListener('click', this.closeContextMenu);
    window.removeEventListener('blur', this.closeContextMenu);
    window.removeEventListener('keydown', this.onGlobalKey);
    window.removeEventListener('app:ws-flow', this.onWsFlow);
    window.removeEventListener('app:ws-flows-cleared', this.onWsCleared);
    window.removeEventListener('app:navigate', this.onNavigate);
  }

  scheduleReload() {
    clearTimeout(this.reloadTimer);
    this.reloadTimer = setTimeout(() => this.load(), 500);
  }

  async load() {
    try {
      const previousSampleId = this.selectedEndpoint?.node?.sample_flow_id;
      const sessionId = this.querySelector('#sm-session')?.value || '';
      const qs = sessionId ? '?session_id=' + encodeURIComponent(sessionId) : '';
      const [tree, scope] = await Promise.all([
        apiGet('/api/sitemap' + qs),
        this.scope ? Promise.resolve(null) : apiGet('/api/scope'),
      ]);
      if (scope) {
        this.scope = scope;
        this.querySelector('#sm-in-scope').disabled = !scope;
      }
      this.tree = tree || { sites: [] };
      if (!this.expanded.size && this.tree.sites.length) {
        this.expanded.add(this.siteKey(this.tree.sites[0]));
      }
      this.renderTree();
      if (this.selectedKey) {
        const selected = this.findEndpoint(this.selectedKey);
        if (!selected) {
          this.selectedKey = null;
          this.selectedEndpoint = null;
          this.clearDetail();
        } else if (selected.node.sample_flow_id !== previousSampleId) {
          await this.selectEndpoint(this.selectedKey);
        }
      }
    } catch (error) {
      this.querySelector('#sm-tree').innerHTML = '<p class="muted sm-notice">Could not load site map.</p>';
      showError('Site map unavailable: ' + error.message);
    }
  }

  siteKey(site) { return `site:${site.scheme}:${site.host}`; }
  dirKey(site, node) { return `dir:${site.scheme}:${site.host}:${node.path}`; }
  endpointKey(site, node) { return `endpoint:${site.scheme}:${site.host}:${node.path}`; }

  setAllExpanded(expand) {
    this.expanded.clear();
    if (!expand) { this.renderTree(); return; }
    for (const site of this.tree.sites || []) {
      this.expanded.add(this.siteKey(site));
      const walk = (nodes) => nodes.forEach((node) => {
        if (node.kind === 'dir') {
          this.expanded.add(this.dirKey(site, node));
          walk(node.children || []);
        }
      });
      walk(site.children || []);
    }
    this.renderTree();
  }

  toggleExpanded(key) {
    if (this.expanded.has(key)) this.expanded.delete(key);
    else this.expanded.add(key);
    this.renderTree();
  }

  endpointMatches(site, node) {
    const method = this.querySelector('#sm-method').value.toUpperCase();
    const status = this.querySelector('#sm-status').value;
    const host = this.querySelector('#sm-host').value.trim().toLowerCase();
    const search = this.querySelector('#sm-search').value.trim().toLowerCase();
    const inScopeOnly = this.querySelector('#sm-in-scope').checked;

    if (method && !node.methods.includes(method)) return false;
    if (status && !node.statuses.some((code) => statusBucket(code) === status)) return false;
    if (host && !site.host.toLowerCase().includes(host)) return false;
    if (search) {
      const haystack = [node.path, ...node.methods, ...node.content_types].join(' ').toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    if (inScopeOnly && !matchesScope(this.scope, site.host, node.path)) return false;
    return true;
  }

  filterNodes(nodes, site) {
    const result = [];
    for (const node of nodes) {
      if (node.kind === 'dir') {
        const children = this.filterNodes(node.children || [], site);
        if (children.length) result.push({ ...node, children });
      } else if (this.endpointMatches(site, node)) {
        result.push(node);
      }
    }
    return result;
  }

  filteredTree() {
    const hostFilter = this.querySelector('#sm-host').value.trim().toLowerCase();
    const sites = [];
    let count = 0;
    for (const site of this.tree.sites || []) {
      if (hostFilter && !site.host.toLowerCase().includes(hostFilter)) continue;
      const children = this.filterNodes(site.children || [], site);
      if (!children.length) continue;
      count += this.countEndpoints(children);
      sites.push({ ...site, children });
    }
    return { sites, count };
  }

  countEndpoints(nodes) {
    return nodes.reduce((total, node) => node.kind === 'endpoint'
      ? total + 1
      : total + this.countEndpoints(node.children || []), 0);
  }

  renderSessionOptions() {
    const select = this.querySelector('#sm-session');
    if (!select) return;
    const sessions = getSessions();
    const activeId = getActiveSessionId();
    const current = select.value;
    const hadUserSelection = select.dataset.userSelected === '1';
    select.innerHTML = '<option value="">All sessions</option>';
    sessions.forEach((s) => {
      const opt = document.createElement('option');
      const isActive = s.id === activeId;
      const dot = isActive ? '\u25cf ' : '\u25cb ';
      opt.value = s.id;
      opt.textContent = dot + (s.name || s.id.slice(0, 8)) + ' (' + (s.flow_count || 0) + ' flows)';
      if (isActive) opt.style.fontWeight = '600';
      select.appendChild(opt);
    });
    if (current && sessions.some((s) => s.id === current)) {
      select.value = current;
    } else if (hadUserSelection && current === '') {
      select.value = '';
    } else {
      select.value = '';
    }
    if (!select.dataset.bound) {
      select.addEventListener('change', () => { select.dataset.userSelected = '1'; });
      select.dataset.bound = '1';
    }
  }

  renderTree() {
    const container = this.querySelector('#sm-tree');
    const { sites, count } = this.filteredTree();
    this.querySelector('#sm-count').textContent = `${count} endpoint${count === 1 ? '' : 's'}`;
    container.innerHTML = '';
    if (!sites.length) {
      container.innerHTML = '<p class="muted sm-notice">No matching endpoints. Start the proxy or adjust filters.</p>';
      return;
    }

    const fragment = document.createDocumentFragment();
    for (const site of sites) fragment.appendChild(this.createSiteElement(site));
    container.appendChild(fragment);
  }

  createSiteElement(site) {
    const expanded = this.expanded.has(this.siteKey(site));
    const item = document.createElement('div');
    item.className = 'sm-item';
    item.innerHTML = `
      <div class="sm-row site ${expanded ? 'expanded' : ''}" data-key="${this.escapeHtml(this.siteKey(site))}"
           data-node='${this.escapeHtml(JSON.stringify({ type: 'host', host: site.host }))}'>
        <span class="sm-caret">${expanded ? '▾' : '▸'}</span>
        <span class="sm-icon">${site.scheme === 'https' ? '🔒' : '🌐'}</span>
        <span class="sm-name">${this.escapeHtml(`${site.scheme}://${site.host}`)}</span>
      </div>`;
    const children = document.createElement('div');
    children.className = 'sm-children';
    if (expanded) for (const node of site.children || []) children.appendChild(this.createNodeElement(site, node, 1));
    item.appendChild(children);
    return item;
  }

  createNodeElement(site, node, depth) {
    const item = document.createElement('div');
    item.className = 'sm-item';
    if (node.kind === 'dir') {
      const key = this.dirKey(site, node);
      const expanded = this.expanded.has(key);
      item.innerHTML = `
        <div class="sm-row dir depth-${depth} ${expanded ? 'expanded' : ''}" data-key="${this.escapeHtml(key)}"
             data-node='${this.escapeHtml(JSON.stringify({ type: 'path', host: site.host, path: node.path }))}'>
          <span class="sm-caret">${expanded ? '▾' : '▸'}</span>
          <span class="sm-folder">📁</span>
          <span class="sm-name">${this.escapeHtml(node.name)}</span>
          <span class="muted sm-meta">${this.countEndpoints(node.children || [])}</span>
        </div>`;
      if (expanded) {
        const children = document.createElement('div');
        children.className = 'sm-children';
        for (const child of node.children || []) children.appendChild(this.createNodeElement(site, child, depth + 1));
        item.appendChild(children);
      }
      return item;
    }

    const key = this.endpointKey(site, node);
    const selected = this.selectedKey === key ? ' selected' : '';
    const annotationColor = COLORS.has(node.annotation?.color) ? node.annotation.color : '';
    const methods = node.methods.map((method) => `<span class="sm-method ${this.escapeHtml(method)}">${this.escapeHtml(method)}</span>`).join('');
    const statuses = node.statuses.map((code) => `<span class="sm-dot status-${statusBucket(code)}" title="HTTP ${formatStatus(code)}"></span>`).join('');
    item.innerHTML = `
      <div class="sm-row endpoint depth-${depth}${selected}${annotationColor ? ' annotated' : ''}"
           data-key="${this.escapeHtml(key)}" data-endpoint="true"
           data-node='${this.escapeHtml(JSON.stringify({
             type: 'endpoint', host: site.host, path: node.path, scheme: site.scheme, node,
           }))}'>
        <span class="sm-annotation-bar" style="${annotationColor ? `background:${annotationColor}` : ''}"></span>
        <span class="sm-endpoint-main">
          <span class="sm-methods">${methods}</span>
          <span class="sm-name" title="${this.escapeHtml(node.path)}">${this.escapeHtml(node.name)}</span>
        </span>
        <span class="sm-right">
          ${statuses}
          ${node.has_params ? '<span class="sm-param" title="Has query parameters">?</span>' : ''}
          ${node.annotation?.comment ? '<span class="sm-comment" title="' + this.escapeHtml(node.annotation.comment) + '">💬</span>' : ''}
          <span class="muted sm-meta">${node.count}</span>
        </span>
      </div>`;
    return item;
  }

  async selectEndpoint(key) {
    const found = this.findEndpoint(key);
    if (!found) return;
    this.selectedKey = key;
    this.selectedEndpoint = found;
    this.renderTree();
    try {
      const flowId = found.node.sample_flow_id;
      let flow = this.flowCache.get(flowId);
      if (!flow) {
        flow = await apiGet('/api/flows/' + encodeURIComponent(flowId));
        this.flowCache.set(flowId, flow);
        if (this.flowCache.size > 100) {
          const firstKey = this.flowCache.keys().next().value;
          this.flowCache.delete(firstKey);
        }
      }
      this.renderDetail(found, flow);
    } catch (error) {
      showError('Could not load flow: ' + error.message);
    }
  }

  findEndpoint(key, nodes = this.tree.sites || [], site = null) {
    for (const currentSite of nodes) {
      const activeSite = site || currentSite;
      const stack = [...(currentSite.children || [])];
      while (stack.length) {
        const node = stack.pop();
        if (node.kind === 'endpoint' && this.endpointKey(activeSite, node) === key) {
          return { site: activeSite, node };
        }
        for (const child of node.children || []) stack.push(child);
      }
    }
    return null;
  }

  renderDetail({ site, node }, flow) {
    this.querySelector('#sm-empty-detail').hidden = true;
    const requestHeaders = formatHeaders(flow.request_headers);
    const responseHeaders = formatHeaders(flow.response_headers);
    const reqType = contentTypeFromHeaders(flow.request_headers);
    const respType = contentTypeFromHeaders(flow.response_headers);
    const request = buildMessage({
      method: flow.method, url: flow.path, headersText: requestHeaders,
      body: flow.request_body || '', contentType: reqType, date: flow.timestamp,
    });
    const response = buildMessage({
      status: flow.status, headersText: responseHeaders,
      body: flow.response_body || '', contentType: respType, date: flow.timestamp,
    });
    this.viewer.data = {
      requestRaw: request.raw, requestPretty: request.pretty,
      requestPrettyHtml: isJsonContentType(reqType) ? highlightJson(request.pretty) : null,
      responseRaw: response.raw, responsePretty: response.pretty,
      responsePrettyHtml: isJsonContentType(respType) ? highlightJson(response.pretty) : null,
      requestHex: toHex(flow.request_body || ''), responseHex: toHex(flow.response_body || ''),
      responseRender: flow.response_body || '<p>(empty response)</p>',
      inspectorSections: [{
        title: 'Endpoint',
        rows: [
          ['Host', site.host], ['Path', node.path], ['Methods', node.methods.join(', ')],
          ['Statuses', node.statuses.join(', ')], ['Count', String(node.count)],
        ],
      }],
    };
    this.showPanel('request');

    const details = [
      ['Scheme', site.scheme], ['Host', site.host], ['Path', node.path],
      ['Methods', node.methods.join(', ')], ['Statuses', node.statuses.map(formatStatus).join(', ')],
      ['Content types', node.content_types.join(', ') || '-'], ['Captures', String(node.count)],
      ['Last seen', new Date(node.last_seen).toLocaleString()],
      ['Query parameters', String(parseQueryParams(flow.full_url).length)],
      ['Comment', node.annotation?.comment || '-'], ['Highlight', node.annotation?.color || '-'],
    ];
    this.querySelector('#sm-pane-details').innerHTML = `<dl class="sm-details">${
      details.map(([name, value]) => `<dt>${this.escapeHtml(name)}</dt><dd>${this.escapeHtml(value)}</dd>`).join('')
    }</dl>`;
  }

  clearDetail() {
    this.viewer.data = {};
    this.querySelector('#sm-pane-details').innerHTML = '';
    this.querySelector('#sm-empty-detail').hidden = false;
    this.showPanel('request');
  }

  showPanel(panelName) {
    this.querySelectorAll('.sitemap-detail-tabs button').forEach((tab) => {
      tab.classList.toggle('active', tab.dataset.panel === panelName);
    });
    this.querySelector('#sm-pane-request').classList.toggle('active', panelName === 'request');
    this.querySelector('#sm-pane-response').classList.toggle('active', panelName === 'response');
    this.querySelector('#sm-pane-details').classList.toggle('active', panelName === 'details');
    const messagePane = this.querySelector(panelName === 'response' ? '#sm-pane-response' : '#sm-pane-request');
    if (this.viewer.parentElement !== messagePane) messagePane.appendChild(this.viewer);
    this.viewer.classList.toggle('hide-response', panelName === 'request');
    this.viewer.classList.toggle('hide-request', panelName === 'response');
  }

  openContextMenu(x, y, contextNode) {
    this.contextNode = contextNode;
    const menu = this.querySelector('#sm-context');
    const items = [];
    items.push({ action: 'add-host', label: 'Add host to scope' });
    items.push({ action: 'remove-host', label: 'Exclude host from scope' });
    if (contextNode.type !== 'host') items.push({ action: 'add-path', label: 'Add path to scope' });
    if (contextNode.type !== 'host') items.push({ action: 'remove-path', label: 'Remove path from scope' });
    if (contextNode.type === 'endpoint') {
      items.push({ action: 'annotate', label: 'Ghi chú' });
      items.push({ action: 'repeater', label: 'Mở trong Repeater' });
    }
    menu.innerHTML = items.map((item) =>
      `<button data-action="${item.action}">${this.escapeHtml(item.label)}</button>`).join('');
    menu.hidden = false;
    const rect = menu.getBoundingClientRect();
    menu.style.left = Math.min(x, window.innerWidth - rect.width - 8) + 'px';
    menu.style.top = Math.min(y, window.innerHeight - rect.height - 8) + 'px';
  }

  hideContextMenu() {
    const menu = this.querySelector('#sm-context');
    if (menu) menu.hidden = true;
  }

  async handleContextAction(action) {
    const target = this.contextNode;
    this.hideContextMenu();
    if (!target) return;
    if (action === 'annotate') { this.openAnnotationModal(target); return; }
    if (action === 'repeater') {
      await this.sendToRepeater(target);
      return;
    }
    await this.updateScopeRules(action, target);
  }

  async updateScopeRules(action, target) {
    if (!this.scope) { showError('Scope is unavailable.'); return; }
    const scope = structuredClone(this.scope);
    ['include_hosts', 'exclude_hosts', 'include_paths', 'exclude_paths'].forEach((key) => {
      scope[key] = scope[key] || [];
    });
    const exactHost = escapeRegExp(target.host);
    const exactPath = target.path ? escapeRegExp(target.path) : null;

    if (action === 'add-host') {
      scope.exclude_hosts = scope.exclude_hosts.filter((value) => value !== exactHost);
      if (!scope.include_hosts.includes(exactHost)) scope.include_hosts.push(exactHost);
    } else if (action === 'remove-host') {
      scope.include_hosts = scope.include_hosts.filter((value) => value !== exactHost);
      if (!scope.exclude_hosts.includes(exactHost)) scope.exclude_hosts.push(exactHost);
    } else if (action === 'add-path') {
      if (!scope.include_hosts.includes(exactHost)) scope.include_hosts.push(exactHost);
      scope.exclude_paths = scope.exclude_paths.filter((value) => value !== exactPath);
      if (!scope.include_paths.includes(exactPath)) scope.include_paths.push(exactPath);
    } else if (action === 'remove-path') {
      scope.include_paths = scope.include_paths.filter((value) => value !== exactPath);
      if (!scope.exclude_paths.includes(exactPath)) scope.exclude_paths.push(exactPath);
    }
    try {
      this.scope = await apiPut('/api/scope', scope);
      this.renderTree();
    } catch (error) {
      showError('Could not update scope: ' + error.message);
    }
  }

  openAnnotationModal(target) {
    this.annotationNode = target;
    const annotation = target.node.annotation || {};
    this.querySelector('#sm-annotation-color').value = annotation.color || '';
    this.querySelector('#sm-annotation-comment').value = annotation.comment || '';
    this.querySelector('#sm-modal').hidden = false;
    this.querySelector('#sm-annotation-comment').focus();
  }

  closeAnnotationModal() {
    this.annotationNode = null;
    const modal = this.querySelector('#sm-modal');
    if (modal) modal.hidden = true;
  }

  async saveAnnotation() {
    if (!this.annotationNode?.node) return;
    const key = `${this.annotationNode.scheme}://${this.annotationNode.host}${this.annotationNode.path}`;
    const comment = this.querySelector('#sm-annotation-comment').value.trim();
    const color = this.querySelector('#sm-annotation-color').value;
    try {
      if (!comment && !color) await apiDeleteBody('/api/sitemap/annotations', { key });
      else await apiPut('/api/sitemap/annotations', { key, comment: comment || null, color: color || null });
      this.annotationNode.node.annotation = comment || color ? { comment: comment || null, color: color || null } : null;
      this.closeAnnotationModal();
      this.renderTree();
    } catch (error) {
      showError('Could not save annotation: ' + error.message);
    }
  }

  async sendToRepeater(target) {
    const flowId = target?.node?.sample_flow_id || this.selectedEndpoint?.node?.sample_flow_id;
    if (!flowId) { showError('Select an endpoint first.'); return; }
    try {
      const flow = await apiGet('/api/flows/' + encodeURIComponent(flowId));
      window.dispatchEvent(new CustomEvent('app:repeater-load', { detail: flow }));
      window.dispatchEvent(new CustomEvent('app:navigate', { detail: { view: 'repeater' } }));
    } catch (error) {
      showError('Could not load flow: ' + error.message);
    }
    void target;
  }

  escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[char]));
  }
}

if (!customElements.get('sitemap-view')) customElements.define('sitemap-view', SitemapView);
