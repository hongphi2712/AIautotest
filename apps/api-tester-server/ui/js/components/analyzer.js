// Analyzer view: generates "flow code" (Mermaid sequence / Python replay) from
// captured traffic and an optional one-shot AI summary via
// DeepSeek. The AI call only happens on an explicit button click and only sends
// a compact, redacted context — never raw bodies or token values.

import { apiGet, apiPost, escapeHtml, showError, toHex } from '../api.js';
import { getActiveSessionId, getSessions, subscribe } from '../store.js';
import './message-viewer.js';

const TEMPLATE = `
  <div class="analyzer-wrap">
    <div class="toolbar">
      <strong>Flow code</strong>
      <select id="a-format">
        <option value="mermaid">Mermaid</option>
        <option value="python">Python</option>
      </select>
      <select id="a-mode">
        <option value="recording">Recording</option>
        <option value="parameterized">Parameterized</option>
      </select>
      <button id="a-generate">Generate</button>
      <button id="a-copy">Copy</button>
      <button id="a-ai" class="btn primary">AI Phân tích</button>
      <span id="a-count" class="muted" style="margin-left:auto">—</span>
    </div>

    <div class="analyzer-tabs">
      <button class="analyzer-tab active" data-a-tab="output">Flow diagram</button>
      <button class="analyzer-tab" data-a-tab="deps">Dependencies</button>
      <button class="analyzer-tab" data-a-tab="workflow">Workflow (AI)</button>
      <button class="analyzer-tab" data-a-tab="security">Security (AI)</button>
    </div>

    <div id="a-pane-output" class="analyzer-pane active">
      <div id="a-sequence" class="seq"></div>
      <div class="a-source-head">
        <span id="a-source-title">Mermaid source</span>
        <button id="a-copy-source" class="mini-btn">Copy source</button>
      </div>
      <pre id="a-output" class="a-pre"></pre>
    </div>

    <div id="a-pane-deps" class="analyzer-pane">
      <div class="table-scroll">
        <table class="flows">
          <thead><tr>
            <th>Source</th><th>Target</th><th>Token type</th><th>Location</th>
          </tr></thead>
          <tbody id="a-deps-body"></tbody>
        </table>
      </div>
    </div>

    <div id="a-pane-workflow" class="analyzer-pane">
      <div class="wf-bar">
        <input id="wf-prompt" placeholder="VD: Đăng nhập lấy access_token, gọi /profile, /orders và kiểm tra status 200...">
        <input id="wf-base" placeholder="https://api.example.com">
        <select id="wf-session" class="a-session-select"><option value="">All sessions</option></select>
        <select id="wf-model" class="a-session-select"><option value="">Default model</option></select>
        <label class="wf-check"><input type="checkbox" id="wf-use-traffic"> Dùng traffic đã bắt</label>
        <button id="wf-generate" class="btn primary">Generate workflow</button>
      </div>      <div id="wf-preview" class="wf-preview"></div>
      <div class="resizer-h" data-resize="wf" title="Kéo để thay đổi kích thước"></div>
      <div id="wf-actions" class="wf-actions" hidden>
        <button id="wf-approve" class="btn primary">Approve &amp; Save</button>
        <button id="wf-run" class="btn">Run</button>
        <button id="wf-cancel" class="btn danger">Cancel</button>
        <span id="wf-status" class="muted" style="margin-left:auto"></span>
      </div>
      <div id="wf-versions" class="table-scroll"></div>
    </div>

    <div id="a-pane-security" class="analyzer-pane">
      <div class="sec-start-panel">
        <div class="sec-start-copy"><div class="sec-kicker">Security testing</div><h2>Tạo kế hoạch kiểm thử</h2><p>Phân tích traffic đã ghi để đề xuất các bài test bảo mật phù hợp với target của bạn.</p></div>
        <div class="sec-start-form">
          <label class="sec-field"><span>Target URL</span><input id="sec-base" placeholder="https://api.example.com" ></label>
          <label class="sec-field"><span>Capture session</span><select id="sec-session"><option value="">All sessions</option></select></label>
          <label class="sec-field"><span>AI Model</span><select id="sec-model"><option value="">Default model</option></select></label>
          <label class="sec-traffic-option"><input type="checkbox" id="sec-use-traffic" checked><span><strong>Dùng traffic đã bắt</strong><small>Giúp AI hiểu endpoint, tham số và session thực tế</small></span></label>
          <button id="sec-generate" class="btn primary sec-generate-btn">Sinh kế hoạch <span aria-hidden="true">→</span></button>
        </div>
        <div class="sec-start-status" aria-live="polite">Bước 1/2 · Nhập target và tạo kế hoạch kiểm thử</div>
      </div>      <div id="sec-preview" class="wf-preview"></div>
      <div class="resizer-h" data-resize="sec" title="Kéo để thay đổi kích thước"></div>
      <div id="sec-actions" class="wf-actions" hidden>
        <button id="sec-approve" class="btn primary">Approve &amp; Save</button>
        <button id="sec-run" class="btn">Run</button>
        <button id="sec-cancel" class="btn danger">Cancel</button>
        <span id="sec-status" class="muted" style="margin-left:auto"></span>
      </div>
      <div id="sec-versions" class="table-scroll"></div>
      <div id="sec-findings" class="table-scroll"></div>
    </div>

    <div id="a-ai-panel" class="ai-panel" hidden>
      <div class="ai-head">
        <strong>AI phân tích luồng</strong>
        <span id="a-ai-model" class="muted"></span>
        <button id="a-ai-hide" class="mini-btn" style="margin-left:auto">Ẩn</button>
      </div>
      <div class="ai-note">Gửi tóm tắt (steps, dependencies, sitemap) + request/response body (text, mỗi body ≤4000 char, bỏ binary/hex) tới DeepSeek — header/token value trong dependency không gửi.</div>
      <pre id="a-ai-output" class="a-pre"></pre>
    </div>

    <div id="a-empty" class="empty" hidden>
      <div class="big">◔</div>
      <h3>Chưa có traffic</h3>
      <p>Bắt traffic qua Proxy rồi bấm <b>Generate</b> để sinh flow code của web (Mermaid / Python) từ các request đã ghi lại.</p>
    </div>
  </div>
`;

export class AnalyzerView extends HTMLElement {
  connectedCallback() {
    this.innerHTML = TEMPLATE;
    this.report = null;
    this.aiStatus = { configured: false, model: '' };
    this.busy = false;
    const workflowOwnedByMigration = this.hasAttribute('data-workflow-owned');
    const securityOwnedByMigration = this.hasAttribute('data-security-owned');

    this.querySelector('#a-format').addEventListener('change', () => this.syncControls());
    this.querySelector('#a-generate').addEventListener('click', () => this.generate());
    this.querySelector('#a-copy').addEventListener('click', () => this.copyOutput());
    this.querySelector('#a-copy-source').addEventListener('click', () => this.copyOutput());
    this.querySelector('#a-ai').addEventListener('click', () => this.aiAnalyze());
    this.querySelector('#a-ai-hide').addEventListener('click', () => {
      this.querySelector('#a-ai-panel').hidden = true;
    });

    if (!workflowOwnedByMigration) {
      this.querySelector('#wf-generate').addEventListener('click', () => this.wfGenerate());
      this.querySelector('#wf-base').addEventListener('keydown', (e) => { if (e.key === 'Enter') this.wfGenerate(); });
      this.querySelector('#wf-prompt').addEventListener('keydown', (e) => { if (e.key === 'Enter') this.wfGenerate(); });
      this.querySelector('#wf-approve').addEventListener('click', () => this.wfApprove());
      this.querySelector('#wf-run').addEventListener('click', () => this.wfRun());
      this.querySelector('#wf-cancel').addEventListener('click', () => this.wfCancel());
    }

    if (!securityOwnedByMigration) {
      this.querySelector('#sec-generate').addEventListener('click', () => this.secGenerate());
      this.querySelector('#sec-approve').addEventListener('click', () => this.secApprove());
      this.querySelector('#sec-run').addEventListener('click', () => this.secRun());
      this.querySelector('#sec-cancel').addEventListener('click', () => this.secCancel());
    }

    this.onWsFlow = () => this.refreshCount();
    this.onWsCleared = () => this.handleCleared();
    window.addEventListener('app:ws-flow', this.onWsFlow);
    window.addEventListener('app:ws-flows-cleared', this.onWsCleared);
    if (!workflowOwnedByMigration) {
      this.onWsWfNode = (event) => this.onWorkflowNode(event.detail);
      this.onWsWfRun = (event) => this.onWorkflowRun(event.detail);
      window.addEventListener('app:ws-workflow-node', this.onWsWfNode);
      window.addEventListener('app:ws-workflow-run', this.onWsWfRun);
    }
    if (!securityOwnedByMigration) {
      this.onWsSecRun = (event) => this.onSecurityRun(event.detail);
      this.onWsSecTest = (event) => this.onSecurityTest(event.detail);
      this.onWsSecConfirm = (event) => this.onSecurityConfirm(event.detail);
      window.addEventListener('app:ws-security_run', this.onWsSecRun);
      window.addEventListener('app:ws-security_test', this.onWsSecTest);
      window.addEventListener('app:ws-security_confirm', this.onWsSecConfirm);
    }

    this.querySelectorAll('.analyzer-tab').forEach((tab) => tab.addEventListener('click', () => {
      this.querySelectorAll('.analyzer-tab').forEach((t) => t.classList.toggle('active', t === tab));
      this.querySelectorAll('.analyzer-pane').forEach((pane) => {
        pane.classList.toggle('active', pane.id === 'a-pane-' + tab.dataset.aTab);
      });
      if (tab.dataset.aTab === 'workflow' && !workflowOwnedByMigration) this.loadWorkflows();
      else if (tab.dataset.aTab === 'security' && !securityOwnedByMigration) this.loadSecurityPlans();
    }));

    this.initResizers();

    this.syncControls();
    this.loadAiStatus();
    this.refreshCount();
    // prefill base_url from Target view localStorage
    try{
      const saved=localStorage.getItem('target.base_url');
      if(saved){
        const wf=this.querySelector('#wf-base');
        const sec=this.querySelector('#sec-base');
        if(wf && !wf.value) wf.value=saved;
        if(sec && !sec.value) sec.value=saved;
      }
    }catch{}
    this.sessionUnsubscribe = subscribe(() => this.populateSessionSelectors());
    this.populateSessionSelectors();
    void this.loadSessions();
    void this.loadModels();
  }

  async loadSessions() {
    try {
      await apiGet('/api/sessions');
      this.populateSessionSelectors();
    } catch { /* ignore */ }
  }

  populateSessionSelectors() {
    const sessions = getSessions();
    const activeId = getActiveSessionId();
    ['#wf-session', '#sec-session'].forEach((sel) => {
      const select = this.querySelector(sel);
      if (!select) return;
      const current = select.value;
      select.innerHTML = '<option value="">All sessions</option>';
      sessions.forEach((s) => {
        const opt = document.createElement('option');
        const isActive = s.id === activeId;
        opt.value = s.id;
        opt.textContent = (isActive ? '[Active] ' : '') + (s.name || s.id.slice(0, 8)) + ' (' + (s.flow_count || 0) + ' flows)';
        if (isActive) opt.style.fontWeight = '600';
        select.appendChild(opt);
      });
      if (current && sessions.some((s) => s.id === current)) {
        select.value = current;
      } else if (activeId) {
        select.value = activeId;
      }
    });
  }

  async loadModels() {
    try {
      const result = await apiGet('/api/ai/models');
      this.models = result.data || [];
      this.populateModelSelectors();
    } catch { this.models = []; }
  }

  populateModelSelectors() {
    ['#sec-model', '#wf-model'].forEach((sel) => {
      const select = this.querySelector(sel);
      if (!select) return;
      const current = select.value;
      select.innerHTML = '<option value="">Default model</option>';
      (this.models || []).forEach((m) => {
        const opt = document.createElement('option');
        opt.value = m.id;
        opt.textContent = m.id;
        select.appendChild(opt);
      });
      if (current) select.value = current;
    });
  }

  disconnectedCallback() {
    window.removeEventListener('app:ws-flow', this.onWsFlow);
    window.removeEventListener('app:ws-flows-cleared', this.onWsCleared);
    if (!this.hasAttribute('data-workflow-owned')) {
      window.removeEventListener('app:ws-workflow-node', this.onWsWfNode);
      window.removeEventListener('app:ws-workflow-run', this.onWsWfRun);
    
    if (this.sessionUnsubscribe) this.sessionUnsubscribe();}
    if (!this.hasAttribute('data-security-owned')) {
      window.removeEventListener('app:ws-security_run', this.onWsSecRun);
      window.removeEventListener('app:ws-security_test', this.onWsSecTest);
      window.removeEventListener('app:ws-security_confirm', this.onWsSecConfirm);
    }
  }

  initResizers() {
    this.setupResizer('wf', 'wf-preview', 'analyzer-wf-preview-h');
    this.setupResizer('sec', 'sec-preview', 'analyzer-sec-preview-h');
  }

  setupResizer(resizeKey, previewId, storageKey) {
    const resizer = this.querySelector(`[data-resize="${resizeKey}"]`);
    const preview = this.querySelector(`#${previewId}`);
    if (!resizer || !preview) return;
    const saved = localStorage.getItem(storageKey);
    if (saved) {
      const h = parseInt(saved, 10);
      if (!isNaN(h) && h >= 80 && h <= 600) {
        preview.style.flex = `0 0 ${h}px`;
        preview.style.height = h + 'px';
      }
    }
    resizer.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      const startY = e.clientY;
      const startH = preview.offsetHeight;
      resizer.classList.add('active');
      document.body.classList.add('resizing-h');
      try { resizer.setPointerCapture(e.pointerId); } catch {}
      const onMove = (ev) => {
        const dy = ev.clientY - startY;
        const newH = Math.max(80, Math.min(600, startH + dy));
        preview.style.flex = `0 0 ${newH}px`;
        preview.style.height = newH + 'px';
      };
      const onUp = (ev) => {
        resizer.classList.remove('active');
        document.body.classList.remove('resizing-h');
        try { resizer.releasePointerCapture(ev.pointerId); } catch {}
        const h = parseInt(preview.style.height || preview.offsetHeight, 10);
        if (!isNaN(h)) localStorage.setItem(storageKey, String(h));
        resizer.removeEventListener('pointermove', onMove);
        resizer.removeEventListener('pointerup', onUp);
        resizer.removeEventListener('pointercancel', onUp);
      };
      resizer.addEventListener('pointermove', onMove);
      resizer.addEventListener('pointerup', onUp);
      resizer.addEventListener('pointercancel', onUp);
    });
  }

  syncControls() {
    const format = this.querySelector('#a-format').value;
    this.querySelector('#a-mode').hidden = format !== 'python';
    this.querySelector('#a-source-title').textContent =
      format === 'python' ? 'Python replay code' : 'Mermaid source';
    if (this.report) this.renderReport(this.report);
  }

  async loadAiStatus() {
    try {
      this.aiStatus = await apiGet('/api/ai/config');
    } catch {
      this.aiStatus = { configured: false, model: '' };
    }
    const button = this.querySelector('#a-ai');
    const model = this.querySelector('#a-ai-model');
    const wfButton = this.querySelector('#wf-generate');
    const secButton = this.querySelector('#sec-generate');
    if (!button || !model) return;
    if (this.aiStatus.configured) {
      button.disabled = false;
      button.title = '';
      if (wfButton) wfButton.disabled = false;
      if (secButton) secButton.disabled = false;
      model.textContent = 'Model: ' + (this.aiStatus.model || '');
    } else {
      button.disabled = true;
      button.title = 'Cấu hình DEEPSEEK_API_KEY hoặc ai.api_key trong config.json để bật';
      if (wfButton) { wfButton.disabled = true;
        wfButton.title = 'Cấu hình AI (thiếu API key)';
      }
      if (secButton) { secButton.disabled = true;
      secButton.title = 'Cấu hình AI (thiếu API key)';
      }
      model.textContent = 'Chưa cấu hình (thiếu API key)';
    }
  }

  async refreshCount() {
    try {
      const health = await apiGet('/api/health');
      const count = health && health.flows;
      this.querySelector('#a-count').textContent = count === undefined ? '—' : count + ' flows captured';
    } catch {
      this.querySelector('#a-count').textContent = '—';
    }
  }

  handleCleared() {
    this.report = null;
    this.querySelector('#a-output').textContent = '';
    this.querySelector('#a-sequence').innerHTML = '';
    this.querySelector('#a-deps-body').innerHTML = '';
    this.querySelector('#a-ai-output').textContent = '';
    this.showEmpty(false);
  }

  setBusy(busy, which) {
    this.busy = busy;
    ['#a-generate', '#a-copy', '#a-copy-source'].forEach((id) => {
      this.querySelector(id).disabled = busy;
    });
    if (which !== 'ai') this.querySelector('#a-ai').disabled = busy || !this.aiStatus.configured;
  }

  async generate() {
    if (this.busy) return;
    this.setBusy(true, 'generate');
    const btn = this.querySelector('#a-generate');
    const original = btn.textContent;
    btn.textContent = 'Đang generate...';
    try {
      const body = { format: this.querySelector('#a-format').value };
      const mode = this.querySelector('#a-mode').value;
      if (body.format === 'python') body.mode = mode;
      const report = await apiPost('/api/analyze/flow', body);
      this.report = report;
      this.renderReport(report);
    } catch (error) {
      showError('Analyze: ' + error);
    } finally {
      btn.textContent = original;
      this.setBusy(false, 'generate');
    }
  }

  renderReport(report) {
    this.showEmpty(report.steps.length === 0);
    this.querySelector('#a-output').textContent = report.output || '';
    this.renderSequence(report.steps);
    this.renderDeps(report);
  }

  showEmpty(empty) {
    this.querySelector('#a-empty').hidden = !empty;
    const panes = this.querySelectorAll('.analyzer-pane');
    panes.forEach((pane) => { pane.style.display = empty ? 'none' : ''; });
  }

  renderSequence(steps) {
    const box = this.querySelector('#a-sequence');
    box.innerHTML = '';
    if (!steps || !steps.length) return;

    const header = document.createElement('div');
    header.className = 'seq-hd';
    header.innerHTML = '<span class="seq-participant">Client</span><span class="seq-gap"></span><span class="seq-participant">API</span>';
    box.appendChild(header);

    for (const step of steps) {
      const req = document.createElement('div');
      req.className = 'seq-row seq-req';
      const method = document.createElement('span');
      method.className = 'method ' + step.method;
      method.textContent = step.method;
      const path = document.createElement('span');
      path.className = 'seq-path';
      path.textContent = step.path + (step.count && step.count > 1 ? ' ×' + step.count : '');
      const reqLabel = document.createElement('span');
      reqLabel.className = 'seq-label';
      reqLabel.append(method, document.createTextNode(' '), path);
      req.append(
        this.span('seq-src', 'Client'),
        this.span('seq-arrow', '->>'),
        this.span('seq-dst', 'API'),
        reqLabel,
      );
      box.appendChild(req);

      const resp = document.createElement('div');
      resp.className = 'seq-row seq-resp';
      resp.append(
        this.span('seq-src', 'API'),
        this.span('seq-arrow', '-->>'),
        this.span('seq-dst', 'Client'),
        this.span('seq-label status-' + Math.floor(step.status / 100), String(step.status)),
      );
      box.appendChild(resp);
    }
  }

  span(cls, text) {
    const el = document.createElement('span');
    el.className = cls;
    el.textContent = text;
    return el;
  }

  renderDeps(report) {
    const tbody = this.querySelector('#a-deps-body');
    tbody.innerHTML = '';
    const label = {};
    for (const step of report.steps || []) label[step.fingerprint] = step.method + ' ' + step.path;
    const deps = report.dependencies || [];
    if (!deps.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">Không phát hiện dependency (token) giữa các request.</td></tr>';
      return;
    }
    const fragment = document.createDocumentFragment();
    for (const dep of deps) {
      const tr = document.createElement('tr');
      const source = document.createElement('td');
      source.textContent = label[dep.source_flow_id] || dep.source_flow_id;
      const target = document.createElement('td');
      target.textContent = label[dep.target_flow_id] || dep.target_flow_id;
      const type = document.createElement('td');
      type.textContent = (dep.token && dep.token.type) || '';
      const loc = document.createElement('td');
      loc.textContent = dep.usage_location || '';
      tr.append(source, target, type, loc);
      fragment.appendChild(tr);
    }
    tbody.appendChild(fragment);
  }

  copyOutput() {
    const text = this.querySelector('#a-output').textContent;
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      const btn = this.querySelector('#a-copy');
      const original = btn.textContent;
      btn.textContent = 'Đã copy!';
      setTimeout(() => { btn.textContent = original; }, 1200);
    }).catch(() => showError('Không copy được'));
  }

  async aiAnalyze() {
    if (this.busy) return;
    if (!this.aiStatus.configured) {
      showError('AI chưa được cấu hình — đặt DEEPSEEK_API_KEY hoặc ai.api_key.');
      return;
    }
    this.setBusy(true, 'ai');
    const panel = this.querySelector('#a-ai-panel');
    const output = this.querySelector('#a-ai-output');
    panel.hidden = false;
    output.textContent = 'Đang phân tích...';
    try {
      const result = await apiPost('/api/ai/flow-summary');
      output.textContent = result.summary || '(trống)';
    } catch (error) {
      output.textContent = 'Lỗi: ' + error;
    } finally {
      this.setBusy(false, 'ai');
    }
  }

  // ---------- Workflow (AI) ----------

  async wfGenerate() {
    const button = this.querySelector('#wf-generate');
    const prompt = this.querySelector('#wf-prompt').value.trim();
    const baseUrl = this.querySelector('#wf-base').value.trim();
    if (!prompt || !baseUrl) { showError('Nhập cả yêu cầu (prompt) và base_url.'); return; }
    button.disabled = true;
    const original = button.textContent;
    button.textContent = 'Đang generate (AI)...';
    this.wfSetStatus('Đang sinh workflow...');
    this.wfHideActions();
    try {
      const sessionId = this.querySelector('#wf-session')?.value || '';
      const model = this.querySelector('#wf-model')?.value || '';
      const preview = await apiPost('/api/workflow/generate', {
        prompt,
        base_url: baseUrl,
        use_traffic: this.querySelector('#wf-use-traffic').checked,
        session_id: sessionId || undefined,
        model: model || undefined,
      });
      this.preview = preview;
      this.wfRenderPreview(preview);
    } catch (error) {
      this.wfRenderError(error);
    } finally {
      button.textContent = original;
      button.disabled = false;
    }
  }

  wfRenderError(message) {
    const preview = this.querySelector('#wf-preview');
    preview.innerHTML = '<div class="wf-error">' + escapeHtml(message) + '</div>';
    this.wfHideActions();
  }

  wfSetStatus(text) {
    this.querySelector('#wf-status').textContent = text || '';
  }

  wfHideActions() {
    this.querySelector('#wf-actions').hidden = true;
  }

  wfShowActions() {
    this.querySelector('#wf-actions').hidden = false;
  }

  wfRenderPreview(preview) {
    const box = this.querySelector('#wf-preview');
    box.innerHTML = '';
    this.wfHideActions();

    const errors = preview.errors || [];
    const warnings = preview.scope_warnings || [];
    const workflow = preview.workflow;

    if (errors.length) {
      const errBox = document.createElement('div');
      errBox.className = 'wf-error';
      errBox.textContent = 'Workflow không hợp lệ (sau ' + (preview.attempts || 0) + ' lượt AI):';
      const ul = document.createElement('ul');
      errors.forEach((error) => {
        const li = document.createElement('li');
        li.textContent = error;
        ul.appendChild(li);
      });
      errBox.appendChild(ul);
      box.appendChild(errBox);
    }

    if (warnings.length) {
      const warnBox = document.createElement('div');
      warnBox.className = 'wf-warning';
      warnBox.textContent = 'Cảnh báo scope (' + warnings.length + ' request ngoài scope — cần xác nhận khi Run):';
      const ul = document.createElement('ul');
      warnings.forEach((w) => {
        const li = document.createElement('li');
        li.textContent = w.node_id + ' → ' + w.url;
        ul.appendChild(li);
      });
      warnBox.appendChild(ul);
      box.appendChild(warnBox);
    }

    if (workflow && typeof workflow === 'object') {
      box.appendChild(this.wfRenderNodes(workflow));
      box.appendChild(this.wfRenderEdges(workflow));
      const raw = document.createElement('details');
      raw.className = 'wf-raw';
      const summary = document.createElement('summary');
      summary.textContent = 'Xem JSON';
      const pre = document.createElement('pre');
      pre.className = 'a-pre';
      pre.textContent = JSON.stringify(workflow, null, 2);
      raw.append(summary, pre);
      box.appendChild(raw);
    } else if (!errors.length) {
      const errBox = document.createElement('div');
      errBox.className = 'wf-error';
      errBox.textContent = 'Không nhận được workflow hợp lệ.';
      box.appendChild(errBox);
    }

    // Preview only — approve/run are explicit user actions (AI never runs).
    if (workflow && typeof workflow === 'object' && !errors.length) {
      this.wfShowActions();
      this.wfSetStatus('Sẵn sàng Approve & Run. AI chưa chạy request nào.');
    }
  }

  wfRenderNodes(workflow) {
    const nodes = workflow.nodes || [];
    const wrap = document.createElement('div');
    wrap.className = 'wf-nodes';
    const head = document.createElement('div');
    head.className = 'wf-section';
    head.textContent = 'Nodes (' + nodes.length + ')';
    wrap.appendChild(head);
    for (const node of nodes) {
      const row = document.createElement('div');
      row.className = 'wf-node';
      const id = document.createElement('span');
      id.className = 'wf-node-id';
      id.textContent = node.id;
      const type = document.createElement('span');
      type.className = 'wf-node-type ' + node.type;
      type.textContent = node.type;
      const cfg = document.createElement('span');
      cfg.className = 'wf-node-cfg';
      cfg.textContent = wfConfigSummary(node);
      row.append(id, type, cfg);
      wrap.appendChild(row);
    }
    return wrap;
  }

  wfRenderEdges(workflow) {
    const edges = workflow.edges || [];
    const wrap = document.createElement('div');
    wrap.className = 'wf-edges';
    const head = document.createElement('div');
    head.className = 'wf-section';
    head.textContent = 'Edges (' + edges.length + ')';
    wrap.appendChild(head);
    if (!edges.length) {
      const empty = document.createElement('div');
      empty.className = 'muted';
      empty.textContent = 'Không có edge.';
      wrap.appendChild(empty);
      return wrap;
    }
    const list = document.createElement('div');
    list.className = 'wf-edge-list';
    for (const edge of edges) {
      const row = document.createElement('div');
      row.className = 'wf-edge';
      row.textContent = edge.from + ' → ' + edge.to + (edge.when ? '  [' + edge.when + ']' : '');
      list.appendChild(row);
    }
    wrap.appendChild(list);
    return wrap;
  }

  async wfApprove() {
    if (!this.preview || !this.preview.workflow) return;
    const baseUrl = this.querySelector('#wf-base').value.trim();
    const name = (this.preview.workflow.name || 'Workflow') + ' v1';
    const button = this.querySelector('#wf-approve');
    button.disabled = true;
    try {
      const version = await apiPost('/api/workflow/approve', {
        name,
        base_url: baseUrl,
        spec_json: JSON.stringify(this.preview.workflow),
      });
      this.versionId = version.id;
      this.wfSetStatus('Đã lưu version: ' + version.name + ' (approved).');
      this.loadWorkflows();
    } catch (error) {
      showError('Approve: ' + error);
    } finally {
      button.disabled = false;
    }
  }

  async wfRun() {
    if (!this.versionId) { showError('Approve & Save trước khi Run.'); return; }
    const warnings = (this.preview && this.preview.scope_warnings) || [];
    let confirmOverride = false;
    if (warnings.length) {
      confirmOverride = window.confirm(
        'Workflow có ' + warnings.length + ' request ngoài scope. Chạy với xác nhận override?'
      );
      if (!confirmOverride) return;
    }
    const button = this.querySelector('#wf-run');
    button.disabled = true;
    this.wfSetStatus('Đang chạy...');
    try {
      const result = await apiPost('/api/workflow/run', {
        version_id: this.versionId,
        confirm_scope_override: confirmOverride,
      });
      this.runId = result.run_id;
      this.wfSetStatus('Run đang chạy: ' + result.run_id);
      this.wfClearLive();
    } catch (error) {
      this.wfSetStatus('');
      showError('Run: ' + error);
    } finally {
      button.disabled = false;
    }
  }

  async wfCancel() {
    if (!this.runId) return;
    try {
      await apiPost('/api/workflow/cancel', { run_id: this.runId });
      this.wfSetStatus('Đang hủy...');
    } catch (error) {
      showError('Cancel: ' + error);
    }
  }

  onWorkflowNode(detail) {
    if (!this.runId || detail.run_id !== this.runId) return;
    this.wfAppendLive(detail);
  }

  onWorkflowRun(detail) {
    if (!this.runId || detail.run_id !== this.runId) return;
    this.wfSetStatus('Run kết thúc: ' + (detail.status || '') + (detail.error ? ' — ' + detail.error : ''));
    this.loadWorkflows();
  }

  wfClearLive() {
    const live = this.querySelector('#wf-live');
    if (live) live.innerHTML = '';
    else {
      // create lazily so subsequent wfAppendLive has a container and
      // wfClearLive never throws on first run
      const box = this.querySelector('#wf-preview');
      if (!box) return;
      const el = document.createElement('div');
      el.id = 'wf-live';
      el.className = 'wf-live';
      box.appendChild(el);
    }
  }

  wfAppendLive(node) {
    let live = this.querySelector('#wf-live');
    if (!live) {
      live = document.createElement('div');
      live.id = 'wf-live';
      live.className = 'wf-live';
      this.querySelector('#wf-preview').appendChild(live);
    }
    const row = document.createElement('div');
    row.className = 'wf-live-row ' + (node.ok ? 'ok' : 'fail');
    const head = document.createElement('span');
    head.className = 'wf-live-id';
    head.textContent = node.node_id;
    const status = document.createElement('span');
    status.className = node.ok ? 'wf-live-status ok' : 'wf-live-status fail';
    status.textContent = node.ok ? '✓' : '✗';
    const info = document.createElement('span');
    info.className = 'wf-live-info';
    info.textContent = node.error ? node.error : wfSummarize(node.output);
    row.append(head, status, info);
    live.appendChild(row);
    live.scrollTop = live.scrollHeight;
  }

  async loadWorkflows() {
    try {
      const versions = await apiGet('/api/workflows');
      this.wfRenderVersions(versions || []);
    } catch {
      this.wfRenderVersions([]);
    }
  }

  wfRenderVersions(versions) {
    const box = this.querySelector('#wf-versions');
    if (!versions.length) {
      box.innerHTML = '';
      return;
    }
    const wrap = document.createElement('div');
    wrap.className = 'wf-section';
    wrap.textContent = 'Workflows đã lưu';
    box.innerHTML = '';
    box.appendChild(wrap);
    for (const version of versions) {
      const row = document.createElement('div');
      row.className = 'wf-version';
      const label = document.createElement('span');
      label.textContent = version.name + '  (v' + version.version + ', ' + version.status + ')';
      const time = document.createElement('span');
      time.className = 'muted';
      time.textContent = new Date(version.created_at).toLocaleString();
      row.append(label, time);
      row.onclick = () => this.loadWorkflowDetail(version.id);
      box.appendChild(row);
    }
  }

  async loadWorkflowDetail(versionId) {
    try {
      const detail = await apiGet('/api/workflow/' + encodeURIComponent(versionId));
      this.wfRenderRuns(detail.runs || []);
    } catch {
      this.wfRenderRuns([]);
    }
  }

  wfRenderRuns(runs) {
    const box = this.querySelector('#wf-versions');
    const wrap = document.createElement('div');
    wrap.className = 'wf-section';
    wrap.textContent = 'Runs';
    box.appendChild(wrap);
    if (!runs.length) {
      const empty = document.createElement('div');
      empty.className = 'muted';
      empty.textContent = 'Chưa có run.';
      box.appendChild(empty);
      return;
    }
    for (const run of runs) {
      const row = document.createElement('div');
      row.className = 'wf-version';
      row.textContent = run.status + '  ·  ' + new Date(run.started_at).toLocaleString() +
        (run.finished_at ? ' → ' + new Date(run.finished_at).toLocaleTimeString() : '');
      box.appendChild(row);
    }
  }

  // ---------- Security (AI) ----------

  async secGenerate() {
    const button = this.querySelector('#sec-generate');
    const baseUrl = this.querySelector('#sec-base').value.trim();
    if (!baseUrl) { showError('Nhập base_url.'); return; }
    button.disabled = true;
    const original = button.textContent;
    button.textContent = 'Đang sinh (AI)...';
    this.secSetStatus('Đang sinh kế hoạch...');
    this.secHideActions();
    try {
      const sessionId = this.querySelector('#sec-session')?.value || '';
      const model = this.querySelector('#sec-model')?.value || '';
      const preview = await apiPost('/api/security/generate', {
        base_url: baseUrl,
        use_traffic: this.querySelector('#sec-use-traffic').checked,
        session_id: sessionId || undefined,
        model: model || undefined,
      });
      this.secPreview = preview;
      this.secRenderPreview(preview);
    } catch (error) {
      this.secRenderError(error);
    } finally {
      button.textContent = original;
      button.disabled = false;
    }
  }

  secRenderError(message) {
    const box = this.querySelector('#sec-preview');
    box.innerHTML = '<div class="wf-error">' + escapeHtml(message) + '</div>';
    this.secHideActions();
  }

  secSetStatus(text) {
    this.querySelector('#sec-status').textContent = text || '';
  }

  secHideActions() {
    this.querySelector('#sec-actions').hidden = true;
  }

  secShowActions() {
    this.querySelector('#sec-actions').hidden = false;
  }

  secRenderPreview(preview) {
    const box = this.querySelector('#sec-preview');
    box.innerHTML = '';
    this.secHideActions();
    const errors = preview.errors || [];
    const plan = preview.plan;
    if (errors.length) {
      const errBox = document.createElement('div');
      errBox.className = 'wf-error';
      errBox.textContent = 'Kế hoạch không hợp lệ (sau ' + (preview.attempts || 0) + ' lượt AI):';
      const ul = document.createElement('ul');
      errors.forEach((e) => { const li = document.createElement('li'); li.textContent = e; ul.appendChild(li); });
      errBox.appendChild(ul);
      box.appendChild(errBox);
    }
    const warnings = preview.warnings || [];
    if (warnings.length) {
      const wBox = document.createElement('div');
      wBox.className = 'wf-warning';
      wBox.textContent = 'Cảnh báo:';
      const ul = document.createElement('ul');
      warnings.forEach((w) => { const li = document.createElement('li'); li.textContent = w; ul.appendChild(li); });
      wBox.appendChild(ul);
      box.appendChild(wBox);
    }
    if (plan && typeof plan === 'object' && plan.tests) {
      const head = document.createElement('div');
      head.className = 'wf-section';
      head.textContent = 'Tests (' + plan.tests.length + ')';
      box.appendChild(head);
      for (const t of plan.tests) {
        const row = document.createElement('div');
        row.className = 'wf-node';
        const id = document.createElement('span'); id.className = 'wf-node-id'; id.textContent = t.id;
        const flaw = document.createElement('span'); flaw.className = 'wf-node-type ' + t.flaw; flaw.textContent = t.flaw;
        const tgt = document.createElement('span'); tgt.className = 'wf-node-cfg'; tgt.textContent = t.target.method + ' ' + t.target.path + ' [' + t.severity + ']';
        row.append(id, flaw, tgt);
        box.appendChild(row);
      }
      const raw = document.createElement('details'); raw.className = 'wf-raw';
      const sum = document.createElement('summary'); sum.textContent = 'Xem JSON';
      const pre = document.createElement('pre'); pre.className = 'a-pre'; pre.textContent = JSON.stringify(plan, null, 2);
      raw.append(sum, pre); box.appendChild(raw);
    } else if (!errors.length) {
      const e = document.createElement('div'); e.className = 'wf-error'; e.textContent = 'Không nhận được kế hoạch.'; box.appendChild(e);
    }
    if (plan && typeof plan === 'object' && !errors.length) {
      this.secShowActions();
      this.secSetStatus('Sẵn sàng Approve & Run.');
    }
  }

  async secApprove() {
    if (!this.secPreview || !this.secPreview.plan) return;
    const baseUrl = this.querySelector('#sec-base').value.trim();
    const name = (this.secPreview.plan.plan_id || 'Security plan') + ' v1';
    const btn = this.querySelector('#sec-approve'); btn.disabled = true;
    try {
      const plan = await apiPost('/api/security/approve', { name, base_url: baseUrl, plan_json: JSON.stringify(this.secPreview.plan) });
      this.secPlanId = plan.id;
      this.secSetStatus('Đã lưu: ' + plan.name);
      this.loadSecurityPlans();
    } catch (e) { showError('Approve: ' + e); }
    finally { btn.disabled = false; }
  }

  async secRun() {
    if (!this.secPlanId) { showError('Approve trước khi Run.'); return; }
    const testCount = (this.secPreview && this.secPreview.plan && this.secPreview.plan.tests) ? this.secPreview.plan.tests.length : 0;
    if (!window.confirm('Chạy security test với ' + testCount + ' test(s)?')) return;
    const btn = this.querySelector('#sec-run'); btn.disabled = true;
    const cancelBtn = this.querySelector('#sec-cancel'); if (cancelBtn) cancelBtn.disabled = false;
    this.secSetStatus('Đang chạy...');
    // Clear findings and show test-by-test progress
    const findingsEl = this.querySelector('#sec-findings');
    if (findingsEl) {
      findingsEl.classList.add('is-live');
      findingsEl.innerHTML = '<div class="sec-progress-head">Đang thực thi...</div>';
    }
    try {
      const r = await apiPost('/api/security/run', { plan_id: this.secPlanId, confirm_scope_override: true });
      this.secRunId = r.run_id;
      this.secSetStatus('Run: ' + r.run_id + ' — đang thực thi...');
    } catch (e) {
      this.secSetStatus('');
      if (findingsEl) findingsEl.classList.remove('is-live');
      showError('Run: ' + e);
      btn.disabled = false;
    }
  }

  async secCancel() {
    if (!this.secRunId) return;
    try { await apiPost('/api/security/cancel', { run_id: this.secRunId }); this.secSetStatus('Đang hủy...'); }
    catch (e) { showError('Cancel: ' + e); }
  }

  onSecurityRun(detail) {
    if (!this.secRunId || detail.run_id !== this.secRunId) return;
    const stopInfo = detail.stop_reason && detail.stop_reason !== 'completed' ? ' (' + detail.stop_reason + ')' : '';
    const reqInfo = detail.requests_sent != null ? ' · ' + detail.requests_sent + ' requests sent' : '';
    const skipInfo = detail.skipped ? ' · ' + detail.skipped + ' skipped' : '';
    this.secSetStatus('Run kết thúc: ' + detail.status + stopInfo + reqInfo + skipInfo);
    this.secRunId = null;
    this.secDestructiveTests = [];
    const liveFindings = this.querySelector('#sec-findings');
    if (liveFindings) liveFindings.classList.remove('is-live');
    const btn = this.querySelector('#sec-run'); if (btn) btn.disabled = false;
    // Reload findings from DB for the full report
    this.loadSecurityDetail(this.secPlanId);
  }

  onSecurityTest(detail) {
    if (!this.secRunId || detail.run_id !== this.secRunId) return;
    const box = this.querySelector('#sec-findings');
    if (!box) return;
    // Remove "Đang thực thi..." header on first event
    const head = box.querySelector('.sec-progress-head');
    if (head) head.remove();

    // Append card for this test
    const card = secCreateTestCard({
      test_id: detail.test_id,
      flaw: detail.flaw,
      target: detail.target,
      status: detail.status,
      passed: detail.passed,
      finding: detail.has_finding ? {} : null,
      potential: detail.potential,
      skipped: detail.skipped,
      evidence: detail.evidence,
      severity: '',
    });
    box.appendChild(card);
    box.scrollTop = box.scrollHeight;
  }

  onSecurityConfirm(detail) {
    if (!this.secRunId || detail.run_id !== this.secRunId) return;
    const box = this.querySelector('#sec-findings');
    if (!box) return;

    // Remove "Đang thực thi..." header on first event
    const head = box.querySelector('.sec-progress-head');
    if (head) head.remove();

    // Remove existing banner to avoid stacking
    const existing = box.querySelector('.sec-confirm-banner');
    if (existing) existing.remove();

    // Track destructive test count
    if (!this.secDestructiveTests) this.secDestructiveTests = [];
    if (!this.secDestructiveTests.includes(detail.test_id)) {
      this.secDestructiveTests.push(detail.test_id);
    }
    const idx = this.secDestructiveTests.indexOf(detail.test_id) + 1;
    const total = this.secDestructiveTests.length;

    const banner = document.createElement('div');
    banner.className = 'sec-confirm-banner';
    banner.dataset.testId = detail.test_id;
    banner.setAttribute('tabindex', '0');
    banner.innerHTML = `
      <div class="sec-confirm-info">
        <span class="sec-badge warn">XAC NHIN</span>
        <strong>${escapeHtml(detail.method)} ${escapeHtml(detail.path)}</strong>
        <span class="muted">${escapeHtml(detail.flaw)} / ${escapeHtml(detail.severity)}</span>
        ${total > 1 ? `<span class="muted">(${idx}/${total})</span>` : ''}
      </div>
      <div class="sec-confirm-hint">${escapeHtml(detail.payload_hint)}</div>
      <div class="sec-confirm-timer">Auto-skip trong <span class="sec-confirm-countdown">60</span>s</div>
      <div class="sec-confirm-actions">
        <button class="btn primary sec-confirm-approve">Dong y</button>
        <button class="btn danger sec-confirm-reject">Tu choi</button>
      </div>
    `;
    box.appendChild(banner);
    box.scrollTop = box.scrollHeight;
    banner.focus();

    let remaining = 60;
    const timer = setInterval(() => {
      remaining--;
      const el = banner.querySelector('.sec-confirm-countdown');
      if (el) el.textContent = remaining;
      if (remaining <= 10) {
        const timerEl = banner.querySelector('.sec-confirm-timer');
        if (timerEl) timerEl.classList.add('urgent');
      }
      if (remaining <= 0) {
        clearInterval(timer);
        banner.remove();
      }
    }, 1000);

    const approveHandler = () => {
      clearInterval(timer);
      this.secSendConfirmation(detail.test_id, true);
      banner.classList.add('sec-confirm-pending');
      banner.querySelector('.sec-confirm-actions').innerHTML = '<span class="muted">Dang xu ly...</span>';
    };

    const rejectHandler = () => {
      clearInterval(timer);
      this.secSendConfirmation(detail.test_id, false);
      banner.remove();
    };

    banner.querySelector('.sec-confirm-approve').addEventListener('click', approveHandler);
    banner.querySelector('.sec-confirm-reject').addEventListener('click', rejectHandler);

    // Keyboard shortcuts
    banner.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        approveHandler();
      } else if (event.key === 'Escape') {
        event.preventDefault();
        rejectHandler();
      }
    });
  }

  async secSendConfirmation(testId, approved) {
    try {
      await apiPost('/api/security/confirm', {
        run_id: this.secRunId,
        test_id: testId,
        approved: approved,
      });
    } catch (e) {
      showError('Confirmation failed: ' + e);
    }
  }

  async loadSecurityPlans() {
    try {
      const plans = await apiGet('/api/security/plans');
      this.secRenderPlans(plans || []);
    } catch { this.secRenderPlans([]); }
  }

  secRenderPlans(plans) {
    const box = this.querySelector('#sec-versions');
    box.innerHTML = '';

    const header = document.createElement('div');
    header.className = 'sec-plans-header';
    const approvedCount = plans.filter((p) => String(p.status || '').toLowerCase() === 'approved').length;
    const draftCount = plans.filter((p) => String(p.status || 'draft').toLowerCase() === 'draft').length;
    const latestPlan = plans[0] && plans[0].created_at ? new Date(plans[0].created_at).toLocaleString() : '—';
    header.innerHTML = '<div><div class="wf-section">Security plans</div><div class="sec-plans-count">' + plans.length + ' kế hoạch · Chọn một kế hoạch để xem các lần chạy</div>'
      + '<div class="sec-plans-summary"><span class="sec-plan-metric"><strong>' + plans.length + '</strong> tổng số</span><span class="sec-plan-metric"><strong>' + approvedCount + '</strong> đã duyệt</span><span class="sec-plan-metric"><strong>' + draftCount + '</strong> bản nháp</span><span class="sec-plan-metric">Lưu gần nhất <strong>' + escapeHtml(latestPlan) + '</strong></span></div></div>'
      + '<div class="sec-plans-tools"><input class="sec-plans-search" type="search" placeholder="Tìm plan hoặc target..." aria-label="Tìm kiếm security plan"><select class="sec-plans-filter" aria-label="Lọc trạng thái"><option value="all">Tất cả trạng thái</option><option value="approved">Đã duyệt</option><option value="active">Đang dùng</option><option value="draft">Draft</option></select><select class="sec-plans-sort" aria-label="Sắp xếp security plan"><option value="recent">Mới nhất</option><option value="name">Tên A-Z</option><option value="status">Trạng thái</option></select><button class="btn primary sec-create-plan" type="button">+ Tạo kế hoạch</button></div>';
    box.appendChild(header);

    if (!plans.length) {
      header.querySelector('.sec-create-plan').addEventListener('click', () => this.secGenerate());
      box.insertAdjacentHTML('beforeend', '<div class="sec-plans-empty"><strong>Chưa có security plan</strong><span>Nhấn "Tạo kế hoạch" để bắt đầu.</span></div>');
      return;
    }

    const tableWrap = document.createElement('div');
    tableWrap.className = 'sec-plans-table-wrap';
    tableWrap.innerHTML = '<table class="sec-plans-table"><thead><tr><th>Tên plan</th><th>Target</th><th>Trạng thái</th><th>Tests</th><th>Version</th><th>Đã lưu</th><th class="sec-plan-action-col">Action</th></tr></thead><tbody></tbody></table>';
    box.appendChild(tableWrap);
    const tbody = tableWrap.querySelector('tbody');
    const planRows = plans.map((p) => {
      let parsed = {};
      try { parsed = JSON.parse(p.plan_json || '{}'); } catch {}
      return {
        plan: p,
        target: p.base_url || parsed.base_url || '',
        tests: Array.isArray(parsed.tests) ? parsed.tests.length : null,
      };
    });

    const self = this;
    const renderRows = () => {
      const query = (header.querySelector('.sec-plans-search').value || '').trim().toLowerCase();
      const statusFilter = header.querySelector('.sec-plans-filter').value;
      const sort = header.querySelector('.sec-plans-sort').value;
      tbody.innerHTML = '';
      const visible = planRows.filter(({ plan: p, target }) => {
        const status = String(p.status || 'draft').toLowerCase();
        return (statusFilter === 'all' || status === statusFilter)
          && (!query || String(p.name || '').toLowerCase().includes(query) || String(p.id || '').toLowerCase().includes(query) || target.toLowerCase().includes(query));
      }).sort((a, b) => {
        if (sort === 'name') return String(a.plan.name || '').localeCompare(String(b.plan.name || ''));
        if (sort === 'status') return String(a.plan.status || '').localeCompare(String(b.plan.status || ''));
        return new Date(b.plan.created_at || 0) - new Date(a.plan.created_at || 0);
      });
      if (!visible.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="sec-plans-no-match">Không tìm thấy security plan phù hợp.</td></tr>';
        return;
      }
      for (const { plan: p, target, tests } of visible) {
        const row = document.createElement('tr');
        const status = String(p.status || 'draft').toLowerCase();
        const statusLabel = status === 'approved' ? 'Đã duyệt' : status === 'active' ? 'Đang dùng' : status;
        row.innerHTML = '<td><strong class="sec-plan-name">' + escapeHtml(p.name || 'Security plan') + '</strong></td>'
          + '<td><span class="sec-plan-target" title="' + escapeHtml(target || 'Chưa có target') + '">' + escapeHtml(target || 'Chưa có target') + '</span></td>'
          + '<td><span class="sec-plan-status ' + status + '">' + escapeHtml(statusLabel) + '</span></td>'
          + '<td><span class="sec-plan-tests">' + (tests == null ? '—' : tests) + '</span></td>'
          + '<td><code class="sec-plan-id">v' + escapeHtml(String(p.id || '').slice(0, 6)) + '</code></td>'
          + '<td><time class="sec-plan-time">' + escapeHtml(new Date(p.created_at).toLocaleString()) + '</time></td>'
          + '<td class="sec-plan-action"><button class="sec-plan-open" type="button">Xem kết quả <span aria-hidden="true">→</span></button></td>';
        row.addEventListener('click', () => { self.secPlanId = p.id; self.loadSecurityDetail(p.id); });
        row.querySelector('.sec-plan-open').addEventListener('click', (event) => {
          event.stopPropagation();
          self.secPlanId = p.id;
          self.loadSecurityDetail(p.id);
        });
        tbody.appendChild(row);
      }
    };
    header.querySelector('.sec-plans-search').addEventListener('input', () => renderRows());
    header.querySelector('.sec-plans-filter').addEventListener('change', () => renderRows());
    header.querySelector('.sec-plans-sort').addEventListener('change', () => renderRows());
    header.querySelector('.sec-create-plan').addEventListener('click', () => this.secGenerate());
    renderRows();
    const findingsEl = this.querySelector('#sec-findings');
    if (findingsEl) findingsEl.style.display = 'none';
  }
  async loadSecurityDetail(planId) {
    this.closeSecurityResults();
    const requestId = (this.secDetailRequestId || 0) + 1;
    this.secDetailRequestId = requestId;
    const overlay = document.createElement('div');
    overlay.className = 'sec-results-overlay';
    overlay.innerHTML = '<section class="sec-results-modal" role="dialog" aria-modal="true" aria-labelledby="sec-results-title"><header class="sec-results-header"><div><h2 id="sec-results-title">Kết quả security plan</h2><span class="muted">Chi tiết các lần chạy và findings</span></div><button class="sec-results-close" type="button" aria-label="Đóng">×</button></header><div class="sec-results-body" id="sec-results-content"></div></section>';
    overlay.addEventListener('click', (event) => { if (event.target === overlay) this.closeSecurityResults(); });
    overlay.querySelector('.sec-results-close').addEventListener('click', () => this.closeSecurityResults());
    overlay.addEventListener('keydown', (event) => { if (event.key === 'Escape') this.closeSecurityResults(); });
    document.body.appendChild(overlay);
    this.secResultsOverlay = overlay;
    this.secFindingsTarget = overlay.querySelector('#sec-results-content');
    overlay.tabIndex = -1;
    overlay.focus();
    this.secFindingsTarget.innerHTML = '<div class="sec-results-loading"><span class="sec-loading-bar"></span><strong>Đang tải kết quả...</strong><span class="muted">Đang lấy các lần chạy của security plan.</span></div>';
    try {
      const d = await apiGet('/api/security/plan/' + encodeURIComponent(planId));
      if (requestId !== this.secDetailRequestId || this.secFindingsTarget !== overlay.querySelector('#sec-results-content')) return;
      this.secRenderFindings(d.runs || []);
    } catch {
      if (requestId !== this.secDetailRequestId || !this.secFindingsTarget) return;
      this.secFindingsTarget.innerHTML = '<div class="sec-results-error"><strong>Không tải được kết quả</strong><span>Vui lòng thử mở lại security plan.</span></div>';
    }
  }

  closeSecurityResults() {
    this.secDetailRequestId = (this.secDetailRequestId || 0) + 1;
    if (this.secResultsOverlay) this.secResultsOverlay.remove();
    this.secResultsOverlay = null;
    this.secFindingsTarget = null;
  }

  secRenderFindings(runs) {
    const box = this.secFindingsTarget || this.querySelector('#sec-findings');
    if (box === this.querySelector('#sec-findings')) box.style.display = '';
    box.innerHTML = '';
    if (!runs.length) {
      box.innerHTML = '<div class="muted" style="padding:8px 12px">Chưa có run. Chạy plan để xem kết quả.</div>';
      return;
    }
    const run = runs[0];
    let findings = [];
    try { findings = JSON.parse(run.findings_json || '[]'); } catch {}

    // Stats
    const total = findings.length;
      const withFinding = findings.filter(f => f.finding).length;
      const potential = findings.filter(f => f.potential && !f.finding).length;
      const passed = findings.filter(f => f.passed && !f.finding).length;
      const skipped = findings.filter(f => f.skipped).length;
      const reqSent = findings.filter(f => !f.skipped).length;

      // Summary header
      const summary = document.createElement('div');
      summary.className = 'sec-run-summary';
      const statusIcon = run.status === 'completed' ? '✓' : run.status === 'failed' ? '✗' : '●';
      const statusCls = run.status === 'completed' ? 'ok' : run.status === 'failed' ? 'fail' : '';
      summary.innerHTML = '<span class="sec-run-icon ' + statusCls + '">' + statusIcon + '</span>'
        + '<span class="sec-run-time">' + new Date(run.started_at).toLocaleString() + '</span>'
        + '<span class="sec-run-stat">' + total + ' tests</span>'
        + (withFinding ? '<span class="sec-run-stat find">' + withFinding + ' findings</span>' : '')
        + (potential ? '<span class="sec-run-stat pot">' + potential + ' potential</span>' : '')
        + (passed ? '<span class="sec-run-stat ok">' + passed + ' passed</span>' : '')
        + (skipped ? '<span class="sec-run-stat muted">' + skipped + ' skipped</span>' : '');
      box.appendChild(summary);

      // Filter bar
      if (total > 0) {
        const filters = document.createElement('div');
        filters.className = 'sec-filters';
        const filterData = [
          { label: 'Tất cả (' + total + ')', filter: null },
          { label: 'Potential (' + potential + ')', filter: 'potential' },
          { label: 'Passed (' + passed + ')', filter: 'passed' },
          { label: 'Findings (' + withFinding + ')', filter: 'finding' },
        ];
        const cardsContainer = document.createElement('div');
        cardsContainer.className = 'sec-cards';

        for (const fd of filterData) {
          const btn = document.createElement('button');
          btn.className = 'sec-filter-btn' + (fd.filter === null ? ' active' : '');
          btn.textContent = fd.label;
          btn.onclick = () => {
            filters.querySelectorAll('.sec-filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderCards(findings, fd.filter, cardsContainer);
          };
          filters.appendChild(btn);
        }
        box.appendChild(filters);
        box.appendChild(cardsContainer);
        renderCards(findings, null, cardsContainer);
      }

      // Raw JSON
      const raw = document.createElement('details'); raw.className = 'wf-raw'; raw.style.marginTop = '8px';
      const sum = document.createElement('summary'); sum.textContent = 'Xem raw JSON';
      const pre = document.createElement('pre'); pre.className = 'a-pre'; pre.textContent = JSON.stringify(findings, null, 2);
      raw.append(sum, pre); box.appendChild(raw);
  }
}

// During the Vite migration the Lit/TypeScript shell owns `analyzer-view`.
// Keep this implementation available under an internal name for the
// compatibility bridge and for the standalone legacy UI.
if (!customElements.get('analyzer-view-legacy')) customElements.define('analyzer-view-legacy', AnalyzerView);

// ---------- Security test card helpers ----------

function summarizeEvidence(ev) {
  if (!ev) return '';
  // Transport errors — return as-is
  if (ev.startsWith('transport error:')) return ev;

  const statusMatch = ev.match(/status=(\d+)/);
  const lenMatch = ev.match(/body_len=(\d+)/);
  const snippetMatch = ev.match(/snippet=(.*)/);

  let parts = [];
  if (statusMatch) parts.push('Status: ' + statusMatch[1]);
  if (lenMatch) {
    const len = parseInt(lenMatch[1], 10);
    parts.push('Size: ' + (len > 1024 ? Math.round(len / 1024) + 'KB' : lenMatch[1] + ' chars'));
  }

  if (snippetMatch) {
    const snippet = snippetMatch[1];
    // Try parse as HTML to extract title/heading
    try {
      const doc = new DOMParser().parseFromString(snippet, 'text/html');
      const title = doc.querySelector('title');
      if (title && title.textContent.trim()) {
        parts.push('Title: ' + title.textContent.trim().slice(0, 60));
      }
      const heading = doc.querySelector('h1, h2');
      if (heading && heading.textContent.trim()) {
        parts.push('Heading: ' + heading.textContent.trim().slice(0, 40));
      }
    } catch { /* not HTML */ }

    // If nothing parsed from HTML, truncate at clean boundary
    if (parts.length <= 2) {
      const lastGt = snippet.lastIndexOf('>');
      const cutAt = lastGt > 20 ? lastGt + 1 : Math.min(snippet.length, 60);
      parts.push('Snippet: ' + snippet.slice(0, cutAt) + (cutAt < snippet.length ? '…' : ''));
    }
  }

  return parts.join(' · ');
}

function secCreateTestCard(f) {
  const card = document.createElement('div');
  card.className = 'sec-card';

  // Badge
  let badgeCls = 'neutral';
  let badgeText = '—';
  if (f.skipped) { badgeCls = 'skip'; badgeText = 'SKIP'; }
  else if (f.finding) { badgeCls = 'fail'; badgeText = 'LỖ HỔNG'; }
  else if (f.potential) { badgeCls = 'warn'; badgeText = 'CÓ THỂ CÓ'; }
  else if (f.passed) { badgeCls = 'ok'; badgeText = 'AN TOÀN'; }

  // Severity
  const sev = (f.severity || '').toUpperCase();
  const sevCls = sev === 'CRITICAL' ? 'sev-critical' : sev === 'HIGH' ? 'sev-high' : sev === 'WARNING' ? 'sev-warning' : sev === 'MEDIUM' ? 'sev-warning' : 'sev-info';

  // Status code
  const statusStr = f.status ? String(f.status) : '—';
  const statusClass = f.status ? 'status-' + Math.floor(f.status / 100) : '';

  // Verdict (plain-English title)
  const verdict = f.verdict || flaw_name_vi(f.flaw);

  // === ROW 1: Badge + Verdict title ===
  const row1 = document.createElement('div');
  row1.className = 'sec-card-row1';
  row1.innerHTML = '<span class="sec-badge ' + badgeCls + '">' + badgeText + '</span>'
    + '<span class="sec-card-verdict">' + escapeHtml(verdict) + '</span>'
    + (sev ? '<span class="sec-severity ' + sevCls + '">' + escapeHtml(sev) + '</span>' : '');

  // === ROW 2: Endpoint + Status code ===
  const row2 = document.createElement('div');
  row2.className = 'sec-card-row2';
  row2.innerHTML = '<span class="sec-card-endpoint">' + escapeHtml(f.target || '') + '</span>'
    + '<span class="sec-card-status-badge ' + statusClass + '">' + statusStr + '</span>';

  // === ROW 3: Explanation (tình trạng) ===
  const row3 = document.createElement('div');
  row3.className = 'sec-card-row3';
  if (f.explanation) {
    row3.innerHTML = '<span class="sec-card-label">Tình trạng:</span> ' + escapeHtml(f.explanation);
  } else {
    row3.style.display = 'none';
  }

  // === ROW 4: Payload sent ===
  const row4 = document.createElement('div');
  row4.className = 'sec-card-row4';
  const needsPayload = ['sqli', 'xss', 'idor', 'open_redirect'].includes(f.flaw);
  if (f.payload_sent && f.payload_sent.trim()) {
    row4.innerHTML = '<span class="sec-card-label">Payload đã gửi:</span> <code>' + escapeHtml(f.payload_sent) + '</code>';
  } else if (needsPayload) {
    row4.innerHTML = '<span class="sec-card-label">Payload:</span> <span class="muted" style="color:#b45309">Thiếu — cần concrete payload</span>';
  } else {
    row4.style.display = 'none';
  }

  // === ROW 5: Risk (rủi ro) ===
  const row5 = document.createElement('div');
  row5.className = 'sec-card-row5';
  if (f.risk) {
    row5.innerHTML = '<span class="sec-card-label">Rủi ro:</span> ' + escapeHtml(f.risk);
  } else {
    row5.style.display = 'none';
  }

  // === ROW 6: Fix suggestion ===
  const row6 = document.createElement('div');
  row6.className = 'sec-card-row6';
  if (f.fix_suggestion) {
    row6.innerHTML = '<span class="sec-card-label">Fix:</span> ' + escapeHtml(f.fix_suggestion);
  } else {
    row6.style.display = 'none';
  }

  // Click handler → open detail modal
  card.style.cursor = 'pointer';
  card.addEventListener('click', () => openSecurityDetail(f));

  card.append(row1, row2, row3, row4, row5, row6);
  return card;
}

function test_target_method(target) {
  if (!target) return 'GET';
  const parts = target.split(' ');
  return parts[0] || 'GET';
}

function openSecurityDetail(f) {
  // Replace the results dialog before opening the request inspector.
  document.querySelectorAll('.sec-results-overlay').forEach((el) => el.remove());
  // Create modal overlay
  const overlay = document.createElement('div');
  overlay.className = 'sec-modal-overlay';
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });

  // Modal container
  const modal = document.createElement('div');
  modal.className = 'sec-modal';

  // Header
  const header = document.createElement('div');
  header.className = 'sec-modal-header';
  const badgeCls = f.finding ? 'fail' : f.potential ? 'warn' : 'ok';
  const badgeText = f.finding ? 'LỖ HỔNG' : f.potential ? 'CÓ THỂ CÓ' : 'AN TOÀN';
  header.innerHTML = '<span class="sec-badge ' + badgeCls + '">' + badgeText + '</span>'
    + '<span class="sec-modal-title">' + escapeHtml(f.verdict || flaw_name_vi(f.flaw)) + '</span>'
    + '<button class="sec-modal-close">✕</button>';
  header.querySelector('.sec-modal-close').addEventListener('click', () => overlay.remove());

  // Message viewer
  const viewer = document.createElement('message-viewer');

  // Construct request raw text — full headers, cookies, body
  const method = f.request_method || test_target_method(f.target);
  const fullUrl = f.request_url || f.target || '';
  const path = fullUrl.replace(/^https?:\/\/[^/]+/, '') || '/';
  const headers = f.request_headers || '(không có header tùy chỉnh)';
  const cookies = f.cookies || '(không có cookie)';
  const location = f.location || '';
  // For GET requests with location=path, payload is in URL not body
  let bodySection;
  if (f.payload_sent && f.payload_sent.trim()) {
    if (method === 'GET' && location === 'path') {
      bodySection = 'Payload (đã inject vào path): ' + f.payload_sent;
    } else if (method === 'GET') {
      bodySection = 'Payload: ' + f.payload_sent;
    } else {
      bodySection = 'Body:\n' + f.payload_sent;
    }
  } else {
    bodySection = method === 'GET' ? '(GET request — no body)' : 'Body: (trống)';
  }
  const requestRaw = method + ' ' + path + ' HTTP/1.1\n'
    + headers + '\n'
    + 'Cookie: ' + cookies + '\n\n'
    + bodySection;

  // Full response wire view — status line, every response header, body.
  const responseHeaders = f.response_headers || '(không có header)';
  const statusLine = 'HTTP/1.1 ' + (f.status || 0);
  const responseBody = f.response_body || '';
  const responseRawFull = statusLine + '\n' + responseHeaders + '\n\n' + responseBody;

  const evidence = document.createElement('div');
  evidence.className = 'sec-evidence';
  const payload = f.payload_sent && f.payload_sent.trim() ? f.payload_sent.trim() : '';
  const payloadLocation = location || (payload ? (method === 'GET' ? 'query/path' : 'body') : 'none');
  let responseEvidence = '';
  try {
    const responseJson = JSON.parse(f.response_body || '{}');
    const tokenKeys = Object.keys(responseJson).filter((key) => /token|jwt/i.test(key));
    if (tokenKeys.length) responseEvidence = 'Phát hiện field nhạy cảm trong response: ' + tokenKeys.join(', ');
  } catch { /* response is not JSON */ }
  if (!responseEvidence && f.flaw === 'jwt_exposure') responseEvidence = 'Response có dấu hiệu chứa access token hoặc refresh token.';
  evidence.innerHTML = '<div class="sec-evidence-title">Bằng chứng kiểm thử</div>'
    + '<div class="sec-evidence-grid"><div><span>Method</span><strong>' + escapeHtml(method) + '</strong></div><div><span>Status</span><strong class="status-' + Math.floor(Number(f.status) / 100) + '">' + escapeHtml(String(f.status || '—')) + '</strong></div><div><span>Vị trí payload</span><strong>' + escapeHtml(payloadLocation) + '</strong></div><div class="sec-evidence-payload"><span>Payload / request body</span><code>' + escapeHtml(payload || 'Không có payload; request không có body.') + '</code></div></div>'
    + (responseEvidence ? '<div class="sec-evidence-response"><span>Bằng chứng response</span><strong>' + escapeHtml(responseEvidence) + '</strong></div>' : '');

  // Construct response raw text — smart formatting
  const responsePrefix = statusLine + '\n' + responseHeaders + '\n\n';
  let responsePretty = '';
  let responseRender = '';
  if (f.response_body) {
    const trimmed = f.response_body.trim();
    const isJson = trimmed.startsWith('{') || trimmed.startsWith('[');
    const isHtml = f.is_html_page || trimmed.includes('<!DOCTYPE') || trimmed.includes('<html');
    if (isHtml) {
      // HTML page — use DOMParser to extract rich summary
      let title = '(HTML page)';
      let headings = [];
      let formDetails = '';
      let ssoButtons = [];
      try {
        const doc = new DOMParser().parseFromString(f.response_body, 'text/html');
        const titleEl = doc.querySelector('title');
        if (titleEl && titleEl.textContent.trim()) {
          title = titleEl.textContent.trim();
        } else {
          const ogTitle = doc.querySelector('meta[property="og:title"]');
          if (ogTitle && ogTitle.getAttribute('content')) {
            title = ogTitle.getAttribute('content').trim();
          }
        }
        headings = [...doc.querySelectorAll('h1, h2, h3')].map(h => h.textContent.trim()).filter(t => t).slice(0, 3);
        // Extract form details
        const forms = doc.querySelectorAll('form');
        formDetails = [...forms].map(f => {
          const action = f.getAttribute('action') || '(no action)';
          const inputs = [...f.querySelectorAll('input')].map(i => {
            const name = i.getAttribute('name') || i.getAttribute('type') || 'unnamed';
            const type = i.getAttribute('type') || 'text';
            return `${name}(${type})`;
          }).join(', ');
          return `Form: action=${action}, inputs=[${inputs}]`;
        }).join('\n');
        // Extract SSO buttons
        ssoButtons = [...doc.querySelectorAll('button, a')].filter(el =>
          el.textContent.includes('Microsoft') || el.textContent.includes('Google')
        ).map(el => el.textContent.trim());
      } catch { /* not valid HTML */ }
      const hasApiData = f.response_body.includes('"data"') || f.response_body.includes('"error"') || f.response_body.includes('"accessToken"');
      responsePretty = responsePrefix
        + '[HTML Page] Title: ' + title + '\n'
        + (headings.length ? 'Headings: ' + headings.join(' | ') + '\n' : '')
        + (formDetails ? 'Forms:\n' + formDetails + '\n' : 'No forms\n')
        + (ssoButtons.length ? 'SSO: ' + ssoButtons.join(', ') + '\n' : '')
        + '---\n'
        + (hasApiData ? 'Có dữ liệu API (JSON) trong HTML\n' : 'Không có dữ liệu API — page render\n')
        + '---\n'
        + 'Endpoint trả HTML page. Xem Render tab để xem trang.\n';
      responseRender = f.response_body;
    } else if (isJson) {
      try {
        const pretty = JSON.stringify(JSON.parse(f.response_body), null, 2);
        responsePretty = responsePrefix + pretty;
      } catch {
        responsePretty = responsePrefix + f.response_body;
      }
      responseRender = f.response_body;
    } else {
      responsePretty = responsePrefix + f.response_body;
      responseRender = f.response_body;
    }
  } else {
    responsePretty = responsePrefix + '(empty)';
    responseRender = '(empty response)';
  }

  // Inspector sections
  const hasCookie = f.cookies && !f.cookies.includes('không có');
  const sections = [
    { title: 'Test info', rows: [
      ['Test ID', f.test_id],
      ['Flaw', f.flaw],
      ['Severity', (f.severity || '').toUpperCase()],
      ['Verdict', f.verdict || ''],
      ['Location', location || '(none)'],
    ]},
    { title: 'Request gốc', rows: [
      ['URL', f.request_url || ''],
      ['Method', f.request_method || ''],
      ['Payload', f.payload_sent || '(none)'],
      ['Cookie', hasCookie ? 'Có' : 'Không'],
    ]},
    { title: 'Analysis', rows: [
      ['Tình trạng', f.explanation || ''],
      ['Rủi ro', f.risk || ''],
      ['Fix', f.fix_suggestion || ''],
      ['HTML page', f.is_html_page ? 'Có — endpoint trả HTML page render' : 'Không — endpoint trả JSON/data'],
    ]},
    { title: 'So sánh', rows: [
      ['Request này', hasCookie ? 'Có Cookie' : 'Không có Cookie, không có Authorization'],
      ['Request bình thường', 'Có session cookie + Authorization: Bearer token'],
      ['Kết luận', f.explanation || ''],
    ]},
  ];
  // Full request/response headers as inspector rows (every header, no trimming).
  const parseHeaderRows = (text) => String(text || '')
    .split('\n')
    .map((line) => {
      const idx = line.indexOf(':');
      return idx > 0 ? [line.slice(0, idx).trim(), line.slice(idx + 1).trim()] : null;
    })
    .filter(Boolean);
  if (!String(f.request_headers || '').includes('không có')) {
    sections.push({ title: 'Request headers', rows: parseHeaderRows(f.request_headers) });
  }
  sections.push({ title: 'Response headers', rows: f.response_headers ? parseHeaderRows(f.response_headers) : [['(không có header)', '']] });
  sections.push({ title: 'Response body', rows: [['Kích thước', responseBody.length + ' chars'], ['Loại', f.is_html_page ? 'HTML page' : 'JSON/text']] });

  // Assemble modal
  modal.append(header, evidence, viewer);
  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  // Set viewer data after DOM append — ensure responseRender is set
  const renderData = {
    requestRaw,
    requestPretty: requestRaw,
    requestHex: toHex(requestRaw),
    responseRaw: responseRawFull,
    responsePretty,
    responseHex: toHex(responseRawFull),
    responseRender: responseRender || '<p>(empty response)</p>',
    inspectorSections: sections,
  };
  viewer.data = renderData;
  // The modal just entered the layout; recompute panel widths once the frame
  // is laid out so Request/Response split evenly instead of clipping Response.
  requestAnimationFrame(() => { if (viewer.applyPanelWidths) viewer.applyPanelWidths(); });
}

function flaw_name_vi(flaw) {
  const names = {
    jwt_exposure: 'Leak JWT Token',
    idor: 'IDOR — Truy cập resource người khác',
    auth_bypass: 'Auth Bypass — Bỏ qua xác thực',
    sqli: 'SQL Injection',
    xss: 'XSS — Cross-Site Scripting',
    csrf: 'CSRF — Cross-Site Request Forgery',
    open_redirect: 'Open Redirect',
    rate_limit: 'Thiếu Rate Limiting',
  };
  return names[flaw] || flaw;
}

function renderCards(findings, filter, container) {
  container.innerHTML = '';
  const filtered = filter === null ? findings : findings.filter(f => {
    if (filter === 'potential') return f.potential && !f.finding;
    if (filter === 'passed') return f.passed && !f.finding;
    if (filter === 'finding') return f.finding;
    return true;
  });
  if (!filtered.length) {
    container.innerHTML = '<div class="muted" style="padding:8px 12px">Không có kết quả phù hợp.</div>';
    return;
  }
  for (const f of filtered) {
    container.appendChild(secCreateTestCard(f));
  }
}

function wfConfigSummary(node) {
  const cfg = node.config || {};
  if (node.type === 'http_request') {
    return (cfg.method || 'GET') + ' ' + (cfg.path || '');
  }
  if (node.type === 'extract_variable') return 'var.' + (cfg.name || '') + '  ← ' + (cfg.source || '');
  if (node.type === 'assert') return (cfg.source || '') + ' ' + (cfg.operator || 'eq') + ' ' + JSON.stringify(cfg.expected);
  if (node.type === 'condition') return (cfg.source || '') + ' ' + (cfg.operator || 'eq') + ' ' + JSON.stringify(cfg.value);
  if (node.type === 'delay') return (cfg.ms || 0) + ' ms';
  if (node.type === 'loop') return 'loop ' + (cfg.source || '') + ' (' + (cfg.max_iterations || 0) + ')';
  return '';
}

function wfSummarize(output) {
  if (output && output.response) {
    return 'HTTP ' + output.response.status + ' · ' + (output.response.body || '').slice(0, 60);
  }
  if (output && typeof output === 'object') {
    const text = JSON.stringify(output);
    return text.length > 80 ? text.slice(0, 80) + '…' : text;
  }
  return String(output || '');
}
