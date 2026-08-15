// Shared Request/Response viewer used by both Intercept and HTTP history.
// Usage: <message-viewer editable></message-viewer>, then `viewer.data = {...}`.
// Edit actions (edit/apply/cancel) are emitted as `viewer-action` events.
// The req | res | inspector column widths are draggable (pointer events) and
// persisted to localStorage; they never auto-size to content.
import './inspector-panel.js';

const MIN_PANEL = 120;
const MIN_INSPECTOR = 150;

function isInspector(element) {
  return element.tagName === 'INSPECTOR-PANEL' || element.classList.contains('inspector-sidebar');
}

export class MessageViewer extends HTMLElement {
  connectedCallback() {
    const editable = this.hasAttribute('editable');
    this.innerHTML = this.template(editable);
    this.inspector = this.querySelector('inspector-panel');
    this.applyPanelWidths();
    this.initResizers();
    this.addEventListener('click', (event) => {
      const tab = event.target.closest('.subtab');
      if (tab) {
        const panel = tab.closest('.rv-panel');
        panel.querySelectorAll('.subtab').forEach((b) => b.classList.remove('active'));
        panel.querySelectorAll('.rv-pane').forEach((p) => p.classList.remove('active'));
        tab.classList.add('active');
        panel.querySelector('[data-pane="' + tab.dataset.tab + '"]').classList.add('active');
        return;
      }
      const action = event.target.closest('[data-action]');
      if (action) {
        this.dispatchEvent(new CustomEvent('viewer-action', { detail: action.dataset.action }));
      }
    });
  }

  set data(value) {
    this.applyPanelWidths();
    this.render(value);
  }

  get editOverlay() {
    return this.querySelector('[data-role="edit-overlay"]');
  }

  template(editable) {
    return `
    <div class="inspector-layout">
      <div class="rv-panel" data-panel="req">
        <div class="rv-header"><span class="rv-title">Request</span>${editable ? '<button class="rv-action" data-action="edit">Edit</button>' : ''}</div>
        <div class="subtabs">
          <button class="subtab active" data-tab="pretty">Pretty</button>
          <button class="subtab" data-tab="raw">Raw</button>
          <button class="subtab" data-tab="hex">Hex</button>
        </div>
        <div class="rv-pane active" data-pane="pretty"><pre data-role="req-pretty"></pre></div>
        <div class="rv-pane" data-pane="raw"><pre data-role="req-raw"></pre></div>
        <div class="rv-pane" data-pane="hex"><pre data-role="req-hex"></pre></div>
      </div>
      <div class="resizer" data-side="req"></div>
      <div class="rv-panel" data-panel="resp">
        <div class="rv-header"><span class="rv-title">Response</span></div>
        <div class="subtabs">
          <button class="subtab active" data-tab="pretty">Pretty</button>
          <button class="subtab" data-tab="raw">Raw</button>
          <button class="subtab" data-tab="hex">Hex</button>
          <button class="subtab" data-tab="render">Render</button>
        </div>
        <div class="rv-pane active" data-pane="pretty"><pre data-role="resp-pretty"></pre></div>
        <div class="rv-pane" data-pane="raw"><pre data-role="resp-raw"></pre></div>
        <div class="rv-pane" data-pane="hex"><pre data-role="resp-hex"></pre></div>
        <div class="rv-pane" data-pane="render"><iframe class="render-frame" sandbox="" data-role="resp-render"></iframe></div>
      </div>
      <div class="resizer" data-side="resp"></div>
      <inspector-panel id="inspector"></inspector-panel>
      ${editable ? `
      <div class="intercept-edit-overlay" data-role="edit-overlay">
        <div class="edit-form">
          <div class="edit-row"><label>Method</label><input class="mono" data-role="edit-method"></div>
          <div class="edit-row"><label>URL</label><input class="mono" style="flex:1" data-role="edit-url"></div>
          <div class="edit-row" data-role="edit-status-row" style="display:none"><label>Status</label><input class="mono" data-role="edit-status"></div>
          <div class="edit-row" style="align-items:flex-start"><label>Headers</label><textarea rows="6" class="mono" data-role="edit-headers" placeholder='[{ "name": "Content-Type", "value": "application/json" }]'></textarea></div>
          <div class="edit-row" style="align-items:flex-start"><label>Body</label><textarea rows="10" class="mono" data-role="edit-body"></textarea></div>
          <div class="edit-row"><span></span><span><button class="btn" data-action="apply">Apply edits &amp; Forward</button> <button class="btn" data-action="cancel">Cancel</button></span></div>
        </div>
      </div>` : ''}
    </div>`;
  }

  applyPanelWidths() {
    const layout = this.querySelector('.inspector-layout');
    if (!layout) return;
    const req = layout.querySelector('[data-panel="req"]');
    const resp = layout.querySelector('[data-panel="resp"]');
    const sidebar = layout.querySelector('inspector-panel');
    if (!req || !resp || !sidebar) return;
    const savedReq = Number(localStorage.getItem('viewer:req')) || 0;
    const savedResp = Number(localStorage.getItem('viewer:resp')) || 0;
    const savedInsp = Number(localStorage.getItem('viewer:insp')) || 0;
    if (savedReq > 0 && savedResp > 0 && savedInsp > 0) {
      req.style.width = savedReq + 'px';
      resp.style.width = savedResp + 'px';
      sidebar.style.width = savedInsp + 'px';
    } else if (layout.clientWidth > 0) {
      req.style.width = Math.round(layout.clientWidth * 0.45) + 'px';
      resp.style.width = Math.round(layout.clientWidth * 0.45) + 'px';
      sidebar.style.width = Math.max(MIN_INSPECTOR, Math.round(layout.clientWidth * 0.1)) + 'px';
    } else {
      req.style.width = '500px';
      resp.style.width = '500px';
      sidebar.style.width = MIN_INSPECTOR + 'px';
    }
  }

  initResizers() {
    this.querySelectorAll('.resizer').forEach((handle) => {
      handle.addEventListener('pointerdown', (event) => {
        event.preventDefault();
        const left = handle.previousElementSibling;
        const right = handle.nextElementSibling;
        if (!left || !right) return;
        const startX = event.clientX;
        const leftStart = left.offsetWidth;
        const rightStart = right.offsetWidth;
        const minLeft = isInspector(left) ? MIN_INSPECTOR : MIN_PANEL;
        const minRight = isInspector(right) ? MIN_INSPECTOR : MIN_PANEL;
        handle.classList.add('active');
        document.body.classList.add('resizing');
        try { handle.setPointerCapture(event.pointerId); } catch { /* noop */ }
        const onMove = (e) => {
          const dx = e.clientX - startX;
          let lw = leftStart + dx;
          let rw = rightStart - dx;
          if (lw < minLeft) { rw -= minLeft - lw; lw = minLeft; }
          if (rw < minRight) { lw -= minRight - rw; rw = minRight; }
          left.style.width = lw + 'px';
          right.style.width = rw + 'px';
        };
        const onUp = () => {
          handle.classList.remove('active');
          document.body.classList.remove('resizing');
          handle.removeEventListener('pointermove', onMove);
          handle.removeEventListener('pointerup', onUp);
          handle.removeEventListener('pointercancel', onUp);
          this.savePanelWidths();
        };
        handle.addEventListener('pointermove', onMove);
        handle.addEventListener('pointerup', onUp);
        handle.addEventListener('pointercancel', onUp);
      });
    });
  }

  savePanelWidths() {
    const req = this.querySelector('[data-panel="req"]');
    const resp = this.querySelector('[data-panel="resp"]');
    const sidebar = this.querySelector('inspector-panel');
    if (!req || !resp || !sidebar) return;
    localStorage.setItem('viewer:req', String(req.offsetWidth));
    localStorage.setItem('viewer:resp', String(resp.offsetWidth));
    localStorage.setItem('viewer:insp', String(sidebar.offsetWidth));
  }

  render(data) {
    const q = (role) => this.querySelector('[data-role="' + role + '"]');

    q('req-raw').textContent = data.requestRaw || '(empty)';
    q('resp-raw').textContent = data.responseRaw || '(empty)';
    if (data.requestPrettyHtml != null) {
      q('req-pretty').innerHTML = data.requestPrettyHtml;
    } else {
      q('req-pretty').textContent = data.requestPretty || '(empty)';
    }
    if (data.responsePrettyHtml != null) {
      q('resp-pretty').innerHTML = data.responsePrettyHtml;
    } else {
      q('resp-pretty').textContent = data.responsePretty || '(empty)';
    }

    q('req-hex').textContent = data.requestHex || '(empty)';
    q('resp-hex').textContent = data.responseHex || '(empty)';
    q('resp-render').srcdoc = data.responseRender || '<p>(empty response)</p>';
    if (this.inspector) {
      this.inspector.data = { sections: data.inspectorSections || [] };
    }
    this.querySelectorAll('.rv-panel').forEach((panel) => {
      panel.querySelectorAll('.subtab').forEach((b, i) => b.classList.toggle('active', i === 0));
      panel.querySelectorAll('.rv-pane').forEach((p, i) => p.classList.toggle('active', i === 0));
    });
  }
}

customElements.define('message-viewer', MessageViewer);
