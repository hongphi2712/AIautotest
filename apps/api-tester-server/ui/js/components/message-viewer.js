// Shared Request/Response viewer used by both Intercept and HTTP history.
// Usage: <message-viewer editable></message-viewer>, then `viewer.data = {...}`.
// Edit actions (apply) are emitted as `viewer-action` events.
//
// In `editable` mode (Intercept) the held message is shown as a single,
// directly editable raw editor + inspector — no mode switching, no overlay.
// Ctrl/Cmd+Z and Ctrl/Cmd+Y (or Ctrl/Cmd+Shift+Z) undo/redo the edits (see
// editor-undo.js). In the default mode (HTTP history) the read-only
// request | response | inspector panels are shown instead.
// The panel widths are draggable (pointer events) and persisted to
// localStorage; they never auto-size to content.
import { renderHttpWire, toHex } from '../api.js';
import { createUndoRedo, caretOffset, setCaret } from './editor-undo.js';
import './inspector-panel.js';

const MIN_PANEL = 120;
const MIN_INSPECTOR = 150;

/// Text after the first blank line of an HTTP message (its body). Used to fill
/// the Hex view of the edit editor for both requests and responses.
function bodyFromWire(wire) {
  const lines = String(wire || '').replace(/\r\n/g, '\n').split('\n');
  const blank = lines.findIndex((line, i) => i > 0 && line.trim() === '');
  return blank === -1 ? '' : lines.slice(blank + 1).join('\n');
}

function isInspector(element) {
  return element.tagName === 'INSPECTOR-PANEL' || element.classList.contains('inspector-sidebar');
}

function sanitizeRenderHtml(html) {
  if (!html) return '<p>(empty response)</p>';
  const doc = new DOMParser().parseFromString(html, 'text/html');
  return doc.body.innerHTML;
}

export class MessageViewer extends HTMLElement {
  connectedCallback() {
    if (this._initialized) return;
    this._initialized = true;
    const editable = this.hasAttribute('editable');
    this.innerHTML = this.template(editable);
    this.inspector = this.querySelector('inspector-panel');
    this.applyPanelWidths();
    this.initResizers();
    if (editable) {
      const editor = this.querySelector('[data-role="edit-editor"]');
      this._renderDoc = '<p>(empty response)</p>';
      this._editWire = '';
      this._editKind = 'request';
      this._editMode = 'pretty';
      this._undoRedo = createUndoRedo({
        element: editor,
        render: (text, caret) => {
          this._editWire = text;
          this.renderEditEditor();
          setCaret(editor, caret);
          this.updateEditLines();
        },
      });
      editor.addEventListener('input', () => this.onEditEditorInput());
      editor.addEventListener('scroll', () => {
        const lines = this.querySelector('[data-role="edit-lines"]');
        if (lines) lines.scrollTop = editor.scrollTop;
      });
    }
    this._clickHandler = (event) => {
      const editTab = event.target.closest('[data-edit-tab]');
      if (editTab) {
        this.setEditTab(editTab.dataset.editTab);
        return;
      }
      const tab = event.target.closest('.subtab');
      if (tab) {
        const panel = tab.closest('.rv-panel');
        if (panel) {
          panel.querySelectorAll('.subtab').forEach((b) => b.classList.remove('active'));
          panel.querySelectorAll('.rv-pane').forEach((p) => p.classList.remove('active'));
          tab.classList.add('active');
          panel.querySelector('[data-pane="' + tab.dataset.tab + '"]').classList.add('active');
        }
        return;
      }
      const action = event.target.closest('[data-action]');
      if (action) {
        this.dispatchEvent(new CustomEvent('viewer-action', { detail: action.dataset.action }));
      }
    };
    this.addEventListener('click', this._clickHandler);
  }

  disconnectedCallback() {
    if (this._clickHandler) {
      this.removeEventListener('click', this._clickHandler);
    }
  }

  set data(value) {
    this.applyPanelWidths();
    this.render(value);
  }

  template(editable) {
    if (editable) {
      return `
      <div class="inspector-layout">
        <div class="rv-panel" data-panel="msg">
          <div class="rv-header msg-header">
            <span class="rv-title" data-role="edit-title">No intercepted request</span>
            <div class="subtabs">
              <button class="subtab active" data-edit-tab="pretty">Pretty</button>
              <button class="subtab" data-edit-tab="raw">Raw</button>
              <button class="subtab" data-edit-tab="hex">Hex</button>
              <button class="subtab" data-edit-tab="render" hidden>Render</button>
            </div>
            <span style="flex:1"></span>
            <button class="btn primary" data-action="apply">Apply edits &amp; Forward</button>
          </div>
          <div class="http-editor" data-role="edit-editor-wrap" style="flex:1;min-height:0">
            <div class="http-line-nums" data-role="edit-lines"></div>
            <pre class="http-body" contenteditable="true" spellcheck="false" data-role="edit-editor" data-placeholder="No intercepted request"></pre>
          </div>
          <pre class="http-body" data-role="edit-hex" hidden></pre>
          <iframe class="render-frame" sandbox="" data-role="edit-render" hidden></iframe>
        </div>
        <div class="resizer" data-side="msg"></div>
        <inspector-panel id="inspector"></inspector-panel>
      </div>`;
    }
    return `
    <div class="inspector-layout">
      <div class="rv-panel" data-panel="req">
        <div class="rv-header"><span class="rv-title">Request</span></div>
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
        <div class="rv-pane" data-pane="render"><iframe class="render-frame" sandbox="allow-scripts" data-role="resp-render"></iframe></div>
      </div>
      <div class="resizer" data-side="resp"></div>
      <inspector-panel id="inspector"></inspector-panel>
    </div>`;
  }

  applyPanelWidths() {
    const layout = this.querySelector('.inspector-layout');
    if (!layout) return;
    if (this.hasAttribute('editable')) {
      const msg = layout.querySelector('[data-panel="msg"]');
      const sidebar = layout.querySelector('inspector-panel');
      if (!msg || !sidebar) return;
      const savedInsp = Number(localStorage.getItem('viewer:insp')) || 0;
      const width = layout.clientWidth;
      let insp;
      if (savedInsp > 0 && width > 0) {
        insp = Math.min(savedInsp, width - MIN_PANEL);
      } else if (width > 0) {
        insp = Math.max(MIN_INSPECTOR, Math.round(width * 0.22));
      } else {
        insp = MIN_INSPECTOR;
      }
      sidebar.style.width = insp + 'px';
      msg.style.width = Math.max(MIN_PANEL, width - insp) + 'px';
      return;
    }
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
    if (this.hasAttribute('editable')) {
      const msg = this.querySelector('[data-panel="msg"]');
      const sidebar = this.querySelector('inspector-panel');
      if (!msg || !sidebar) return;
      localStorage.setItem('viewer:msg', String(msg.offsetWidth));
      localStorage.setItem('viewer:insp', String(sidebar.offsetWidth));
      return;
    }
    const req = this.querySelector('[data-panel="req"]');
    const resp = this.querySelector('[data-panel="resp"]');
    const sidebar = this.querySelector('inspector-panel');
    if (!req || !resp || !sidebar) return;
    localStorage.setItem('viewer:req', String(req.offsetWidth));
    localStorage.setItem('viewer:resp', String(resp.offsetWidth));
    localStorage.setItem('viewer:insp', String(sidebar.offsetWidth));
  }

  /// Loads the held message into the (always visible) editor. The editor is
  /// disabled and the undo/redo history is reset when `wire` is empty.
  setEditContent({ title, wire, kind }) {
    this._editTitle = title || 'Edit message';
    this._editWire = String(wire || '');
    this._editKind = kind === 'response' ? 'response' : 'request';
    if (this._editMode === 'render' && this._editKind !== 'response') {
      this._editMode = 'pretty';
    }
    if (!this._editMode) this._editMode = 'pretty';
    this._undoRedo.reset(this._editWire);

    const titleEl = this.querySelector('[data-role="edit-title"]');
    if (titleEl) titleEl.textContent = this._editTitle;
    const editor = this.querySelector('[data-role="edit-editor"]');
    if (editor) editor.contentEditable = this._editWire ? 'true' : 'false';
    const renderTab = this.querySelector('[data-edit-tab="render"]');
    if (renderTab) renderTab.hidden = this._editKind !== 'response';
    this.renderEditMode();
  }

  editWire() {
    return this._editWire;
  }

  setEditTab(mode) {
    if (mode === 'render' && this._editKind !== 'response') return;
    this._editMode = mode;
    this.renderEditMode();
  }

  renderEditMode() {
    const wrap = this.querySelector('[data-role="edit-editor-wrap"]');
    const hex = this.querySelector('[data-role="edit-hex"]');
    const frame = this.querySelector('[data-role="edit-render"]');
    this.querySelectorAll('[data-edit-tab]').forEach((b) => {
      b.classList.toggle('active', b.dataset.editTab === this._editMode);
    });
    if (this._editMode === 'hex') {
      wrap.hidden = true;
      hex.hidden = false;
      if (frame) frame.hidden = true;
      hex.textContent = toHex(bodyFromWire(this._editWire));
      return;
    }
    if (this._editMode === 'render') {
      wrap.hidden = true;
      hex.hidden = true;
      if (frame) {
        frame.hidden = false;
        frame.srcdoc = sanitizeRenderHtml(this._renderDoc);
      }
      return;
    }
    wrap.hidden = false;
    hex.hidden = true;
    if (frame) frame.hidden = true;
    this.renderEditEditor();
    this.updateEditLines();
  }

  renderEditEditor() {
    const editor = this.querySelector('[data-role="edit-editor"]');
    if (!editor) return;
    if (this._editMode === 'pretty') {
      editor.innerHTML = renderHttpWire(this._editWire, this._editKind);
    } else {
      editor.textContent = this._editWire;
    }
  }

  onEditEditorInput() {
    const editor = this.querySelector('[data-role="edit-editor"]');
    if (!editor) return;
    this._undoRedo.commit(editor.textContent);
    const caret = caretOffset(editor);
    this._editWire = editor.textContent;
    this.renderEditEditor();
    setCaret(editor, caret);
    this.updateEditLines();
  }

  updateEditLines() {
    const count = this._editWire.split('\n').length;
    const lines = this.querySelector('[data-role="edit-lines"]');
    if (lines) lines.textContent = Array.from({ length: count }, (_, i) => i + 1).join('\n');
  }

  render(data) {
    if (this.hasAttribute('editable')) {
      this._renderDoc = data.responseRender || '<p>(empty response)</p>';
      if (this._editMode === 'render') {
        const frame = this.querySelector('[data-role="edit-render"]');
        if (frame) frame.srcdoc = sanitizeRenderHtml(this._renderDoc);
      }
      if (this.inspector) {
        this.inspector.data = { sections: data.inspectorSections || [] };
      }
      return;
    }
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
    q('resp-render').srcdoc = sanitizeRenderHtml(data.responseRender);
    if (this.inspector) {
      this.inspector.data = { sections: data.inspectorSections || [] };
    }
    this.querySelectorAll('.rv-panel').forEach((panel) => {
      panel.querySelectorAll('.subtab').forEach((b, i) => b.classList.toggle('active', i === 0));
      panel.querySelectorAll('.rv-pane').forEach((p, i) => p.classList.toggle('active', i === 0));
    });
  }
}

if (!customElements.get('message-viewer')) customElements.define('message-viewer', MessageViewer);
