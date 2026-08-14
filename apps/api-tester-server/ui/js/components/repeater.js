import { invoke } from '../api.js';

const TEMPLATE = `
  <div class="toolbar"><strong>Repeater</strong><button class="btn primary" id="send">Send</button><span id="repeater-state" class="muted">Edit request and resend it</span></div>
  <div class="repeater">
    <div class="repeater-grid"><label>Method</label><input id="rep-method" value="GET"><label>URL</label><input id="rep-url" placeholder="https://example.com/path"><label>Headers</label><textarea id="rep-headers" placeholder='{"Accept":"application/json"}'></textarea><label>Body</label><textarea id="rep-body"></textarea></div>
    <h3>Response</h3><pre id="rep-response">No request sent.</pre>
  </div>
`;

export class RepeaterView extends HTMLElement {
  connectedCallback() {
    this.innerHTML = TEMPLATE;
    this.querySelector('#send').addEventListener('click', () => this.send());
    this.onLoad = (event) => {
      const f = event.detail;
      this.querySelector('#rep-method').value = f.method;
      this.querySelector('#rep-url').value = f.full_url;
      this.querySelector('#rep-headers').value = JSON.stringify(f.request_headers || {}, null, 2);
      this.querySelector('#rep-body').value = f.request_body || '';
      window.dispatchEvent(new CustomEvent('app:navigate', { detail: { view: 'repeater' } }));
    };
    window.addEventListener('app:repeater-load', this.onLoad);
  }

  disconnectedCallback() {
    window.removeEventListener('app:repeater-load', this.onLoad);
  }

  async send() {
    const state = this.querySelector('#repeater-state');
    state.textContent = 'Sending...';
    let headers;
    try { headers = JSON.parse(this.querySelector('#rep-headers').value || '{}'); }
    catch (error) { state.textContent = 'Headers must be valid JSON'; return; }
    try {
      const result = await invoke('repeater_send', { request: {
        method: this.querySelector('#rep-method').value,
        url: this.querySelector('#rep-url').value,
        headers, body: this.querySelector('#rep-body').value,
      } });
      this.querySelector('#rep-response').textContent = result.error
        ? result.error
        : 'HTTP ' + result.status + ' | ' + result.length + ' bytes\n\n' + result.body;
      state.textContent = result.error ? 'Request failed' : 'Response received';
    } catch (error) {
      this.querySelector('#rep-response').textContent = String(error);
      state.textContent = 'Request failed';
    }
  }
}

customElements.define('repeater-view', RepeaterView);
