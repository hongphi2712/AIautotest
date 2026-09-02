import { apiGet, apiPut, showError } from '../api.js';

const TEMPLATE = `
  <div class="target-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
    <details class="panel" open>
      <summary style="cursor:pointer"><h3 style="display:inline">Proxy Scope (Capture) — <span class="muted">quyết định traffic nào được lưu</span></h3></summary>
      <p class="muted" style="margin-top:8px">Chỉ capture host/path khớp include. Out-of-scope sẽ tunnel mù (không lưu). Dùng cho thu thập flows trước khi AI phân tích. — <i>Burp: Target scope</i></p>
      <div class="field-grid" style="margin-top:8px">
        <label>Include Hosts (regex, mỗi dòng 1)</label><textarea id="proxy-include-hosts" rows="3" placeholder="127\\.0\\.0\\.1
103\\.249\\.117\\.202
api\\.example\\.com"></textarea>
        <label>Exclude Hosts</label><textarea id="proxy-exclude-hosts" rows="2" placeholder="google\\.com"></textarea>
        <label>Include Paths</label><textarea id="proxy-include-paths" rows="2" placeholder="/api/.*"></textarea>
        <label>Exclude Paths</label><textarea id="proxy-exclude-paths" rows="2" placeholder=".*\\.(png|jpg|css|js)$"></textarea>
      </div>
      <div class="row" style="margin-top:12px">
        <button id="proxy-save" class="btn primary">Lưu Proxy Scope</button>
        <span id="proxy-status" class="muted"></span>
      </div>
    </details>
    <details class="panel">
      <summary style="cursor:pointer"><h3 style="display:inline">Security Scope (Intrusive) — <span class="muted">allowlist bắt buộc cho AI scan</span></h3> <span class="muted">(mặc định thu gọn để sitemap lên cao)</span></summary>
      <p class="muted" style="margin-top:8px">SecurityExecutor chỉ gửi request tới host/path trong allowlist này. <b>Bắt buộc non-empty</b> — nếu rỗng sẽ báo lỗi. Tách riêng để tránh scan nhầm sang CDN. — <i>Burp: Target &gt; Site map &gt; Filter + Right-click Add to scope</i></p>
      <div class="field-grid" style="margin-top:8px">
        <label>Include Hosts (regex, bắt buộc)</label><textarea id="sec-include-hosts" rows="3" placeholder="103\\.249\\.117\\.202
fit\\.neu\\.edu\\.vn
api\\.target\\.com"></textarea>
        <label>Exclude Hosts</label><textarea id="sec-exclude-hosts" rows="2"></textarea>
        <label>Include Paths</label><textarea id="sec-include-paths" rows="2" placeholder="/identity/.*
/workshop/.*"></textarea>
        <label>Exclude Paths</label><textarea id="sec-exclude-paths" rows="2" placeholder=".*\\.(png|jpg|css|js)$"></textarea>
      </div>
      <div class="row" style="margin-top:12px">
        <button id="sec-save" class="btn primary">Lưu Security Scope</button>
        <span id="sec-status" class="muted"></span>
      </div>
    </details>
  </div>
  <div class="panel" style="margin-top:12px">
    <h3>Base URL cho AI Generate</h3>
    <p class="muted">Base URL được dùng khi gọi <code>POST /api/security/generate {base_url}</code> — nên khớp 1 host trong Security Scope.</p>
    <div class="field-grid">
      <label>Base URL</label><input id="target-base-url" placeholder="http://103.249.117.202:44476">
    </div>
    <div class="row" style="margin-top:8px">
      <button id="base-save" class="btn">Lưu Base URL (localStorage)</button>
      <span id="base-status" class="muted"></span>
    </div>
  </div>
`;

function parseTextarea(id){
  const el=document.getElementById(id);
  if(!el) return [];
  return el.value.split('\n').map(s=>s.trim()).filter(Boolean);
}
function fillTextarea(id, arr){
  const el=document.getElementById(id);
  if(el) el.value=(arr||[]).join('\n');
}

export class TargetView extends HTMLElement {
  connectedCallback(){
    this.innerHTML=TEMPLATE;
    this.querySelector('#proxy-save').addEventListener('click',()=>this.saveProxy());
    this.querySelector('#sec-save').addEventListener('click',()=>this.saveSecurity());
    this.querySelector('#base-save').addEventListener('click',()=>this.saveBase());
    this.load();
    // prefill base_url from localStorage or last security plan
    const saved=localStorage.getItem('target.base_url');
    if(saved) this.querySelector('#target-base-url').value=saved;
  }
  async load(){
    try{
      const proxy=await apiGet('/api/scope');
      fillTextarea('proxy-include-hosts', proxy.include_hosts);
      fillTextarea('proxy-exclude-hosts', proxy.exclude_hosts);
      fillTextarea('proxy-include-paths', proxy.include_paths);
      fillTextarea('proxy-exclude-paths', proxy.exclude_paths);
    }catch(e){ this.querySelector('#proxy-status').textContent='Lỗi load proxy scope: '+e; }
    try{
      const sec=await apiGet('/api/security/scope');
      fillTextarea('sec-include-hosts', sec.include_hosts);
      fillTextarea('sec-exclude-hosts', sec.exclude_hosts);
      fillTextarea('sec-include-paths', sec.include_paths);
      fillTextarea('sec-exclude-paths', sec.exclude_paths);
    }catch(e){ this.querySelector('#sec-status').textContent='Lỗi load security scope: '+e; }
  }
  async saveProxy(){
    const btn=this.querySelector('#proxy-save');
    const st=this.querySelector('#proxy-status');
    btn.disabled=true; st.textContent='Đang lưu...';
    try{
      const body={
        include_hosts: parseTextarea('proxy-include-hosts'),
        exclude_hosts: parseTextarea('proxy-exclude-hosts'),
        include_paths: parseTextarea('proxy-include-paths'),
        exclude_paths: parseTextarea('proxy-exclude-paths'),
      };
      await apiPut('/api/scope', body);
      st.textContent='Đã lưu Proxy Scope';
    }catch(e){ showError('Proxy scope: '+e); st.textContent='Lỗi: '+e; }
    finally{ btn.disabled=false; }
  }
  async saveSecurity(){
    const btn=this.querySelector('#sec-save');
    const st=this.querySelector('#sec-status');
    btn.disabled=true; st.textContent='Đang lưu...';
    try{
      const body={
        include_hosts: parseTextarea('sec-include-hosts'),
        exclude_hosts: parseTextarea('sec-exclude-hosts'),
        include_paths: parseTextarea('sec-include-paths'),
        exclude_paths: parseTextarea('sec-exclude-paths'),
      };
      if(!body.include_hosts.length) throw new Error('Security include_hosts bắt buộc non-empty');
      await apiPut('/api/security/scope', body);
      st.textContent='Đã lưu Security Scope';
    }catch(e){ showError('Security scope: '+e); st.textContent='Lỗi: '+e; }
    finally{ btn.disabled=false; }
  }
  saveBase(){
    const v=this.querySelector('#target-base-url').value.trim();
    if(!v){ showError('Nhập base_url'); return; }
    try{ new URL(v); }catch{ showError('base_url không hợp lệ'); return; }
    localStorage.setItem('target.base_url', v);
    // also prefill analyzer inputs
    const wf=document.getElementById('wf-base');
    const sec=document.getElementById('sec-base');
    if(wf) wf.value=v;
    if(sec) sec.value=v;
    this.querySelector('#base-status').textContent='Đã lưu';
  }
}
if(!customElements.get('target-view')) customElements.define('target-view', TargetView);
