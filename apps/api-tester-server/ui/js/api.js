// REST API client: the UI is served by the axum backend on the same origin,
// so commands are plain fetch() calls (no Tauri IPC anymore).
async function request(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const data = await response.json();
      if (data && data.error) detail = data.error;
    } catch { /* not JSON */ }
    throw new Error(detail || response.statusText);
  }
  return response.json();
}

export function apiGet(path) {
  return request(path);
}

export function apiPost(path, body) {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body == null ? undefined : JSON.stringify(body),
  });
}

export function formatStatus(code) { return code === 0 ? 'N/A' : String(code); }

export function colorStatus(code) {
  if (code >= 200 && code < 300) return 'status-2';
  if (code >= 400) return 'status-4';
  if (code >= 300) return 'status-3';
  return '';
}

export function formatTime(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function shortCookies(cookies) {
  if (!cookies || !cookies.length) return '-';
  return cookies.length + ' cookie' + (cookies.length === 1 ? '' : 's');
}

export function shortUrl(f) {
  const v = f.path || '/';
  return v.length > 72 ? v.slice(0, 69) + '...' : v;
}

export function toHex(value) {
  return Array.from(new TextEncoder().encode(value || '')).map((b, i) => (i % 16 === 0 ? '\n' : '') + b.toString(16).padStart(2, '0')).join('').trim() || '(empty)';
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

export function formatHeaders(headers) {
  if (!headers) return '';
  if (Array.isArray(headers)) {
    return headers
      .map((h) => (h && h.name !== undefined ? `${capitalizeHeader(h.name)}: ${h.value}` : String(h)))
      .join('\n');
  }
  if (typeof headers === 'object') {
    return Object.entries(headers)
      .map(([name, value]) => `${capitalizeHeader(name)}: ${value}`)
      .join('\n');
  }
  return String(headers);
}

/// Renders a header name in canonical HTTP/1.1 title case, e.g.
/// `content-type` -> `Content-Type`, `x-transaction-id` -> `X-Transaction-Id`.
export function capitalizeHeader(name) {
  return String(name)
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('-');
}

/// Formats a date as an HTTP `Date` header value (`Fri, 14 Aug 2026 02:17:50 GMT`).
export function toHttpDate(date) {
  if (date instanceof Date) return date.toUTCString();
  if (typeof date === 'string' || typeof date === 'number') {
    const parsed = new Date(date);
    if (!Number.isNaN(parsed.getTime())) return parsed.toUTCString();
  }
  return new Date().toUTCString();
}

/// Ensures a `Date:` header is the first line of the header block. When the
/// captured headers already carry one it is moved to the top; otherwise one is
/// generated from `date`. HTTP servers are expected to send a `Date`, but some
/// omit it (and hyper stores headers alphabetically, not in send order).
function ensureDateHeader(headersText, date) {
  const lines = (headersText || '').split('\n').filter((line) => line.trim() !== '');
  const idx = lines.findIndex((line) => /^date:/i.test(line));
  let dateLine;
  if (idx >= 0) {
    dateLine = `Date: ${lines.splice(idx, 1)[0].replace(/^date:\s*/i, '')}`;
  } else {
    dateLine = `Date: ${toHttpDate(date)}`;
  }
  return [dateLine, ...lines].join('\n');
}

export function showError(message) {
  window.dispatchEvent(new CustomEvent('app:error', { detail: message }));
}

export async function openBrowser() {
  await apiPost('/api/browser/open');
}

const INLINE_TAGS = new Set(['span', 'a', 'b', 'i', 'em', 'strong', 'small', 'code', 'img', 'br', 'input', 'label', 'option', 'select', 'textarea', 'button', 'meta', 'link', 'script', 'style', 'wbr']);
const VOID_TAGS = new Set(['br', 'img', 'input', 'meta', 'link', 'hr', 'source', 'wbr', 'area', 'base', 'col', 'embed', 'param', 'track']);

/// Indents HTML tags into a readable hierarchy. Deliberately small (no deps):
/// block-level tags get indented, inline tags and text nodes stay inline.
export function beautifyHtml(html) {
  const tokens = String(html).replace(/>\s*</g, '><').split(/(<[^>]*>)/g);
  let out = '';
  let indent = 0;
  const pad = () => '  '.repeat(indent);
  for (const token of tokens) {
    if (!token) continue;
    if (token[0] === '<') {
      if (token.startsWith('<!--')) {
        out += pad() + token + '\n';
        continue;
      }
      const isClose = token.startsWith('</');
      const tagMatch = token.match(/^<\/?\s*([a-zA-Z0-9]+)/);
      const tag = tagMatch ? tagMatch[1].toLowerCase() : '';
      const selfClose = token.endsWith('/>') || VOID_TAGS.has(tag);
      if (isClose) {
        indent = Math.max(0, indent - 1);
        out += pad() + token + '\n';
      } else {
        out += pad() + token;
        if (!INLINE_TAGS.has(tag)) {
          out += '\n';
          if (!selfClose) indent += 1;
        }
      }
    } else {
      const text = token.trim();
      if (text) {
        out += (out.endsWith('\n') ? pad() : '') + text + '\n';
      }
    }
  }
  return out.replace(/\n{2,}/g, '\n').trim();
}

/// Pretty-prints a message body based on its content type.
export function prettyBody(contentType, body) {
  if (!body) return '';
  const ct = (contentType || '').toLowerCase();
  if (ct.includes('json')) {
    try {
      return JSON.stringify(JSON.parse(body), null, 2);
    } catch {
      return body;
    }
  }
  if (ct.includes('html') || ct.includes('xml')) {
    return beautifyHtml(body);
  }
  return body;
}

export function isJsonContentType(contentType) {
  return (contentType || '').toLowerCase().includes('json');
}

/// Reads the content-type header from a headers object, a `{name,value}` list,
/// or a `[name, value]` tuple list (repeater responses).
export function contentTypeFromHeaders(headers) {
  if (!headers) return '';
  const find = (name) => {
    if (Array.isArray(headers)) {
      const hit = headers.find((h) => {
        if (h && typeof h === 'object' && h.name !== undefined) {
          return String(h.name).toLowerCase() === name;
        }
        if (Array.isArray(h)) return String(h[0]).toLowerCase() === name;
        return false;
      });
      if (!hit) return '';
      return hit.name !== undefined ? String(hit.value) : String(hit[1]);
    }
    if (typeof headers === 'object') {
      const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
      return key ? String(headers[key]) : '';
    }
    return '';
  };
  return find('content-type');
}

/// Canonical start line for an HTTP request (`METHOD url HTTP/1.1`) or
/// response (`HTTP/2 status reason`).
export function httpStartLine({ method, url, status, reason }) {
  return status != null
    ? `HTTP/2 ${status}${reason ? ' ' + reason : ''}`
    : `${method} ${url} HTTP/1.1`;
}

/// Builds `raw` (as-stored) and `pretty` (formatted) message texts for the
/// message viewer. `status != null` renders a response start line and, when the
/// headers lack one, injects a `Date:` header from `date`.
export function buildMessage({ method, url, status, reason, headersText, body, contentType, date }) {
  const startLine = httpStartLine({ method, url, status, reason });
  const head = status != null ? ensureDateHeader(headersText, date) : headersText;
  const raw = startLine + '\n' + head + '\n\n' + (body || '');
  const pretty = startLine + '\n' + head + '\n\n' + prettyBody(contentType, body);
  return { raw, pretty };
}

function escapeHtmlInline(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const JSON_TOKEN = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(\btrue\b|\bfalse\b|\bnull\b)/g;

/// Wraps JSON tokens in syntax-highlight spans. Input must be normalized JSON
/// (`JSON.stringify` output); every interpolated string is HTML-escaped.
export function highlightJson(text) {
  return String(text).replace(JSON_TOKEN, (match, str, colon, num, lit) => {
    if (str !== undefined) {
      const cls = colon ? 'tok-key' : 'tok-str';
      return `<span class="${cls}">${escapeHtmlInline(str)}</span>${colon ? escapeHtmlInline(colon) : ''}`;
    }
    if (num !== undefined) return `<span class="tok-num">${match}</span>`;
    if (lit !== undefined) return `<span class="tok-lit">${match}</span>`;
    return match;
  });
}

/// Parses an HTTP request given in wire format into its parts. Used by the
/// Repeater to turn the user-edited text back into a sendable request.
export function parseHttpRequest(text) {
  const normalized = String(text || '').replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  let start = 0;
  while (start < lines.length && !lines[start].trim()) start++;
  const requestLine = (lines[start] || '').trim();
  const parts = requestLine.split(/\s+/);
  const method = parts[0] || 'GET';
  let path = parts[1] || '/';
  const version = parts[2] || 'HTTP/1.1';

  const headers = [];
  let j = start + 1;
  while (j < lines.length && lines[j].trim() !== '') {
    const idx = lines[j].indexOf(':');
    if (idx > 0) {
      headers.push({ name: lines[j].slice(0, idx).trim(), value: lines[j].slice(idx + 1).trim() });
    }
    j++;
  }
  const body = lines.slice(j + 1).join('\n');
  const host = headers.find((h) => h.name.toLowerCase() === 'host')?.value || 'example.com';
  let url = `http://${host}${path}`;
  // Absolute-form request target (`GET http://example.com/...`) already
  // contains the full URL; do not double-prepend the Host.
  if (/^https?:\/\//i.test(path)) {
    url = path;
    try {
      const parsedUrl = new URL(path);
      path = parsedUrl.pathname + parsedUrl.search;
    } catch { /* keep original path */ }
  }
  return { method, path, version, headers, body, url };
}

/// Parses query parameters out of a URL.
export function parseQueryParams(url) {
  const out = [];
  try {
    const parsed = new URL(url);
    for (const [name, value] of parsed.searchParams.entries()) {
      out.push({ name, value });
    }
  } catch { /* ignore */ }
  return out;
}

/// Best-effort body parameter extraction for the inspector.
export function parseBodyParams(contentType, body) {
  const ct = (contentType || '').toLowerCase();
  const out = [];
  if (!body) return out;
  if (isJsonContentType(ct)) {
    try {
      const parsed = JSON.parse(body);
      for (const [name, value] of Object.entries(parsed)) {
        out.push({ name, value: value && typeof value === 'object' ? JSON.stringify(value) : String(value) });
      }
    } catch { /* not JSON after all */ }
    return out;
  }
  if (ct.includes('x-www-form-urlencoded')) {
    for (const pair of body.split('&')) {
      if (!pair) continue;
      const [name, value] = pair.split('=');
      if (name) out.push({ name: decodeURIComponent(name), value: decodeURIComponent(value || '') });
    }
    return out;
  }
  if (ct.includes('multipart/form-data')) {
    const names = [...body.matchAll(/name="([^"]+)"/g)].map((m) => m[1]);
    names.forEach((name) => out.push({ name, value: '(multipart part)' }));
    return out;
  }
  return out;
}

/// Parses cookie headers (`Cookie` for requests, `Set-Cookie` for responses).
export function parseCookies(headers, response) {
  const out = [];
  const wanted = response ? 'set-cookie' : 'cookie';
  for (const header of headers || []) {
    if ((header.name || '').toLowerCase() !== wanted) continue;
    for (const part of String(header.value || '').split(/;\s*/)) {
      const idx = part.indexOf('=');
      if (idx > 0) out.push({ name: part.slice(0, idx).trim(), value: part.slice(idx + 1).trim() });
    }
  }
  return out;
}

/// Renders an HTTP request/response wire text as escaped, syntax-highlighted
/// HTML (status line, header names, and JSON bodies). Safe for `innerHTML`.
export function renderHttpWire(text, kind) {
  const normalized = String(text || '').replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  let start = 0;
  while (start < lines.length && !lines[start].trim()) start++;
  const blank = lines.findIndex((l, i) => i > start && l.trim() === '');
  const headEnd = blank === -1 ? lines.length : blank;
  const head = lines.slice(start, headEnd);
  const body = blank === -1 ? '' : lines.slice(blank + 1).join('\n');

  let contentType = '';
  let html = '';
  head.forEach((line, i) => {
    if (i === 0) {
      if (kind === 'request') {
        const parts = line.trim().split(/\s+/);
        html += `<span class="http-method">${escapeHtmlInline(parts[0] || '')}</span> <span class="http-path">${escapeHtmlInline(parts[1] || '')}</span> <span class="http-version">${escapeHtmlInline(parts[2] || '')}</span>`;
      } else {
        html += `<span class="http-status-line">${escapeHtmlInline(line)}</span>`;
      }
      html += '\n';
      return;
    }
    const idx = line.indexOf(':');
    if (idx > 0) {
      const name = line.slice(0, idx);
      const value = line.slice(idx + 1).trim();
      if (name.toLowerCase() === 'content-type') contentType = value;
      html += `<span class="http-header-name">${escapeHtmlInline(name)}</span>: ${escapeHtmlInline(value)}`;
    } else {
      html += escapeHtmlInline(line);
    }
    html += '\n';
  });

  if (body) {
    const ct = contentType.toLowerCase();
    if (isJsonContentType(ct) || body.trim().startsWith('{') || body.trim().startsWith('[')) {
      const pretty = prettyBody(ct, body);
      html += '\n' + highlightJson(pretty);
    } else {
      html += '\n' + escapeHtmlInline(body);
    }
  }
  return html;
}
