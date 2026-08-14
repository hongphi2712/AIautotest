export const invoke = window.__TAURI__.core.invoke;

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

export function getExtension(path) {
  const clean = path.split('?')[0];
  const m = clean.match(/\.([a-z0-9]+)$/i);
  return m ? m[1] : '-';
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
  await invoke('open_browser');
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

/// Reads the content-type header from a headers object or `[{name,value}]` list.
export function contentTypeFromHeaders(headers) {
  if (!headers) return '';
  const find = (name) => {
    if (Array.isArray(headers)) {
      const hit = headers.find((h) => h && h.name && h.name.toLowerCase() === name);
      return hit ? hit.value : '';
    }
    if (typeof headers === 'object') {
      const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
      return key ? String(headers[key]) : '';
    }
    return '';
  };
  return find('content-type');
}

/// Builds `raw` (as-stored) and `pretty` (formatted) message texts for the
/// message viewer. `status != null` renders a response start line and, when the
/// headers lack one, injects a `Date:` header from `date`.
export function buildMessage({ method, url, status, reason, headersText, body, contentType, date }) {
  const startLine = status != null
    ? `HTTP/2 ${status}${reason ? ' ' + reason : ''}`
    : `${method} ${url} HTTP/1.1`;
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
