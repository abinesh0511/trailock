// Shared helpers for Trailock pages
const LOGO = `<svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="M16 2 28 7v8c0 7.5-5.2 12.8-12 15C9.2 27.8 4 22.5 4 15V7l12-5Z" stroke="#ffb547" stroke-width="2"/><circle cx="16" cy="15" r="4.5" stroke="#6fd3ff" stroke-width="2"/><path d="M16 19.5V24" stroke="#6fd3ff" stroke-width="2" stroke-linecap="round"/></svg>`;

// Simple fast hash (works on plain http too, unlike crypto.subtle)
function cyrb53(str, seed = 0) {
  let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761); h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(14, '0');
}

// Device fingerprint: browser + OS + screen + timezone + hardware
function deviceId() {
  let gpu = '';
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const ext = gl && gl.getExtension('WEBGL_debug_renderer_info');
    if (ext) gpu = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
  } catch (e) {}
  const parts = [navigator.userAgent, navigator.language, navigator.platform,
    screen.width + 'x' + screen.height, screen.colorDepth,
    Intl.DateTimeFormat().resolvedOptions().timeZone, navigator.hardwareConcurrency, gpu];
  return cyrb53(parts.join('|'));
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: 'same-origin'
  });
  let data = {};
  try { data = await res.json(); } catch (e) {}
  if (!res.ok) {
    const err = new Error(data.detail || `Request failed (${res.status})`);
    err.status = res.status; throw err;
  }
  return data;
}

function riskColor(s) { return s >= 70 ? 'var(--danger)' : s >= 35 ? 'var(--amber)' : 'var(--ok)'; }
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function place(e) { return [e.city, e.country].filter(Boolean).join(', ') || 'Unknown'; }

document.querySelectorAll('[data-logo]').forEach(el => el.insertAdjacentHTML('afterbegin', LOGO));
