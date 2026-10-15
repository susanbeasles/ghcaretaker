// Byte-level primitives shared by the webhook ingress and the ledgers. No secrets pass through logs here.
const encoder = new TextEncoder();

export class CodedError extends Error {
  constructor(code, status = 0) { super(code); this.code = code; this.status = status; }
}
export class BodyTooLarge extends CodedError { constructor() { super('body_too_large'); } }

export const utf8 = text => encoder.encode(text);

// Fatal decoding: invalid UTF-8 is an error, never replaced. The BOM is preserved so text matches the raw bytes.
export function decodeUtf8(bytes) { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }

export function bytesToHex(bytes) {
  let out = '';
  for (const b of new Uint8Array(bytes)) out += b.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Constant time for equal-length inputs; the length itself is public (a SHA-256 MAC is always 32 bytes).
export function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export async function sha256Hex(data) {
  const bytes = typeof data === 'string' ? utf8(data) : data;
  return bytesToHex(await crypto.subtle.digest('SHA-256', bytes));
}

// Reads a stream while counting; never trusts a declared length. Cancels the stream as soon as the bound is crossed.
export async function readBounded(stream, limit) {
  if (!stream) return new Uint8Array(0);
  const reader = stream.getReader(), chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) { await reader.cancel().catch(() => {}); throw new BodyTooLarge(); }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
  return out;
}

// Bounded, fatal-UTF-8 JSON body of an upstream response.
export async function readJson(response, limit) { return JSON.parse(decodeUtf8(await readBounded(response.body, limit))); }

// The Workers runtime rejects `redirect: 'error'` ("Invalid redirect value, must be one of follow or manual"), so
// "never follow a redirect" is `redirect: 'manual'` plus this check: any 3xx is a failure and its body is discarded.
export class RedirectRefused extends CodedError { constructor(status) { super('redirect_refused', status); } }
export async function fetchNoRedirect(fetcher, url, init = {}) {
  const response = await fetcher(url, { ...init, redirect: 'manual' });
  if (response.status >= 300 && response.status < 400) { await response.body?.cancel().catch(() => {}); throw new RedirectRefused(response.status); }
  return response;
}

export const isPlainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
