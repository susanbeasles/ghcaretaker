// Test doubles. node:sqlite stands in for Durable Object SQL storage (same SQLite engine and SQL dialect).
// Secret values here are generated per test run; nothing is a real credential.
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';

export function sqlStorage() {
  const db = new DatabaseSync(':memory:');
  let alarm = null;
  const cursor = rows => ({
    toArray: () => rows,
    one: () => { if (rows.length !== 1) throw Error('expected exactly one row'); return rows[0]; },
  });
  return {
    db,
    sql: {
      exec(query, ...bindings) {
        const statement = db.prepare(query);
        return cursor(statement.all(...bindings).map(r => ({ ...r })));
      },
    },
    transactionSync(fn) {
      db.exec('BEGIN');
      try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
    },
    async getAlarm() { return alarm; },
    async setAlarm(t) { alarm = t; },
    async deleteAlarm() { alarm = null; },
    get alarmAt() { return alarm; },
  };
}

export function memoryR2() {
  const objects = new Map();
  const bucket = {
    objects, puts: 0, fail: false,
    async put(key, value, options = {}) {
      if (bucket.fail) throw Error('r2 unavailable');
      const ifNoneMatch = options.onlyIf instanceof Headers ? options.onlyIf.get('if-none-match') : null;
      if (ifNoneMatch === '*' && objects.has(key)) return null;
      bucket.puts++;
      const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : new Uint8Array(value);
      objects.set(key, { bytes, customMetadata: { ...options.customMetadata }, httpMetadata: options.httpMetadata, sha256: options.sha256 });
      return { key };
    },
    async head(key) { const o = objects.get(key); return o ? { key, customMetadata: o.customMetadata } : null; },
    async get(key) {
      const o = objects.get(key);
      if (!o) return null;
      return { key, customMetadata: o.customMetadata, body: new Blob([o.bytes]).stream(), text: async () => new TextDecoder().decode(o.bytes) };
    },
    json(key) { return JSON.parse(new TextDecoder().decode(objects.get(key).bytes)); },
    // R2 list semantics used by the anchors: ascending keys, prefix, startAfter (exclusive), limit, opaque cursor.
    async list({ prefix = '', startAfter, cursor, limit = 1000 } = {}) {
      const keys = [...objects.keys()].filter(k => k.startsWith(prefix) && (startAfter === undefined || k > startAfter)).sort();
      const from = cursor ? Number(cursor) : 0, page = keys.slice(from, from + limit), truncated = from + limit < keys.length;
      return { objects: page.map(key => ({ key, customMetadata: objects.get(key).customMetadata })), truncated, ...(truncated ? { cursor: String(from + limit) } : {}) };
    },
  };
  return bucket;
}

// Captures structured log lines (console.log/warn/error) while `fn` runs, for "nothing sensitive is logged" checks.
export async function captureLogs(fn) {
  const lines = [], saved = { log: console.log, warn: console.warn, error: console.error };
  for (const k of Object.keys(saved)) console[k] = (...a) => lines.push(a.map(String).join(' '));
  try { return { result: await fn(), lines }; } finally { Object.assign(console, saved); }
}

// A promise with its resolver exposed, for holding an effect open while a test observes the caller.
export function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

export const secret = value => ({ get: async () => value });
export const randomSecret = () => crypto.randomUUID() + crypto.randomUUID();

export function clock(start = Date.parse('2026-10-15T12:00:00Z')) {
  let t = start;
  const now = () => t;
  now.advance = ms => { t += ms; };
  return now;
}

// Namespace stub that routes idFromName(name).get() to one in-process core per name.
export function namespace(factory) {
  const instances = new Map();
  return {
    instances,
    idFromName: name => name,
    get: name => { if (!instances.has(name)) instances.set(name, factory(name)); return instances.get(name); },
  };
}

export async function sign(secretValue, body) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secretValue), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, typeof body === 'string' ? new TextEncoder().encode(body) : body));
  return 'sha256=' + [...mac].map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function pkcs8Pem() {
  const k = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const bytes = await crypto.subtle.exportKey('pkcs8', k.privateKey);
  return { pem: '-----BEGIN PRIVATE KEY-----\n' + Buffer.from(bytes).toString('base64') + '\n-----END PRIVATE KEY-----', publicKey: k.publicKey };
}

export const sha = n => createHash('sha1').update('commit-' + n).digest('hex');

// D1 stand-in over node:sqlite (D1 is SQLite): prepare/bind/first/all/run and an all-or-nothing batch.
export function d1Database(schemaSql) {
  const db = new DatabaseSync(':memory:');
  if (schemaSql) db.exec(schemaSql);
  const statement = (query, args = []) => ({
    query, args,
    bind: (...values) => {
      if (values.some(v => v === undefined)) throw new TypeError('D1_TYPE_ERROR: undefined is not a supported bind value');
      return statement(query, values);
    },
    async first(column) { const row = db.prepare(query).get(...args); if (!row) return null; return column ? row[column] : { ...row }; },
    async all() { return { success: true, results: db.prepare(query).all(...args).map(r => ({ ...r })), meta: {} }; },
    async run() { const r = db.prepare(query).run(...args); return { success: true, meta: { changes: Number(r.changes) } }; },
  });
  const fake = {
    db, failNextBatch: false, batches: 0,
    prepare: query => statement(query),
    async batch(statements) {
      if (fake.failNextBatch) { fake.failNextBatch = false; throw new Error('d1 unavailable'); }
      fake.batches++;
      db.exec('BEGIN');
      try {
        const out = statements.map(s => { const r = db.prepare(s.query).run(...s.args); return { success: true, meta: { changes: Number(r.changes) } }; });
        db.exec('COMMIT');
        return out;
      } catch (e) { db.exec('ROLLBACK'); throw e; }
    },
  };
  return fake;
}

// Cloudflare Access stand-in: an RS256 key pair generated per test run, its JWKS at the team certs URL, and a signer.
export const ACCESS_TEAM = 'https://vespoli.cloudflareaccess.com';
export const ACCESS_AUD_TEST = 'a'.repeat(32) + 'b'.repeat(32);
export const OWNER_EMAIL_TEST = 'owner@vespoli.test';
export async function accessKit({ kid = 'kid-' + crypto.randomUUID() } = {}) {
  const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const keys = [{ kid, kty: 'RSA', alg: 'RS256', use: 'sig', n: jwk.n, e: jwk.e }];
  const b64u = bytes => Buffer.from(bytes).toString('base64url');
  const kit = {
    kid, keys, certFetches: 0,
    env: { ACCESS_TEAM_DOMAIN: ACCESS_TEAM, ACCESS_AUD: ACCESS_AUD_TEST, OWNER_EMAIL: OWNER_EMAIL_TEST },
    claims: (over = {}) => { const t = Math.floor(Date.now() / 1000); return { aud: [ACCESS_AUD_TEST], email: OWNER_EMAIL_TEST, exp: t + 600, iat: t - 10, nbf: t - 10, iss: ACCESS_TEAM, sub: 'owner-sub', type: 'app', ...over }; },
    async sign(claims = kit.claims(), header = {}, key = pair.privateKey) {
      const input = b64u(Buffer.from(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT', ...header }))) + '.' + b64u(Buffer.from(JSON.stringify(claims)));
      const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(input));
      return input + '.' + b64u(new Uint8Array(sig));
    },
    fetcher: async (url, init) => {
      if (url !== ACCESS_TEAM + '/cdn-cgi/access/certs') return new Response(null, { status: 599 });
      if (init?.redirect !== 'manual') throw new Error('certs must be fetched with redirect: manual (and 3xx refused)');
      kit.certFetches++;
      return Response.json({ keys: kit.keys, public_cert: {}, public_certs: [] });
    },
  };
  return kit;
}
