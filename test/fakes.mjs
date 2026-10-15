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
  };
  return bucket;
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
