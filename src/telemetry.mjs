// Parser for the one line `actions/runner-telemetry` (workflow_depot) prints in a job's post step:
//   ##[runner-telemetry]{"schema":"runner-telemetry/v1",...}
// The job log is untrusted text (any step can print anything), so the line is validated strictly: exact key set,
// bounded numbers, no extra fields. Only the LAST line containing the marker is considered; when it is missing or
// invalid there is no telemetry (null), never a fallback to an earlier line and never an invented value.
import { decodeUtf8 } from './bytes.mjs';

export const TELEMETRY_MARKER = '##[runner-telemetry]';
export const TELEMETRY_SCHEMA = 'runner-telemetry/v1';
export const MAX_TELEMETRY_LINE = 4096;

const MAX_BYTES = 2 ** 50; // 1 PiB: far above any runner, far below 2^53
const MAX_DURATION_S = 35 * 86_400; // self-hosted jobs may run up to 5 days; leave room
const int = (min, max) => v => Number.isSafeInteger(v) && v >= min && v <= max;
const num = (min, max) => v => typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max;
const nullable = check => v => v === null || check(v);
const bytes = nullable(int(0, MAX_BYTES));
const fraction = nullable(num(0, 1));

// Every key is required; the value must pass its check. Keep in step with workflow_depot actions/runner-telemetry/lib.mjs.
export const TELEMETRY_FIELDS = Object.freeze({
  schema: v => v === TELEMETRY_SCHEMA,
  os: v => v === 'linux',
  arch: v => typeof v === 'string' && /^[a-z0-9_]{1,16}$/.test(v),
  cpu_count: int(1, 4096),
  memory_total_bytes: bytes,
  samples: int(2, 20_001),
  duration_s: num(0, MAX_DURATION_S),
  interval_s: int(1, 60),
  cpu_mean: fraction,
  cpu_p95: fraction,
  cpu_max: fraction,
  memory_used_max_bytes: bytes,
  memory_used_mean_bytes: bytes,
  disk_read_bytes: bytes,
  disk_write_bytes: bytes,
  net_rx_bytes: bytes,
  net_tx_bytes: bytes,
  load1_max: nullable(num(0, 100_000)),
  disk_free_min_bytes: bytes,
});

/** Returns the validated telemetry object, or null with no partial result. */
export function validateTelemetry(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return null;
  const keys = Object.keys(value), expected = Object.keys(TELEMETRY_FIELDS);
  if (keys.length !== expected.length || !keys.every(k => Object.hasOwn(TELEMETRY_FIELDS, k))) return null;
  for (const k of expected) if (!TELEMETRY_FIELDS[k](value[k])) return null;
  if (value.cpu_mean !== null && value.cpu_max !== null && value.cpu_mean > value.cpu_max + 1e-9) return null;
  if (value.cpu_p95 !== null && value.cpu_max !== null && value.cpu_p95 > value.cpu_max + 1e-9) return null;
  if (value.memory_used_max_bytes !== null && value.memory_total_bytes !== null && value.memory_used_max_bytes > value.memory_total_bytes) return null;
  // Rebuild in a fixed key order so what is stored is exactly the validated fields.
  return Object.fromEntries(expected.map(k => [k, value[k]]));
}

// A raw job log line is `<ISO timestamp> <text>`; the marker must start the text (nothing else before it).
const LINE_PREFIX = /^(?:\uFEFF)?(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z )?$/;

/** Parse the JSON after the marker on one line of text. */
export function parseTelemetryLine(line) {
  const at = typeof line === 'string' ? line.indexOf(TELEMETRY_MARKER) : -1;
  if (at < 0 || !LINE_PREFIX.test(line.slice(0, at))) return null;
  const json = line.slice(at + TELEMETRY_MARKER.length).replace(/\r$/, '');
  if (json.length === 0 || json.length > MAX_TELEMETRY_LINE || json[0] !== '{') return null;
  let value;
  try { value = JSON.parse(json); } catch { return null; }
  return validateTelemetry(value);
}

const MARKER_BYTES = new TextEncoder().encode(TELEMETRY_MARKER);

function lastIndexOfBytes(haystack, needle) {
  outer: for (let i = haystack.length - needle.length; i >= 0; i--) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

/**
 * Finds the last line of a (possibly truncated, possibly mid-character) log tail that contains the marker and
 * parses it. Only that line is decoded, as fatal UTF-8, so unrelated bytes elsewhere in the log do not matter.
 * Returns {telemetry, reason}: telemetry is null when reason is 'no_line' or 'invalid_line'.
 */
export function telemetryFromLog(bytesOfLog) {
  const data = bytesOfLog instanceof Uint8Array ? bytesOfLog : new Uint8Array(bytesOfLog);
  const at = lastIndexOfBytes(data, MARKER_BYTES);
  if (at < 0) return { telemetry: null, reason: 'no_line' };
  const start = data.lastIndexOf(0x0a, at) + 1;
  let end = data.indexOf(0x0a, at);
  if (end < 0) end = data.length;
  if (end - start > MAX_TELEMETRY_LINE + 256) return { telemetry: null, reason: 'invalid_line' };
  let line;
  try { line = decodeUtf8(data.subarray(start, end)); } catch { return { telemetry: null, reason: 'invalid_line' }; }
  const telemetry = parseTelemetryLine(line);
  return telemetry ? { telemetry, reason: 'ok' } : { telemetry: null, reason: 'invalid_line' };
}
