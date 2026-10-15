import { CodedError } from './bytes.mjs';

// Secrets Store bindings expose `get()`. Plain string vars are refused so a misconfigured env var can never stand in.
export async function readSecret(binding) {
  if (!binding || typeof binding.get !== 'function') throw new CodedError('secret_unbound');
  const value = await binding.get();
  if (typeof value !== 'string' || value.length === 0) throw new CodedError('secret_empty');
  return value;
}

// Absent binding or absent secret both mean "not configured" (used for OBSERVATORY_WEBHOOK_SECRET_PREVIOUS outside rotation).
export async function readOptionalSecret(binding) {
  if (!binding) return null;
  try { return await readSecret(binding); } catch { return null; }
}
