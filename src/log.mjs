// Structured, body-free log lines. Callers pass identifiers and reason codes only, never payloads or secret values.
export function log(severity, event, fields = {}) {
  const line = JSON.stringify({ severity, event, ...fields });
  if (severity === 'critical' || severity === 'error') console.error(line);
  else if (severity === 'warning') console.warn(line);
  else console.log(line);
}

export const errorCode = error => String(error?.code || error?.name || 'error').replace(/[^A-Za-z0-9_.:-]/g, '_').slice(0, 80);
