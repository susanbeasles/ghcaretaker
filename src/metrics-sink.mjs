// Seam for the workflow metrics collector (ADR-0001 section 3). The event ledger outbox calls
// `metricsSinkFor(env).record(observation)` once per `workflow_run` / `workflow_job` delivery from an owned repository.
//
// Contract for an implementation:
// - Idempotent on `observation.delivery_id`: the outbox is at-least-once and will call again after any failure.
// - Throw to request a retry (backoff 30 s doubling to 1 h, forever; an operational alert after 8 attempts).
//   Return normally only once the observation is durably handled or deliberately ignored.
// - Read the raw payload with `readDelivery(env, observation.object_key, observation.body_sha256)` from
//   src/observatory-read.mjs; it verifies the digest. Never log or persist the raw body outside the collector's tables.
//
import { metricsCollector } from './metrics.mjs';

/**
 * @typedef {object} WorkflowObservation
 * @property {string} delivery_id  X-GitHub-Delivery (UUID)
 * @property {'workflow_run'|'workflow_job'} event
 * @property {string|null} action  e.g. requested, in_progress, completed, queued, waiting
 * @property {number} repo_id
 * @property {string} received_at  ISO-8601 receive time at the ingress
 * @property {string} object_key   R2 key in EVENTS (github-events) of the captured delivery
 * @property {string} body_sha256  hex sha256 of the raw body bytes
 *
 * @typedef {object} MetricsSink
 * @property {(observation: WorkflowObservation) => Promise<void>} record
 */

/** @type {MetricsSink} */
export const noopMetricsSink = Object.freeze({ async record() {} });

/**
 * @returns {MetricsSink} The D1 collector (src/metrics.mjs). Without the METRICS_DB binding `record` throws
 * `metrics_db_unbound`, so observations stay in the outbox (retried, escalated) instead of being dropped.
 */
export function metricsSinkFor(env) { return metricsCollector(env); }
