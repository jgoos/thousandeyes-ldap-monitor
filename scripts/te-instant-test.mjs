/**
 * Run a transaction script once on real ThousandEyes agents, as a web-transaction instant test,
 * wait for the result and check it. Used by .github/workflows/real-agent-validation.yml; set-up
 * and the meaning of the output are in docs/REAL_AGENT_VALIDATION.md.
 *
 *   node scripts/te-instant-test.mjs [--dry-run] [--script ldap-monitor.js] [--url ldaps://host/]
 *     [--agents 125,126] [--credentials 3247,1051] [--markers ldap-bind,ldap-search]
 *     [--time-limit 30] [--name "test name"]
 *
 * Options fall back to the environment:
 *   TE_API_TOKEN          API key or OAuth bearer token (required, except with --dry-run)
 *   TE_ACCOUNT_GROUP_ID   account group ID, sent as the `aid` query parameter (required)
 *   TE_TARGET_URL         --url: the test URL the script reads with test.getSettings().url
 *   TE_AGENT_IDS          --agents: agent IDs, comma-separated
 *   TE_CREDENTIAL_IDS     --credentials: credential IDs to attach, comma-separated
 *   TE_EXPECTED_MARKERS   --markers: markers every agent must report (default ldap-bind,ldap-search)
 *   TE_TIME_LIMIT         --time-limit: transaction time limit in seconds, 5-180 (default 30)
 *   TE_POLL_INTERVAL      seconds between result polls (default 10)
 *   TE_POLL_TIMEOUT       seconds to wait for all results (default 600)
 *   TE_HIDE_CONSOLE_LOGS  'true' to count console log lines without printing them
 *   TE_API_BASE_URL       default https://api.thousandeyes.com/v7
 * "none" as a list value means an empty list, e.g. --markers none.
 *
 * Exit status: 0 every agent passed; 1 an agent reported an error, a marker is missing, or a
 * result did not arrive in time; 2 configuration or API error.
 *
 * The token goes only into the Authorization header. Credential values never pass through here:
 * the test refers to ThousandEyes credentials by ID.
 */
import { createHash, randomUUID } from 'node:crypto';
import { appendFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

export const DEFAULT_BASE_URL = 'https://api.thousandeyes.com/v7';
export const DEFAULT_SCRIPT = 'ldap-monitor.js';
export const DEFAULT_MARKERS = ['ldap-bind', 'ldap-search'];
export const EXIT = { pass: 0, fail: 1, error: 2 };

const DEFAULT_TIME_LIMIT_S = 30;
const DEFAULT_TARGET_TIME_S = 10; // ThousandEyes default; it may not exceed timeLimit
const DEFAULT_POLL_INTERVAL_S = 10;
const DEFAULT_POLL_TIMEOUT_S = 600;
const CONSOLE_LOG_ATTEMPTS = 3; // console logs can lag the result; they never decide the verdict
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RATE_LIMIT_WAIT_MS = 60_000;
const CREATE_ATTEMPTS = 3; // only a 429 is retried: the test was not created
const ID_PATTERN = /^[A-Za-z0-9_-]+$/;

const OPTIONS = {
  'dry-run': { type: 'boolean', default: false },
  help: { type: 'boolean', short: 'h', default: false },
  script: { type: 'string' },
  url: { type: 'string' },
  agents: { type: 'string' },
  credentials: { type: 'string' },
  markers: { type: 'string' },
  'time-limit': { type: 'string' },
  name: { type: 'string' },
};

export const USAGE = `Usage: node scripts/te-instant-test.mjs [--dry-run] [--script FILE] [--url URL]
  [--agents IDS] [--credentials IDS] [--markers NAMES] [--time-limit SECONDS] [--name NAME]
See the header of this file and docs/REAL_AGENT_VALIDATION.md for the environment variables.`;

/* ───────────── Configuration ───────────── */

/**
 * Split a comma- or space-separated list; "none" or an empty value is an empty list.
 * @param {unknown} value
 * @returns {string[]}
 */
export function parseList(value) {
  const text = String(value ?? '').trim();
  if (text === '' || text.toLowerCase() === 'none') return [];
  return [...new Set(text.split(/[\s,]+/).filter(Boolean))];
}

/** A CLI option wins; an empty environment variable counts as unset, as GitHub passes unset vars as ''. */
const pick = (option, envValue) => (option !== undefined ? option : (envValue || undefined));

const isTrue = (value) => ['true', '1', 'yes'].includes(String(value ?? '').trim().toLowerCase());

function integerSetting(name, raw, fallback, min, max, errors) {
  if (raw === undefined || String(raw).trim() === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    errors.push(`${name} must be a whole number from ${min} to ${max}, got "${raw}"`);
    return fallback;
  }
  return value;
}

/**
 * Settings from the command line and the environment, checked.
 * @param {{ argv?: string[], env?: Record<string, string | undefined>, now?: () => number }} input
 * @returns {{ config: object, errors: string[] }}
 */
export function readConfig({ argv = [], env = {}, now = Date.now } = {}) {
  const errors = [];
  let values = {};
  try {
    ({ values } = parseArgs({ args: argv, options: OPTIONS, strict: true, allowPositionals: false }));
  } catch (err) {
    errors.push(err.message);
  }

  const markersRaw = pick(values.markers, env.TE_EXPECTED_MARKERS);
  const config = {
    dryRun: Boolean(values['dry-run']),
    help: Boolean(values.help),
    token: String(env.TE_API_TOKEN ?? '').trim(),
    accountGroupId: String(env.TE_ACCOUNT_GROUP_ID ?? '').trim(),
    baseUrl: String(env.TE_API_BASE_URL || DEFAULT_BASE_URL).trim().replace(/\/+$/, ''),
    scriptPath: pick(values.script, env.TE_SCRIPT) ?? DEFAULT_SCRIPT,
    url: String(pick(values.url, env.TE_TARGET_URL) ?? '').trim(),
    agentIds: parseList(pick(values.agents, env.TE_AGENT_IDS)),
    credentialIds: parseList(pick(values.credentials, env.TE_CREDENTIAL_IDS)),
    expectedMarkers: markersRaw === undefined ? [...DEFAULT_MARKERS] : parseList(markersRaw),
    timeLimitS: integerSetting('time limit', pick(values['time-limit'], env.TE_TIME_LIMIT), DEFAULT_TIME_LIMIT_S, 5, 180, errors),
    pollIntervalS: integerSetting('TE_POLL_INTERVAL', env.TE_POLL_INTERVAL, DEFAULT_POLL_INTERVAL_S, 1, 300, errors),
    pollTimeoutS: integerSetting('TE_POLL_TIMEOUT', env.TE_POLL_TIMEOUT, DEFAULT_POLL_TIMEOUT_S, 30, 3600, errors),
    hideConsoleLogs: isTrue(env.TE_HIDE_CONSOLE_LOGS),
    testName: values.name || `ldap-monitor validation ${new Date(now()).toISOString()}`
      + (env.GITHUB_RUN_ID ? ` (run ${env.GITHUB_RUN_ID})` : ''),
  };
  if (config.help) return { config, errors };

  if (!config.dryRun && !config.token) errors.push('TE_API_TOKEN is not set');
  if (!config.dryRun && !config.accountGroupId) errors.push('TE_ACCOUNT_GROUP_ID is not set');
  if (config.accountGroupId && !ID_PATTERN.test(config.accountGroupId)) errors.push('TE_ACCOUNT_GROUP_ID is not an ID');

  if (!config.url) errors.push('no test URL: set --url or TE_TARGET_URL');
  else if (!targetHost(config.url)) errors.push('the test URL has no host name');

  if (config.agentIds.length === 0) errors.push('no agents: set --agents or TE_AGENT_IDS');
  for (const id of config.agentIds) if (!ID_PATTERN.test(id)) errors.push(`agent ID "${id}" is not an ID`);
  for (const id of config.credentialIds) if (!ID_PATTERN.test(id)) errors.push(`credential ID "${id}" is not an ID`);

  try {
    if (new URL(config.baseUrl).protocol !== 'https:') errors.push('TE_API_BASE_URL must be an https:// URL');
  } catch {
    errors.push('TE_API_BASE_URL is not a URL');
  }
  return { config, errors };
}

/**
 * Host name in a test URL, without IPv6 brackets; null when there is none.
 * @param {string} url
 * @returns {string | null}
 */
export function targetHost(url) {
  try {
    const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
    return host || null;
  } catch {
    return null;
  }
}

/* ───────────── Request ───────────── */

/**
 * Body for POST /tests/web-transactions/instant (WebTransactionInstantTestRequest). Mirrors the
 * scheduled test in terraform/monitoring.tf: script, URL, agents, credentials, time limit and
 * console log collection; everything else keeps the ThousandEyes default.
 */
export function buildInstantTestRequest({ script, url, agentIds, credentialIds = [], timeLimitS, testName }) {
  const body = {
    testName,
    url,
    transactionScript: script,
    agents: agentIds.map((agentId) => ({ agentId })),
    timeLimit: timeLimitS,
    flagCollectConsoleLogs: true,
  };
  if (timeLimitS < DEFAULT_TARGET_TIME_S) body.targetTime = timeLimitS;
  if (credentialIds.length > 0) body.credentials = [...credentialIds];
  return body;
}

/**
 * API URL: path segments are percent-encoded; empty query values are left out.
 * @param {string} baseUrl
 * @param {Array<string | number>} segments
 * @param {Record<string, string | undefined>} [query]
 */
export function apiUrl(baseUrl, segments, query = {}) {
  const url = new URL(`${baseUrl}/${segments.map((s) => encodeURIComponent(String(s))).join('/')}`);
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== '') url.searchParams.set(key, value);
  }
  return url.toString();
}

/** The request --dry-run prints: token redacted, the script reduced to its size and hash. */
export function describeRequest(config, body) {
  const url = apiUrl(config.baseUrl, ['tests', 'web-transactions', 'instant'], {
    aid: config.accountGroupId || '<TE_ACCOUNT_GROUP_ID>',
  });
  const script = body.transactionScript;
  const digest = createHash('sha256').update(script).digest('hex').slice(0, 16);
  const shown = { ...body, transactionScript: `<${script.length} characters from ${config.scriptPath}, sha256 ${digest}...>` };
  return [
    `POST ${url}`,
    'Authorization: Bearer <redacted>',
    'Content-Type: application/json',
    '',
    JSON.stringify(shown, null, 2),
  ].join('\n');
}

/* ───────────── API client ───────────── */

export class ApiError extends Error {
  /**
   * @param {string} message
   * @param {{ status?: number, retryable?: boolean, retryAfterMs?: number }} [details]
   */
  constructor(message, { status, retryable = false, retryAfterMs } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.retryable = retryable;
    this.retryAfterMs = retryAfterMs;
  }
}

/** A rate-limit reset header: epoch seconds, epoch milliseconds or a date. */
const parseResetTime = (raw) => {
  if (raw === null || raw === undefined || String(raw).trim() === '') return null;
  const number = Number(raw);
  if (Number.isFinite(number)) return number < 1e12 ? number * 1000 : number;
  const date = Date.parse(raw);
  return Number.isNaN(date) ? null : date;
};

/**
 * How long to wait after an HTTP 429: until the reset time ThousandEyes reports for instant
 * tests or for the organization, at least 1 s and at most 60 s; `fallbackMs` without a header.
 * @param {Headers} headers
 * @param {number} nowMs
 * @param {number} fallbackMs
 */
export function rateLimitDelayMs(headers, nowMs, fallbackMs) {
  const reset = parseResetTime(headers.get('x-instant-test-rate-limit-reset'))
    ?? parseResetTime(headers.get('x-organization-rate-limit-reset'));
  if (reset === null) return fallbackMs;
  return Math.min(Math.max(reset - nowMs, 1000), MAX_RATE_LIMIT_WAIT_MS);
}

/** Short, single-line reason from an error body (application/problem+json or other). */
function problemText(data, text) {
  let reason = '';
  if (data && typeof data === 'object') {
    reason = [data.title, data.detail, data.message, data.errorMessage]
      .filter((part) => typeof part === 'string' && part).join(': ');
    if (Array.isArray(data.errors) && data.errors.length) reason += ` ${JSON.stringify(data.errors)}`;
  }
  if (!reason) reason = text;
  reason = oneLine(reason).trim();
  return reason ? `: ${reason.length > 500 ? `${reason.slice(0, 500)}...` : reason}` : '';
}

/**
 * Minimal ThousandEyes v7 client. Every request carries the bearer token and the account group.
 * @param {{ baseUrl: string, token: string, accountGroupId: string, fetchImpl: typeof fetch,
 *   now: () => number, pollIntervalMs: number }} options
 */
export function createClient({ baseUrl, token, accountGroupId, fetchImpl, now, pollIntervalMs }) {
  return async function call(method, segments, { body } = {}) {
    const url = apiUrl(baseUrl, segments, { aid: accountGroupId });
    const label = `${method} /${segments.join('/')}`;
    const headers = {
      Authorization: `Bearer ${token}`,
      Accept: 'application/hal+json, application/json, application/problem+json',
    };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let response;
    try {
      response = await fetchImpl(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (err) {
      // No response at all: for a GET, polling may try again.
      throw new ApiError(`${label} failed: ${err && err.message || err}`, { retryable: method === 'GET' });
    }
    const text = await response.text();
    let data = null;
    try {
      if (text) data = JSON.parse(text);
    } catch {
      // Not JSON: an error message falls back to the raw text
    }
    if (!response.ok) {
      const status = response.status;
      throw new ApiError(`${label} returned HTTP ${status}${problemText(data, text)}`, {
        status,
        retryable: status === 429 || (method === 'GET' && status >= 500),
        retryAfterMs: status === 429 ? rateLimitDelayMs(response.headers, now(), pollIntervalMs) : undefined,
      });
    }
    return data ?? {};
  };
}

/* ───────────── Polling ───────────── */

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Call `step` until it reports done, the attempts run out or the deadline passes. Retryable API
 * errors (429, 5xx, no response) and, where allowed, 404 count as "not yet".
 * @param {() => Promise<{ done: boolean, value?: any }>} step
 * @returns {Promise<{ done: boolean, value: any, attempts: number, lastError: Error | null }>}
 */
async function poll(step, { deadline, intervalMs, maxAttempts, now, sleep, notFoundIsPending = true }) {
  let value;
  let lastError = null;
  let attempts = 0;
  while (attempts < maxAttempts) {
    attempts++;
    let waitMs = intervalMs;
    try {
      const result = await step();
      value = result.value;
      lastError = null;
      if (result.done) return { done: true, value, attempts, lastError };
    } catch (err) {
      const pending = err instanceof ApiError && (err.retryable || (notFoundIsPending && err.status === 404));
      if (!pending) throw err;
      lastError = err;
      if (err.retryAfterMs !== undefined) waitMs = err.retryAfterMs;
    }
    const left = deadline - now();
    if (attempts >= maxAttempts || left <= 0) break;
    await sleep(Math.min(waitMs, left));
  }
  return { done: false, value, attempts, lastError };
}

const asString = (value) => (value === null || value === undefined ? '' : String(value));
const resultsOf = (data) => (data && Array.isArray(data.results) ? data.results : []);

/**
 * Create the instant test, then wait for one result per agent, its markers and console logs.
 * @returns {Promise<{ testId: string, created: object, rounds: Map<string, object>, timedOut: boolean, lastError: Error | null }>}
 */
export async function runInstantTest({ config, body, fetchImpl = fetch, sleep = defaultSleep, now = Date.now, log = () => {} }) {
  const intervalMs = config.pollIntervalS * 1000;
  const call = createClient({ ...config, fetchImpl, now, pollIntervalMs: intervalMs });

  let created;
  for (let attempt = 1; ; attempt++) {
    try {
      created = await call('POST', ['tests', 'web-transactions', 'instant'], { body });
      break;
    } catch (err) {
      if (!(err instanceof ApiError) || err.status !== 429 || attempt >= CREATE_ATTEMPTS) throw err;
      log(`Rate limited creating the instant test; retrying in ${Math.round(err.retryAfterMs / 1000)} s`);
      await sleep(err.retryAfterMs);
    }
  }
  const testId = asString(created.testId);
  if (!testId) throw new ApiError('POST /tests/web-transactions/instant returned no testId');
  log(`Created instant test ${testId}; waiting up to ${config.pollTimeoutS} s for ${config.agentIds.length} agent(s)`);

  const deadline = now() + config.pollTimeoutS * 1000;
  const maxAttempts = Math.ceil(config.pollTimeoutS / config.pollIntervalS) + 1;
  const pollOptions = { deadline, intervalMs, maxAttempts, now, sleep };

  // 1 ▸ One summary result per agent. Without a window the endpoint returns the latest round.
  let reported = -1;
  const summary = await poll(async () => {
    const byAgent = new Map();
    for (const result of resultsOf(await call('GET', ['test-results', testId, 'web-transactions']))) {
      const agentId = asString(result.agent && result.agent.agentId);
      if (agentId && !byAgent.has(agentId)) byAgent.set(agentId, result);
    }
    const count = config.agentIds.filter((id) => byAgent.has(id)).length;
    if (count !== reported) {
      log(`${count} of ${config.agentIds.length} agent(s) reported`);
      reported = count;
    }
    return { done: count === config.agentIds.length, value: byAgent };
  }, pollOptions);

  // 2 ▸ Per agent: the detailed result, which carries the markers, then the console logs.
  const rounds = new Map();
  const byAgent = summary.value || new Map();
  for (const agentId of config.agentIds) {
    const result = byAgent.get(agentId);
    if (!result) continue;
    const roundPath = ['test-results', testId, 'web-transactions', 'agent', agentId, 'round', asString(result.roundId)];
    const round = { summary: result, detail: null, consoleLogs: [], consoleLogsError: null };
    const detail = await poll(async () => {
      const [first] = resultsOf(await call('GET', roundPath));
      return { done: Boolean(first), value: first };
    }, { ...pollOptions, deadline: Math.max(deadline, now() + intervalMs), maxAttempts: Math.min(maxAttempts, 6) });
    round.detail = detail.value || null;

    try {
      const logs = await poll(async () => {
        const entries = resultsOf(await call('GET', [...roundPath, 'console-logs']))
          .flatMap((entry) => (Array.isArray(entry.consoleLogs) ? entry.consoleLogs : []));
        return { done: entries.length > 0, value: entries };
      }, { ...pollOptions, deadline: Math.max(deadline, now() + intervalMs), maxAttempts: CONSOLE_LOG_ATTEMPTS });
      round.consoleLogs = logs.value || [];
      if (!logs.done && logs.lastError) round.consoleLogsError = logs.lastError.message;
    } catch (err) {
      round.consoleLogsError = err.message;
    }
    rounds.set(agentId, round);
  }
  return { testId, created, rounds, timedOut: !summary.done, lastError: summary.lastError };
}

/* ───────────── Verdict ───────────── */

/**
 * Check one agent's result: no errorDetails, and every expected marker reported.
 * @param {object} result  WebTransactionDetailTestResult (or the summary result, which has no markers)
 * @param {string[]} expectedMarkers
 */
export function evaluateRound(result, expectedMarkers) {
  const problems = [];
  const errorDetails = asString(result.errorDetails).trim();
  const errorType = asString(result.errorType).trim();
  if (errorDetails) problems.push(`error${errorType ? ` (${errorType})` : ''}: ${errorDetails}`);

  const markers = (Array.isArray(result.markers) ? result.markers : []).map((marker) => ({
    name: asString(marker && marker.name),
    duration: marker && Number.isFinite(marker.duration) ? marker.duration : null,
  }));
  const names = new Set(markers.map((marker) => marker.name));
  const missing = expectedMarkers.filter((name) => !names.has(name));
  if (missing.length) problems.push(`missing marker${missing.length === 1 ? '' : 's'}: ${missing.join(', ')}`);

  return {
    agentId: asString(result.agent && result.agent.agentId),
    agentName: asString(result.agent && result.agent.agentName),
    roundId: result.roundId ?? null,
    transactionTime: Number.isFinite(result.transactionTime) ? result.transactionTime : null,
    errorType,
    errorDetails,
    markers,
    problems,
    ok: problems.length === 0,
  };
}

/**
 * Verdict over all requested agents; an agent without a result fails.
 * @param {{ agentIds: string[], rounds: Map<string, object>, expectedMarkers: string[], pollTimeoutS?: number }} input
 */
export function evaluateRun({ agentIds, rounds, expectedMarkers, pollTimeoutS }) {
  const agents = agentIds.map((agentId) => {
    const round = rounds.get(agentId);
    if (!round) {
      const within = pollTimeoutS ? ` within ${pollTimeoutS} s` : '';
      return {
        agentId, agentName: '', hasResult: false, ok: false, markers: [], consoleLogs: [], consoleLogsError: null,
        transactionTime: null, roundId: null, errorType: '', errorDetails: '', problems: [`no result${within}`],
      };
    }
    const evaluated = evaluateRound(round.detail || round.summary, expectedMarkers);
    if (!round.detail && expectedMarkers.length) evaluated.problems.push('no detailed result, so markers are unknown');
    return {
      ...evaluated,
      agentId,
      hasResult: true,
      ok: evaluated.problems.length === 0,
      consoleLogs: round.consoleLogs || [],
      consoleLogsError: round.consoleLogsError || null,
    };
  });
  return { ok: agents.length > 0 && agents.every((agent) => agent.ok), agents };
}

/* ───────────── Output ───────────── */

/** Text from the API or the agent on one line: control characters become spaces. */
// eslint-disable-next-line no-control-regex
const oneLine = (value) => asString(value).replace(/[\u0000-\u001f\u007f]+/g, ' ');

/** Untrusted multi-line text, each line indented (so none can start a workflow command). */
// eslint-disable-next-line no-control-regex
const indentLines = (value, prefix) => asString(value).split(/\r\n|\r|\n/).map((line) => `${prefix}${line.replace(/[\u0000-\u001f\u007f]+/g, ' ')}`);

const agentLabel = (agent) => `Agent ${oneLine(agent.agentId)}${agent.agentName ? ` (${oneLine(agent.agentName)})` : ''}`;

/**
 * Human-readable result, one line per fact.
 * @returns {string[]}
 */
export function formatSummary(run, { testId, timeLimitS, expectedMarkers, hideConsoleLogs = false }) {
  const lines = [
    `Instant test ${oneLine(testId)}: time limit ${timeLimitS} s; expected markers: ${expectedMarkers.length ? expectedMarkers.join(', ') : 'none'}`,
  ];
  for (const agent of run.agents) {
    const facts = [agent.ok ? 'PASS' : 'FAIL'];
    if (agent.transactionTime !== null && agent.transactionTime !== undefined) facts.push(`transaction ${agent.transactionTime} ms`);
    if (agent.roundId !== null && agent.roundId !== undefined) facts.push(`round ${oneLine(agent.roundId)}`);
    lines.push(`${agentLabel(agent)}: ${facts.join(', ')}`);
    if (agent.markers.length) {
      lines.push(`  markers: ${agent.markers.map((m) => `${oneLine(m.name)} ${m.duration === null ? '?' : `${m.duration} ms`}`).join(', ')}`);
    }
    for (const problem of agent.problems) lines.push(...indentLines(problem, '  ! '));
    if (agent.consoleLogsError) lines.push(`  console logs unavailable: ${oneLine(agent.consoleLogsError)}`);
    const logs = agent.consoleLogs;
    if (logs.length && hideConsoleLogs) lines.push(`  console logs: ${logs.length} line(s), hidden (TE_HIDE_CONSOLE_LOGS)`);
    else if (logs.length) {
      lines.push(`  console logs (${logs.length}):`);
      for (const entry of logs) lines.push(...indentLines(entry && entry.value, `    [${oneLine(entry && entry.level) || '?'}] `));
    } else if (agent.hasResult && !agent.consoleLogsError) {
      lines.push('  console logs: none');
    }
  }
  const failed = run.agents.filter((agent) => !agent.ok).length;
  lines.push(run.ok ? `Result: PASS (${run.agents.length} agent(s))` : `Result: FAIL (${failed} of ${run.agents.length} agent(s))`);
  return lines;
}

const cell = (value) => oneLine(value).replace(/\|/g, '\\|');

/**
 * Markdown for the GitHub job summary. Leaves out error text and console logs, which can name
 * the target server: those are only in the (masked) log.
 */
export function formatStepSummary(run, { testId, scriptPath }) {
  const rows = run.agents.map((agent) => {
    const markers = agent.markers.map((m) => `${m.name} ${m.duration === null ? '?' : `${m.duration} ms`}`).join(', ');
    const problems = agent.problems.map((p) => (p.startsWith('error') ? `error${agent.errorType ? ` (${agent.errorType})` : ''}, see log` : p));
    return `| ${cell(agent.agentId)} | ${cell(agent.agentName)} | ${agent.ok ? 'pass' : 'FAIL'} | ${agent.transactionTime ?? ''} | ${cell(markers)} | ${cell(problems.join('; '))} |`;
  });
  return [
    `### ${run.ok ? 'Pass' : 'FAIL'}: \`${cell(scriptPath)}\` on ThousandEyes (instant test ${cell(testId)})`,
    '',
    '| Agent | Name | Result | Transaction (ms) | Markers | Problems |',
    '| --- | --- | --- | --- | --- | --- |',
    ...rows,
    '',
  ].join('\n');
}

/* ───────────── Command line ───────────── */

/**
 * @param {{ argv?: string[], env?: object, fetchImpl?: typeof fetch, sleep?: (ms: number) => Promise<void>,
 *   now?: () => number, write?: (text: string) => void, cwd?: string }} [io]
 * @returns {Promise<number>} exit status
 */
export async function main({
  argv = process.argv.slice(2),
  env = process.env,
  fetchImpl = fetch,
  sleep = defaultSleep,
  now = Date.now,
  write = (text) => process.stdout.write(text),
  cwd = process.cwd(),
} = {}) {
  const out = (...lines) => write(`${lines.join('\n')}\n`);
  const { config, errors } = readConfig({ argv, env, now });
  if (config.help) {
    out(USAGE);
    return EXIT.pass;
  }
  if (errors.length) {
    out(...errors.map((message) => `error: ${message}`), USAGE);
    return EXIT.error;
  }

  let script;
  try {
    script = readFileSync(path.resolve(cwd, config.scriptPath), 'utf8');
  } catch (err) {
    out(`error: cannot read the script ${config.scriptPath}: ${err.message}`);
    return EXIT.error;
  }
  if (!script.trim()) {
    out(`error: the script ${config.scriptPath} is empty`);
    return EXIT.error;
  }
  const body = buildInstantTestRequest({ ...config, script });

  if (config.dryRun) {
    out(describeRequest(config, body));
    return EXIT.pass;
  }

  const inActions = env.GITHUB_ACTIONS === 'true';
  if (inActions) {
    // The target server's name appears in console logs and errors; keep it out of public logs.
    out(`::add-mask::${config.url}`, `::add-mask::${targetHost(config.url)}`);
  }
  out(`Running ${config.scriptPath} on agent(s) ${config.agentIds.join(', ')} against ${config.url}`);

  let result;
  try {
    result = await runInstantTest({ config, body, fetchImpl, sleep, now, log: (line) => out(line) });
  } catch (err) {
    out(`error: ${oneLine(err && err.message || err)}`);
    return EXIT.error;
  }

  const run = evaluateRun({ ...config, rounds: result.rounds });
  if (result.timedOut && result.lastError) out(`last polling error: ${oneLine(result.lastError.message)}`);
  // Agent output can contain anything, including text that looks like a workflow command.
  const stopToken = inActions ? randomUUID() : null;
  if (stopToken) out(`::stop-commands::${stopToken}`);
  out(...formatSummary(run, { ...config, testId: result.testId }));
  if (stopToken) out(`::${stopToken}::`);

  if (env.GITHUB_STEP_SUMMARY) {
    try {
      appendFileSync(env.GITHUB_STEP_SUMMARY, formatStepSummary(run, { testId: result.testId, scriptPath: config.scriptPath }));
    } catch (err) {
      out(`warning: cannot write the job summary: ${err.message}`);
    }
  }
  return run.ok ? EXIT.pass : EXIT.fail;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await main();
}
