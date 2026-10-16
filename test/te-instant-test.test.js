// scripts/te-instant-test.mjs against a fake ThousandEyes API: request building, polling and the
// verdict. No network. The fixtures in test/fixtures/te-instant-test are synthetic, shaped after
// the v7 models in the official SDK (thousandeyes-sdk-python: instant-tests and test-results);
// replace them with recorded responses once the workflow has run against a real account.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_MARKERS,
  EXIT,
  apiUrl,
  buildInstantTestRequest,
  collectResults,
  escapeCommandData,
  evaluateRound,
  evaluateRun,
  formatSummary,
  main,
  neutralise,
  parseList,
  rateLimitDelayMs,
  readConfig,
  redactFactLine,
  resultsWindow,
} from '../scripts/te-instant-test.mjs';

const REPO = fileURLToPath(new URL('..', import.meta.url));
const TOKEN = 'te-token-DO-NOT-PRINT-0123456789';
const TEST_ID = '7012345';
const ROUND = '1792184400';
const T0 = Date.UTC(2026, 9, 16, 21);

const fixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/te-instant-test/${name}.json`, import.meta.url), 'utf8'));
const firstResult = (name) => fixture(name).results[0];

const baseEnv = (overrides = {}) => ({
  TE_API_TOKEN: TOKEN,
  TE_ACCOUNT_GROUP_ID: '1234',
  TE_TARGET_URL: 'ldaps://ldap.example.com:636/',
  TE_AGENT_IDS: '125',
  TE_CREDENTIAL_IDS: '3247,1051',
  ...overrides,
});

/** A clock that `sleep` advances, so polling runs instantly; `sleeps` records each wait. */
function fakeClock() {
  let t = T0;
  const sleeps = [];
  return { now: () => t, sleep: async (ms) => { sleeps.push(ms); t += ms; }, sleeps };
}

/**
 * A fake v7 API. `routes` maps "METHOD /path" (without /v7) to a reply, or to a function of the
 * call count and the query returning one: { status = 200, body = {}, headers }. Unknown routes
 * return 404.
 */
function fakeApi(routes) {
  const calls = [];
  const counts = new Map();
  const fetchImpl = async (url, init) => {
    const parsed = new URL(url);
    const key = `${init.method} ${parsed.pathname.replace(/^\/v7/, '')}`;
    const query = Object.fromEntries(parsed.searchParams);
    calls.push({ key, url, query, headers: init.headers, body: init.body && JSON.parse(init.body) });
    const count = (counts.get(key) || 0) + 1;
    counts.set(key, count);
    const route = routes[key];
    if (!route) return new Response(JSON.stringify({ title: 'Not Found' }), { status: 404 });
    const reply = typeof route === 'function' ? route(count, query) : route;
    return new Response(JSON.stringify(reply.body ?? {}), { status: reply.status ?? 200, headers: reply.headers });
  };
  return { fetchImpl, calls, count: (key) => counts.get(key) || 0 };
}

const CREATE = 'POST /tests/web-transactions/instant';
const RESULTS = `GET /test-results/${TEST_ID}/web-transactions`;
const detailKey = (agentId, round = ROUND) => `GET /test-results/${TEST_ID}/web-transactions/agent/${agentId}/round/${round}`;
const DETAIL = detailKey('125');
const LOGS = `${DETAIL}/console-logs`;

const happyRoutes = (overrides = {}) => ({
  [CREATE]: { status: 201, body: fixture('create-response') },
  [RESULTS]: (n) => ({ body: fixture(n < 3 ? 'results-pending' : 'results-ready') }),
  [DETAIL]: { body: fixture('detail-pass') },
  [LOGS]: { body: fixture('console-logs') },
  ...overrides,
});

/** A copy of a fixture's first result for another agent and round. */
function resultFor(name, agentId, roundId, changes = {}) {
  const result = structuredClone(firstResult(name));
  return { ...result, roundId, agent: { ...result.agent, agentId, agentName: `Agent ${agentId}` }, ...changes };
}

/** Run main() against `routes`; returns the exit code, the printed text, the API calls and the clock. */
async function run({ routes = happyRoutes(), env = baseEnv(), argv = [] } = {}) {
  const api = fakeApi(routes);
  const clock = fakeClock();
  let output = '';
  const code = await main({ argv, env, fetchImpl: api.fetchImpl, now: clock.now, sleep: clock.sleep, write: (text) => { output += text; }, cwd: REPO });
  return { code, output, api, clock };
}

describe('instant test request', () => {
  it('builds the body like the scheduled Terraform test', () => {
    const body = buildInstantTestRequest({
      script: 'console.log(1);', url: 'ldaps://ldap.example.com/', agentIds: ['125', '126'],
      credentialIds: ['3247'], timeLimitS: 30, testName: 'n',
    });
    assert.deepEqual(body, {
      testName: 'n',
      url: 'ldaps://ldap.example.com/',
      transactionScript: 'console.log(1);',
      agents: [{ agentId: '125' }, { agentId: '126' }],
      timeLimit: 30,
      flagCollectConsoleLogs: true,
      credentials: ['3247'],
    });
  });

  it('leaves out credentials when there are none, and keeps targetTime within a short time limit', () => {
    const body = buildInstantTestRequest({ script: 's', url: 'ldap://h:389', agentIds: ['1'], timeLimitS: 5, testName: 'n' });
    assert.equal('credentials' in body, false);
    assert.equal(body.targetTime, 5);
  });

  it('percent-encodes path segments and adds the account group as aid', () => {
    assert.equal(
      apiUrl('https://api.thousandeyes.com/v7', ['test-results', 'a/b', 'web-transactions'], { aid: '1234', empty: '' }),
      'https://api.thousandeyes.com/v7/test-results/a%2Fb/web-transactions?aid=1234',
    );
  });

  it('asks for results from a window that starts before the test was created', () => {
    assert.equal(resultsWindow(T0, T0), '60s');
    assert.equal(resultsWindow(T0, T0 + 90_500), '151s');
  });
});

describe('configuration', () => {
  it('reads the environment, with the probe markers and a 30 s time limit by default', () => {
    const { config, errors } = readConfig({ env: baseEnv() });
    assert.deepEqual(errors, []);
    assert.equal(config.url, 'ldaps://ldap.example.com:636/');
    assert.deepEqual(config.agentIds, ['125']);
    assert.deepEqual(config.credentialIds, ['3247', '1051']);
    assert.deepEqual(config.expectedMarkers, DEFAULT_MARKERS);
    assert.equal(config.timeLimitS, 30);
    assert.equal(config.scriptPath, 'ldap-monitor.js');
  });

  it('lets options override the environment; "none" is an empty list', () => {
    const { config, errors } = readConfig({
      env: baseEnv({ TE_EXPECTED_MARKERS: 'ldap-bind' }),
      argv: ['--agents', '7, 8', '--markers', 'none', '--credentials', 'none', '--time-limit', '60', '--script', 'x.js'],
    });
    assert.deepEqual(errors, []);
    assert.deepEqual(config.agentIds, ['7', '8']);
    assert.deepEqual(config.expectedMarkers, []);
    assert.deepEqual(config.credentialIds, []);
    assert.equal(config.timeLimitS, 60);
    assert.equal(config.scriptPath, 'x.js');
  });

  it('treats empty variables as unset, as GitHub passes unset vars', () => {
    const { config } = readConfig({ env: baseEnv({ TE_EXPECTED_MARKERS: '', TE_TIME_LIMIT: '', TE_SHOW_DETAILS: '' }) });
    assert.deepEqual(config.expectedMarkers, DEFAULT_MARKERS);
    assert.equal(config.timeLimitS, 30);
    assert.equal(config.showDetails, true);
  });

  it('hides details by default in GitHub Actions only; TE_SHOW_DETAILS decides when set', () => {
    assert.equal(readConfig({ env: baseEnv() }).config.showDetails, true);
    assert.equal(readConfig({ env: baseEnv({ GITHUB_ACTIONS: 'true' }) }).config.showDetails, false);
    assert.equal(readConfig({ env: baseEnv({ GITHUB_ACTIONS: 'true', TE_SHOW_DETAILS: 'true' }) }).config.showDetails, true);
    assert.equal(readConfig({ env: baseEnv({ TE_SHOW_DETAILS: 'false' }) }).config.showDetails, false);
  });

  it('reports every missing setting', () => {
    const { errors } = readConfig({ env: {} });
    assert.equal(errors.length, 4);
    assert.match(errors.join('\n'), /TE_API_TOKEN/);
    assert.match(errors.join('\n'), /TE_ACCOUNT_GROUP_ID/);
    assert.match(errors.join('\n'), /no test URL/);
    assert.match(errors.join('\n'), /no agents/);
  });

  it('rejects a time limit outside 5-180 s, a malformed ID and a non-https API URL', () => {
    const { errors } = readConfig({
      env: baseEnv({ TE_TIME_LIMIT: '200', TE_AGENT_IDS: 'agent.name', TE_API_BASE_URL: 'http://api.thousandeyes.com/v7' }),
    });
    assert.match(errors.join('\n'), /time limit must be a whole number from 5 to 180/);
    assert.match(errors.join('\n'), /agent ID "agent\.name" is not an ID/);
    assert.match(errors.join('\n'), /https/);
    assert.equal(readConfig({ env: baseEnv({ TE_AGENT_IDS: '12/../x' }) }).errors.length, 1);
  });

  it('rejects a token that cannot go into a header, without quoting it', () => {
    for (const token of ['tok en-SECRET', 'tokén-SECRET', 'tok\u0000en-SECRET']) {
      const { errors } = readConfig({ env: baseEnv({ TE_API_TOKEN: token }) });
      assert.equal(errors.length, 1, JSON.stringify(token));
      assert.match(errors[0], /TE_API_TOKEN must be printable ASCII/);
      assert.equal(errors[0].includes('SECRET'), false);
    }
  });

  it('needs no token or account group for a dry run', () => {
    const { errors } = readConfig({ env: baseEnv({ TE_API_TOKEN: '', TE_ACCOUNT_GROUP_ID: '' }), argv: ['--dry-run'] });
    assert.deepEqual(errors, []);
  });

  it('splits lists on commas and spaces and drops duplicates', () => {
    assert.deepEqual(parseList(' 1, 2 3,,1 '), ['1', '2', '3']);
    assert.deepEqual(parseList(undefined), []);
    assert.deepEqual(parseList('NONE'), []);
  });
});

describe('result evaluation', () => {
  it('passes a result without errorDetails that has every expected marker', () => {
    const verdict = evaluateRound(firstResult('detail-pass'), DEFAULT_MARKERS);
    assert.equal(verdict.ok, true);
    assert.deepEqual(verdict.problems, []);
    assert.equal(verdict.agentId, '125');
    assert.equal(verdict.transactionTime, 412);
    assert.deepEqual(verdict.markers.find((m) => m.name === 'ldap-bind'), { name: 'ldap-bind', duration: 12 });
  });

  it('fails on errorDetails, naming the error type', () => {
    const verdict = evaluateRound(firstResult('detail-error'), ['ldap-bind']);
    assert.equal(verdict.ok, false);
    assert.deepEqual(verdict.problems, ['error (Transaction): Error: Authentication failed: invalidCredentials (49)']);
  });

  it('fails on a missing marker; an empty errorDetails is no error', () => {
    const verdict = evaluateRound(firstResult('detail-missing-marker'), DEFAULT_MARKERS);
    assert.equal(verdict.ok, false);
    assert.deepEqual(verdict.problems, ['missing marker: ldap-search']);
  });

  it('fails an agent that sent no result, and a result without markers when markers are expected', () => {
    const rounds = new Map([['125', { summary: firstResult('results-ready'), detail: null, consoleLogs: [] }]]);
    const run = evaluateRun({ agentIds: ['125', '126'], rounds, expectedMarkers: DEFAULT_MARKERS, pollTimeoutS: 600 });
    assert.equal(run.ok, false);
    assert.match(run.agents[0].problems.join('\n'), /missing markers: ldap-bind, ldap-search/);
    assert.match(run.agents[0].problems.join('\n'), /no detailed result/);
    assert.deepEqual(run.agents[1].problems, ['no result within 600 s']);
  });

  it('fails the run when one of two agents fails', () => {
    const rounds = new Map([
      ['125', { detail: firstResult('detail-pass'), consoleLogs: [] }],
      ['126', { detail: resultFor('detail-error', '126', 1792184460), consoleLogs: [] }],
    ]);
    const run = evaluateRun({ agentIds: ['125', '126'], rounds, expectedMarkers: ['ldap-bind'] });
    assert.deepEqual(run.agents.map((agent) => agent.ok), [true, false]);
    assert.equal(run.ok, false);
  });

  it('keeps each agent\'s latest round across result pages', () => {
    const byAgent = new Map();
    collectResults(byAgent, [resultFor('results-ready', '125', 100), resultFor('results-ready', '126', 160)]);
    collectResults(byAgent, [resultFor('results-ready', '125', 90), resultFor('results-ready', '125', 130), { roundId: 1 }]);
    assert.deepEqual([...byAgent].map(([id, result]) => [id, result.roundId]), [['125', 130], ['126', 160]]);
  });
});

describe('output safety', () => {
  it('breaks up workflow commands: ##[ anywhere, :: at the start of a line', () => {
    assert.equal(neutralise('ok ##[error]x ##[group]'), 'ok # #[error]x # #[group]');
    assert.equal(neutralise('::error::x'), ': :error::x');
    assert.equal(neutralise('  ::add-mask::x'), '  : :add-mask::x');
    assert.equal(neutralise('a::b'), 'a::b');
    assert.equal(neutralise('tab\there\r'), 'tab here ');
  });

  it('prints agent output one neutralised line per entry', () => {
    const rounds = new Map([['125', {
      detail: firstResult('detail-pass'),
      consoleLogs: [{ level: 'INFO', value: 'line one\n::error::injected\u001b[31m\n##[warning]x' }],
    }]]);
    const run = evaluateRun({ agentIds: ['125'], rounds, expectedMarkers: DEFAULT_MARKERS });
    const lines = formatSummary(run, { testId: TEST_ID, timeLimitS: 30, expectedMarkers: DEFAULT_MARKERS });
    assert.ok(lines.includes('    [INFO] line one'));
    assert.ok(lines.includes('    [INFO] : :error::injected [31m'));
    assert.ok(lines.includes('    [INFO] # #[warning]x'));
    assert.equal(lines.some((line) => /^\s*::|##\[/.test(line)), false);
    assert.equal(lines.at(-1), 'Result: PASS (1 agent(s))');
  });

  it('escapes %, CR and LF in workflow command data', () => {
    assert.equal(escapeCommandData('a%b\r\nc'), 'a%25b%0D%0Ac');
  });

  it('reduces quoted error messages in runtime facts to their length', () => {
    assert.equal(
      redactFactLine('runtime-fact markers: {"restart":{"threw":true,"error":{"code":null,"message":"Marker x"}},"list":[{"message":"abc"}]}'),
      'runtime-fact markers: {"restart":{"threw":true,"error":{"code":null,"message":"<8 characters hidden>"}},"list":[{"message":"<3 characters hidden>"}]}',
    );
    assert.equal(redactFactLine('LDAP Monitor: PASS'), null);
    assert.equal(redactFactLine('runtime-fact x: not json'), null);
  });
});

describe('rate limits', () => {
  const headers = (h) => new Headers(h);
  it('waits until the reported reset, between 1 and 60 s', () => {
    assert.equal(rateLimitDelayMs(headers({ 'X-Instant-Test-Rate-Limit-Reset': String(T0 / 1000 + 12) }), T0, 10_000), 12_000);
    assert.equal(rateLimitDelayMs(headers({ 'X-Organization-Rate-Limit-Reset': String(T0 + 5_000) }), T0, 10_000), 5_000);
    assert.equal(rateLimitDelayMs(headers({ 'X-Organization-Rate-Limit-Reset': String(T0 / 1000 + 600) }), T0, 10_000), 60_000);
    assert.equal(rateLimitDelayMs(headers({ 'X-Organization-Rate-Limit-Reset': String(T0 / 1000 - 5) }), T0, 10_000), 1_000);
    assert.equal(rateLimitDelayMs(headers({}), T0, 10_000), 10_000);
  });

  it('waits for the later of the instant-test and organization resets', () => {
    const both = (instant, org) => headers({
      'X-Instant-Test-Rate-Limit-Reset': String(T0 / 1000 + instant),
      'X-Organization-Rate-Limit-Reset': String(T0 / 1000 + org),
    });
    assert.equal(rateLimitDelayMs(both(5, 20), T0, 10_000), 20_000);
    assert.equal(rateLimitDelayMs(both(30, 3), T0, 10_000), 30_000);
  });
});

describe('running an instant test against a fake API', () => {
  it('creates the test, polls until the agent reports, and passes', async () => {
    const { code, output, api } = await run();
    assert.equal(code, EXIT.pass);

    const create = api.calls.find((c) => c.key === CREATE);
    assert.equal(create.headers.Authorization, `Bearer ${TOKEN}`);
    assert.equal(create.body.transactionScript, readFileSync(path.join(REPO, 'ldap-monitor.js'), 'utf8'));
    assert.equal(create.body.url, 'ldaps://ldap.example.com:636/');
    assert.deepEqual(create.body.agents, [{ agentId: '125' }]);
    assert.deepEqual(create.body.credentials, ['3247', '1051']);
    assert.equal(create.body.flagCollectConsoleLogs, true);
    assert.ok(api.calls.every((c) => c.query.aid === '1234'), 'every request names the account group');
    assert.equal(api.count(RESULTS), 3);
    const windows = api.calls.filter((c) => c.key === RESULTS).map((c) => c.query.window);
    assert.deepEqual(windows, ['60s', '70s', '80s'], 'results cover every round since the test was created');

    assert.match(output, /Agent 125 \(Example Enterprise Agent\): PASS, transaction 412 ms/);
    assert.match(output, /markers: .*ldap-bind 12 ms, ldap-search 6 ms/);
    assert.match(output, /\[INFO\] LDAP Monitor: PASS/);
    assert.equal(output.includes(TOKEN), false, 'the token is never printed');
  });

  it('waits for two agents that report in different rounds, across result pages', async () => {
    const page1 = { results: [resultFor('results-ready', '125', 1792184400)], _links: { next: { href: `https://api.thousandeyes.com/v7/test-results/${TEST_ID}/web-transactions?cursor=p2&aid=1234` } } };
    const page2 = { results: [resultFor('results-ready', '126', 1792184460)] };
    const { code, output, api } = await run({
      env: baseEnv({ TE_AGENT_IDS: '125,126' }),
      routes: happyRoutes({
        [RESULTS]: (n, query) => {
          if (n === 1) return { body: { results: [resultFor('results-ready', '125', 1792184400)] } };
          return { body: query.cursor === 'p2' ? page2 : page1 };
        },
        [detailKey('126', 1792184460)]: { body: { results: [resultFor('detail-pass', '126', 1792184460)] } },
        [`${detailKey('126', 1792184460)}/console-logs`]: { body: fixture('console-logs') },
      }),
    });
    assert.equal(code, EXIT.pass, output);
    const resultCalls = api.calls.filter((c) => c.key === RESULTS);
    assert.deepEqual(resultCalls.map((c) => c.query.cursor ?? null), [null, null, 'p2']);
    assert.ok(resultCalls.every((c) => c.query.aid === '1234'));
    assert.match(output, /1 of 2 agent\(s\) reported/);
    assert.match(output, /2 of 2 agent\(s\) reported/);
    assert.match(output, /Agent 126 \(Agent 126\): PASS, transaction 412 ms, round 1792184460/);
    assert.match(output, /Result: PASS \(2 agent\(s\)\)/);
  });

  it('does not follow a next link outside the API', async () => {
    const { code, output } = await run({
      routes: happyRoutes({ [RESULTS]: { body: { results: [], _links: { next: { href: 'https://attacker.example/v7/x' } } } } }),
    });
    assert.equal(code, EXIT.error);
    assert.match(output, /next link outside the API/);
  });

  it('fails when one of two agents reports an error', async () => {
    const { code, output } = await run({
      env: baseEnv({ TE_AGENT_IDS: '125,126' }),
      routes: happyRoutes({
        [RESULTS]: { body: { results: [resultFor('results-ready', '125', 1792184400), resultFor('results-ready', '126', 1792184400)] } },
        [detailKey('126')]: { body: { results: [resultFor('detail-error', '126', 1792184400)] } },
      }),
    });
    assert.equal(code, EXIT.fail);
    assert.match(output, /Agent 125 \(Example Enterprise Agent\): PASS/);
    assert.match(output, /Agent 126 \(Agent 126\): FAIL/);
    assert.match(output, /Result: FAIL \(1 of 2 agent\(s\)\)/);
  });

  it('keeps polling until every agent has reported, then fails the missing one', async () => {
    const { code, output, api } = await run({
      env: baseEnv({ TE_AGENT_IDS: '125,126', TE_POLL_INTERVAL: '10', TE_POLL_TIMEOUT: '60' }),
      routes: happyRoutes({ [RESULTS]: { body: fixture('results-ready') } }),
    });
    assert.equal(code, EXIT.fail);
    assert.equal(api.count(RESULTS), 7, 'one agent is not enough to stop polling');
    assert.match(output, /Agent 125 \(Example Enterprise Agent\): PASS/);
    assert.match(output, /Agent 126: FAIL/);
    assert.match(output, /no result within 60 s/);
  });

  it('fails when the agent reports errorDetails', async () => {
    const { code, output } = await run({ routes: happyRoutes({ [DETAIL]: { body: fixture('detail-error') } }) });
    assert.equal(code, EXIT.fail);
    assert.match(output, /! error \(Transaction\): Error: Authentication failed/);
    assert.match(output, /! missing marker: ldap-search/);
    assert.match(output, /Result: FAIL \(1 of 1 agent\(s\)\)/);
  });

  it('fails when a marker is missing', async () => {
    const { code } = await run({ routes: happyRoutes({ [DETAIL]: { body: fixture('detail-missing-marker') } }) });
    assert.equal(code, EXIT.fail);
  });

  it('gives up after a bounded number of polls and fails', async () => {
    const { code, output, api } = await run({
      routes: happyRoutes({ [RESULTS]: { body: fixture('results-pending') } }),
      env: baseEnv({ TE_POLL_INTERVAL: '10', TE_POLL_TIMEOUT: '60' }),
    });
    assert.equal(code, EXIT.fail);
    assert.equal(api.count(RESULTS), 7);
    assert.match(output, /Agent 125: FAIL/);
    assert.match(output, /no result within 60 s/);
  });

  it('keeps polling through 404 and 5xx while results are not ready', async () => {
    const { code } = await run({
      routes: happyRoutes({ [RESULTS]: (n) => (n === 1 ? { status: 404 } : n === 2 ? { status: 503 } : { body: fixture('results-ready') }) }),
    });
    assert.equal(code, EXIT.pass);
  });

  it('waits out a rate-limited poll until the reset', async () => {
    const { code, api, clock } = await run({
      routes: happyRoutes({
        [RESULTS]: (n) => (n === 1
          ? { status: 429, headers: { 'X-Organization-Rate-Limit-Reset': String(T0 / 1000 + 25) } }
          : { body: fixture('results-ready') }),
      }),
    });
    assert.equal(code, EXIT.pass);
    assert.equal(api.count(RESULTS), 2);
    assert.equal(clock.sleeps[0], 25_000);
  });

  it('retries a rate-limited create after the reset', async () => {
    const { code, api } = await run({
      routes: happyRoutes({
        [CREATE]: (n) => (n === 1
          ? { status: 429, headers: { 'X-Instant-Test-Rate-Limit-Reset': String(T0 / 1000 + 5) } }
          : { status: 201, body: fixture('create-response') }),
      }),
    });
    assert.equal(code, EXIT.pass);
    assert.equal(api.count(CREATE), 2);
  });

  it('does not retry a create that failed with 5xx: it may have started a test', async () => {
    const { code, api } = await run({ routes: happyRoutes({ [CREATE]: { status: 502 } }) });
    assert.equal(code, EXIT.error);
    assert.equal(api.count(CREATE), 1);
  });

  it('stops on an authentication error without printing the token', async () => {
    const { code, output, api } = await run({
      routes: { [CREATE]: { status: 401, body: { title: 'Unauthorized', detail: 'Invalid token' } } },
    });
    assert.equal(code, EXIT.error);
    assert.match(output, /error: POST \/tests\/web-transactions\/instant returned HTTP 401: Unauthorized: Invalid token/);
    assert.equal(api.count(CREATE), 1);
    assert.equal(output.includes(TOKEN), false);
  });

  it('reports a request that cannot be sent without quoting the error, which may hold the token', async () => {
    const fetchImpl = async (_url, init) => {
      throw new TypeError(`Headers.append: "${init.headers.Authorization}" is an invalid header value.`);
    };
    let output = '';
    const code = await main({ env: baseEnv(), fetchImpl, ...fakeClock(), write: (text) => { output += text; }, cwd: REPO });
    assert.equal(code, EXIT.error);
    assert.match(output, /POST \/tests\/web-transactions\/instant failed: the request could not be sent/);
    assert.equal(output.includes(TOKEN), false);
  });

  it('reports a configuration error without calling the API', async () => {
    const { code, output, api } = await run({ env: baseEnv({ TE_AGENT_IDS: '' }) });
    assert.equal(code, EXIT.error);
    assert.match(output, /error: no agents/);
    assert.equal(api.calls.length, 0);
  });
});

describe('in GitHub Actions', () => {
  const inActions = (overrides = {}) => baseEnv({ GITHUB_ACTIONS: 'true', ...overrides });

  it('masks the target, then fences all further output between stop-commands markers', async () => {
    const { code, output } = await run({ routes: happyRoutes({ [DETAIL]: { body: fixture('detail-error') } }), env: inActions() });
    assert.equal(code, EXIT.fail);
    const lines = output.split('\n');
    assert.equal(lines.at(-1), '', 'output ends with a newline');
    lines.pop();
    assert.equal(lines[0], '::add-mask::ldaps://ldap.example.com:636/');
    assert.equal(lines[1], '::add-mask::ldap.example.com');
    assert.match(lines[2], /^::stop-commands::[0-9a-f-]{36}$/);
    const token = lines[2].slice('::stop-commands::'.length);
    assert.equal(lines.at(-1), `::${token}::`, 'commands resume only after the last line');
    const fenced = lines.slice(3, -1);
    assert.ok(fenced.some((line) => line.startsWith('Agent 125')));
    assert.ok(fenced.some((line) => line.startsWith('Result: FAIL')));
    assert.equal(fenced.some((line) => line.includes(token)), false);
  });

  it('keeps the fence on an API error', async () => {
    const { code, output } = await run({ routes: { [CREATE]: { status: 403 } }, env: inActions() });
    assert.equal(code, EXIT.error);
    const lines = output.trimEnd().split('\n');
    const token = lines[2].slice('::stop-commands::'.length);
    assert.equal(lines.at(-1), `::${token}::`);
    assert.match(lines.at(-2), /^error: POST \/tests\/web-transactions\/instant returned HTTP 403/);
  });

  it('escapes the target in ::add-mask::', async () => {
    const { output } = await run({ env: inActions({ TE_TARGET_URL: 'ldaps://ldap.example.com/dc=a%2Cdc=b' }) });
    assert.match(output, /^::add-mask::ldaps:\/\/ldap\.example\.com\/dc=a%252Cdc=b$/m);
  });

  it('hides error details and console logs by default, showing only the error type and length', async () => {
    const { output } = await run({ routes: happyRoutes({ [DETAIL]: { body: fixture('detail-error') } }), env: inActions() });
    const length = firstResult('detail-error').errorDetails.length;
    assert.ok(output.includes(`! error (Transaction): ${length} characters hidden (set TE_SHOW_DETAILS=true to show)`));
    assert.equal(output.includes('Authentication failed'), false);
    assert.match(output, /console logs \(3, 3 hidden: set TE_SHOW_DETAILS=true to show\):/);
    assert.equal(output.includes('peer CN'), false);
  });

  it('shows runtime facts while hidden, with their error messages reduced to a length', async () => {
    const facts = { results: [{ consoleLogs: [
      { level: 'INFO', value: 'runtime-fact markers: {"restartAfterStop":{"threw":true,"error":{"message":"Marker \\"rt\\" was already started"}}}' },
      { level: 'INFO', value: 'connect ECONNREFUSED 10.1.2.3:636' },
    ] }] };
    const { output } = await run({ routes: happyRoutes({ [LOGS]: { body: facts } }), env: inActions() });
    const length = 'Marker "rt" was already started'.length;
    assert.ok(output.includes(`[INFO] runtime-fact markers: {"restartAfterStop":{"threw":true,"error":{"message":"<${length} characters hidden>"}}}`));
    assert.equal(output.includes('already started'), false);
    assert.equal(output.includes('10.1.2.3'), false);
  });

  it('shows error details and console logs with TE_SHOW_DETAILS=true', async () => {
    const { output } = await run({
      routes: happyRoutes({ [DETAIL]: { body: fixture('detail-error') } }),
      env: inActions({ TE_SHOW_DETAILS: 'true' }),
    });
    assert.match(output, /! error \(Transaction\): Error: Authentication failed: invalidCredentials \(49\)/);
    assert.match(output, /\[INFO\] TLS cipher: TLS_AES_256_GCM_SHA384; peer CN: ldap\.example\.com/);
  });

  it('writes a job summary without error text or the target', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'te-instant-test-'));
    const summaryPath = path.join(dir, 'summary.md');
    try {
      await run({
        routes: happyRoutes({ [DETAIL]: { body: fixture('detail-error') } }),
        env: inActions({ GITHUB_STEP_SUMMARY: summaryPath, TE_SHOW_DETAILS: 'true' }),
      });
      const summary = readFileSync(summaryPath, 'utf8');
      assert.match(summary, /\| 125 \| Example Enterprise Agent \| FAIL \| 230 \|/);
      assert.match(summary, /error \(Transaction\), see log/);
      assert.equal(summary.includes('Authentication failed'), false);
      assert.equal(summary.includes('ldap.example.com'), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('dry run', () => {
  it('prints the request with the token redacted and the script summarised', async () => {
    const { code, output, api } = await run({ argv: ['--dry-run'] });
    assert.equal(code, EXIT.pass);
    assert.equal(api.calls.length, 0);
    assert.match(output, /^POST https:\/\/api\.thousandeyes\.com\/v7\/tests\/web-transactions\/instant\?aid=1234$/m);
    assert.match(output, /^Authorization: Bearer <redacted>$/m);
    assert.match(output, /"transactionScript": "<\d+ characters from ldap-monitor\.js, sha256 [0-9a-f]{16}\.\.\.>"/);
    assert.match(output, /"flagCollectConsoleLogs": true/);
    assert.equal(output.includes(TOKEN), false);
    assert.equal(output.includes('import { net'), false, 'the script itself is not printed');
  });
});
