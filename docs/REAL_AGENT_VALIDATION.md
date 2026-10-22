# Real-agent validation

The unit tests in `test/` run `ldap-monitor.js` against a stand-in for the ThousandEyes runtime (`test/support/thousandeyes-stub.js`). That is tier 1. Tier 2 runs the same script, unmodified, on a real ThousandEyes agent. The workflow `.github/workflows/real-agent-validation.yml` does this as a web-transaction instant test, which runs once and is not saved as a scheduled test.

- **Workflow:** `.github/workflows/real-agent-validation.yml`
- **Helper:** `scripts/te-instant-test.mjs`. It creates the instant test, polls for the result and checks it. Plain Node, no dependencies.
- **Diagnostic script:** `scripts/te-runtime-facts.js`. It records how the runtime behaves where the ThousandEyes documentation is silent ([below](#what-a-run-settles)).

## When it runs

| Trigger | What runs |
| --- | --- |
| Manual (`workflow_dispatch`) | `ldap-monitor.js`. Then `te-runtime-facts.js`, unless `runtime_facts` is off. |
| Nightly (`schedule`, 04:23 UTC) | `ldap-monitor.js` only. |

- **Not on pull requests or pushes.** A fork pull request can never reach the ThousandEyes token.
- **Configuration check.** The first step checks the five required settings:

| Required settings set | Scheduled run | Manual run |
| --- | --- | --- |
| None | Skips with a notice, job green | Fails, listing what is missing |
| Some | Fails, listing what is missing | Fails, listing what is missing |
| All | Runs | Runs |

  So the nightly run stays green until set-up starts. A half-finished set-up shows up red.
- **Default branch only.** GitHub runs scheduled workflows only from the default branch. It offers `workflow_dispatch` only for workflow files that exist there. Nothing runs until this workflow is merged to `main`.
- **Target from the secret only.** The target always comes from the `TE_TARGET_URL` secret. There is no input for it: the test carries the bind credentials, so whoever chooses the target receives the password.

## Set-up

### 1. In ThousandEyes

1. **A dedicated account group** for this validation, holding only the test's Secure Credentials and agents. Anyone with the token can create a test in that group that attaches any credential in the group, aimed at a server of their choice. So the token effectively exposes every Secure Credential in the account group.
2. **An API credential for that account group only.**
   - Prefer an API key (Account Settings > Users and Roles). API keys are organization-owned, have their own permissions, and can be scoped to one account group. An OAuth bearer token also works, but it carries all the permissions, in all account groups, of the user who owns it.
   - Permissions needed:
     - creating instant tests: the v7 reference says "You will need to be an Account Admin".
     - running instant tests: the instant-test guide lists *View agents in account group* and *Edit tests*.
     - reading test results.
   - Grant no more than that.
3. **Secure Credentials for the probe.**
   - `ldapMonUser` (bind DN) and `ldapMonPass`, as for the scheduled test (see the root README).
   - Optional: `ldapCaBase64` for a private CA.
   - Optional: `ldapDebugMode` set to `true` for more console output.
4. **An agent that can reach the LDAP server.** For an internal server, that is an Enterprise Agent.
5. **Look up the IDs**, using the token:

```bash
API=https://api.thousandeyes.com/v7
AUTH="Authorization: Bearer $TE_API_TOKEN"
curl -s -H "$AUTH" "$API/account-groups" | jq '.accountGroups[] | {aid, accountGroupName}'
curl -s -H "$AUTH" "$API/agents?aid=$AID" | jq '.agents[] | {agentId, agentName, agentType}'
curl -s -H "$AUTH" "$API/credentials?aid=$AID" | jq '.credentials[] | {id, name}'
```

### 2. In GitHub: the `real-agent-validation` environment

The job runs in the environment `real-agent-validation`. Create that environment **before the workflow first runs**, in Settings > Environments:

1. Create the environment `real-agent-validation`.
2. Under **Deployment branches and tags**, choose *Selected branches and tags* and allow only `main`.
3. Add the secrets and variables below **to the environment**, not to the repository. Repository-level secrets would be readable by any workflow on any branch.

> GitHub creates a missing environment the first time a job refers to it, **without any protection rules**. If the first scheduled run comes before step 2, the environment exists, but unprotected. Check its deployment branches even when it already exists.

| Name | Kind | Required | Value |
| --- | --- | --- | --- |
| `TE_API_TOKEN` | environment secret | yes | The API key or OAuth bearer token from step 1. |
| `TE_TARGET_URL` | environment secret | yes | The test URL, e.g. `ldaps://ldap.example.com:636/`. It is a secret so that the host name is masked in logs, and so that only maintainers can change it. |
| `TE_ACCOUNT_GROUP_ID` | environment variable | yes | The account group ID (`aid`). Every request sends it as the `aid` query parameter, so the test runs in that account group even if the credential can see several. |
| `TE_AGENT_IDS` | environment variable | yes | One or more agent IDs, comma-separated. The `agent_id` input overrides it for a manual run. |
| `TE_CREDENTIAL_IDS` | environment variable | yes | IDs of the Secure Credentials to attach (`ldapMonUser`, `ldapMonPass`, and any optional ones), comma-separated. These are IDs only; the values stay in ThousandEyes. |
| `TE_EXPECTED_MARKERS` | environment variable | no | Markers every agent must report. Default `ldap-bind,ldap-search`. Use `ldap-bind` when `ldapBindOnly` is set. |
| `TE_TIME_LIMIT` | environment variable | no | Transaction time limit in seconds, 5–180. Default 30, the same as the Terraform default. |
| `TE_SHOW_DETAILS` | environment variable | no | `true` to print error details and console logs in the log ([Public logs](#public-logs)). Default: hidden in Actions. |

- **Rotation.** After an API key is regenerated, the old key stays valid for 7 days.

## Running it

```bash
gh workflow run real-agent-validation.yml                                  # agents from TE_AGENT_IDS
gh workflow run real-agent-validation.yml -f agent_id=125 -f runtime_facts=false
```

From a workstation, with the same names as environment variables. Outside Actions, error details and console logs are shown by default.

```bash
export TE_API_TOKEN=… TE_ACCOUNT_GROUP_ID=… TE_AGENT_IDS=… TE_CREDENTIAL_IDS=…
node scripts/te-instant-test.mjs --url ldaps://ldap.example.com:636/
node scripts/te-instant-test.mjs --dry-run --url ldaps://ldap.example.com:636/   # print the request; nothing is sent
node scripts/te-instant-test.mjs --script scripts/te-runtime-facts.js --markers none --credentials none --time-limit 60 --url …
```

- **Options.** Every option has an environment fallback; the full list is in the header of `scripts/te-instant-test.mjs`.
- **Dry run.** It prints the request body with the token redacted, and the script reduced to its size and SHA-256.

## Reading the result

The helper makes these calls, all under `https://api.thousandeyes.com/v7` with `?aid=<TE_ACCOUNT_GROUP_ID>`:

1. `POST /tests/web-transactions/instant` creates and starts the test.
   - The body mirrors `terraform/monitoring.tf`: `testName`, `url`, `transactionScript`, `agents`, `credentials`, `timeLimit` and `flagCollectConsoleLogs: true`.
   - The response has the `testId`, not the result.
2. `GET /test-results/{testId}/web-transactions?window=<seconds since creation + 60>s` is polled every 10 s, for up to 10 minutes.
   - Without a window, the API returns only the most recent round. Agents can report in different rounds, so the helper asks for every round since the test was created.
   - It follows `_links.next`, only within the API base URL, and keeps each agent's latest round across polls.
   - It stops once every requested agent has reported. An agent busy with another test starts the instant test only when that test is done.
3. `GET /test-results/{testId}/web-transactions/agent/{agentId}/round/{roundId}` fetches each agent's detailed result. Only this one carries the `markers`.
4. `GET …/round/{roundId}/console-logs` fetches each agent's console output.

Then it prints a summary like this one, which is from a local run, with details shown:

```
Instant test 7012345: time limit 30 s; expected markers: ldap-bind, ldap-search
Agent 125 (Example Enterprise Agent): PASS, transaction 412 ms, round 1792184400
  markers: ldap-attempt-1 41 ms, ldaps-ssl-handshake 41 ms, ldap-bind 12 ms, ldap-search 6 ms
  console logs (3):
    [INFO] Establishing LDAPS connection with system CA certificates
    [INFO] TLS cipher: TLS_AES_256_GCM_SHA384; peer CN: ldap.example.com
    [INFO] LDAP Monitor: PASS - Total 59ms (connect: 41ms, bind: 12ms, search: 6ms)
Result: PASS (1 agent(s))
```

- **In Actions, by default:**
  - an error shows as `! error (Transaction): 53 characters hidden (set TE_SHOW_DETAILS=true to show)`.
  - console logs are counted, not printed. `runtime-fact` lines are the exception: they are printed with their quoted error messages reduced to a length.
- **Job summary.** The GitHub job summary gets a table of agent, result, transaction time and markers. It never includes error text or console output.
- **Exit status:**

| Exit | Meaning |
| --- | --- |
| 0 | Every agent passed. |
| 1 | Any one agent failed:<ul><li>it reported `errorDetails`</li><li>an expected marker is missing</li><li>it sent no result within the poll timeout</li></ul> |
| 2 | Configuration or API error, such as a 401, 403 or a rejected request body. The API's problem title and detail are printed. |

- **The token never appears in output.** `readConfig` rejects a token that is not printable ASCII. If a request cannot be sent, the message is generic, because the error text could quote the header.
- **Retries:**
  - Polling rides out 404, 5xx and 429 responses until the timeout. A 429 waits until the later of the `X-Instant-Test-Rate-Limit-Reset` and `X-Organization-Rate-Limit-Reset` times.
  - Creating the test is retried only on 429. After any other failure, the test may already have started.

## What a run settles

The stub makes assumptions where the ThousandEyes documentation is silent or only implies an answer. A manual run with `runtime_facts` on answers them.

`te-runtime-facts.js` prints one `runtime-fact <name>: <JSON>` console line per fact. It describes values by type and size, not content; only error messages are quoted, in `message` fields, and those are hidden in Actions unless `TE_SHOW_DETAILS=true`.

- **Connections:** it opens two connections to the target and sends only an UnbindRequest, with no bind.
- **Credentials:** it attaches none.
- **Certificates:** it does not check the certificate (`rejectUnauthorized: false`).
- **Time limit:** it runs with a 60 s limit, so `timeout` 60 means seconds.

| Stub assumption | Evidence | Read it as |
| --- | --- | --- |
| `test.getSettings().timeout` is in seconds. The probe's `testTimeLimitMs` treats values up to 180 as seconds. | `runtime-fact settings` → `timeout`, `timeoutType` | `60` means seconds; `60000` means milliseconds. |
| `sock.setTimeout()` exists, ends an idle read, and takes milliseconds. The stub enforces it only with `enforceSocketTimeout`, as Node's idle timeout. | `runtime-fact socket` → `methods.setTimeout`; `runtime-fact setTimeout` → `unit`, `read` | `setTimeout(2)` on an idle connection: `milliseconds` if the read ended within 1 s, `seconds` if it ended later (about 2 s), `not enforced` if it was still pending at 6 s. `read.error.code` is the error the probe would see. |
| `read()` resolves with `null` at end of stream. | `runtime-fact read-at-end` → `reads` (up to three reads after the server closed the connection) | The probe reports "connection closed" at once for `null` or `undefined`, and after three empty buffers in a row. A `rejected` read is reported as that read error. `pending` would mean the probe notices a closed connection only when its time budget runs out. |
| `credentials.get()` throws for a credential not associated with the test. The probe copes either way: it maps a throw to `null`. | `runtime-fact credentials` → `unassociated.threw`, or `returned` | `threw: true` matches the stub. Otherwise the stub should return what `returned` describes. |
| A marker restart throws. This is documented, but unchecked here. | `runtime-fact markers` → `restartAfterStop.threw`, `stopNeverStarted.threw` | `true` matches the stub. The marker list in the result shows how ThousandEyes reports `rt-marker`. |
| ThousandEyes accepts an `ldap://` or `ldaps://` test URL and passes it through. | The `POST` succeeds; `runtime-fact settings` → `urlScheme`; `runtime-fact target` | A 400 on create, or `urlScheme` other than `ldap`/`ldaps`, means the URL needs another form. Terraform and the probe would then have to change. |
| `getPeerCertificate()` exists on TLS sockets. | `runtime-fact socket` → `methods.getPeerCertificate`; `runtime-fact getPeerCertificate` → `hasSubject` | `function` and `hasSubject: true` match the probe's expectation. Needs an `ldaps://` target. With `TE_SHOW_DETAILS=true`, the probe's `TLS cipher: …; peer CN: …` line shows it too. |

After the first real run, update the assumptions at the top of `test/support/thousandeyes-stub.js` and the README's Testing section to match. Also replace the synthetic fixtures in `test/fixtures/te-instant-test/` with recorded responses, with IDs and names scrubbed.

## Public logs

This repository is public, so its Actions logs are public too.

- **The target.** In Actions, the helper first masks the target URL and host name (`::add-mask::`, with `%`, CR and LF escaped).
- **Details hidden by default.** Error details and console logs can carry certificate names (CN and SANs), IP addresses, the base DN and server diagnostics. In Actions they are hidden unless the environment variable `TE_SHOW_DETAILS` is `true`. Only show them for a run you are watching, and consider deleting that run's logs afterwards.
- **Workflow commands.** After masking, everything the helper prints is fenced between `::stop-commands::<random token>` and `::<token>::`. That fence is what stops text from an agent, an LDAP server or the API from issuing workflow commands. The helper also breaks up `##[` anywhere in a line and `::` at the start of one. Indentation alone would not stop a command.

## Limits

- **Rate limits.** Instant tests have their own limit: 24 calls per minute. Other API calls share the organization's 240 requests per minute. One run makes one or two instant-test calls plus a few dozen polls.
- **Time limit.** `timeLimit` is 5–180 s. `targetTime` defaults to 10 s and may not exceed it, so the helper lowers it when the time limit is below 10 s.
- **Alerts.** Instant tests do not raise alerts. Their results are not kept permanently.

## Interactive alternative

ThousandEyes publishes an MCP server and a Claude Code plugin ([thousandeyes/thousandeyes-ai-agents-toolkit](https://github.com/thousandeyes/thousandeyes-ai-agents-toolkit)). Its `thousandeyes-synthetic-monitoring` skill uses the tool `run_web_transaction_instant_test` for the same check, run by hand from a chat. The toolkit README gives the install command as `claude plugin install thousandeyes`. The MCP endpoint is `https://api.thousandeyes.com/mcp`. This workflow is the unattended, repeatable version.

## References

- **Endpoints:**
  - [Create web transactions instant test](https://developer.cisco.com/docs/thousandeyes/create-web-transactions-instant-test/)
  - [Get web transactions test results](https://developer.cisco.com/docs/thousandeyes/get-web-transactions-test-results/): `window`, `startDate`, `cursor`, and the latest round by default.
  - [results by agent and round](https://developer.cisco.com/docs/thousandeyes/get-web-transactions-test-results-by-agent-and-round/)
  - [console logs by agent and round](https://developer.cisco.com/docs/thousandeyes/get-console-logs-test-results-by-agent-and-round/)
- **Models:**
  - [instant tests (official Python SDK)](https://github.com/thousandeyes/thousandeyes-sdk-python/tree/main/thousandeyes-sdk-instant-tests)
  - [test results (official Python SDK)](https://github.com/thousandeyes/thousandeyes-sdk-python/tree/main/thousandeyes-sdk-test-results)
- **Credentials and limits:**
  - [Getting started with the API](https://docs.thousandeyes.com/product-documentation/getting-started/getting-started-with-the-thousandeyes-api): bearer header, account group context and `aid`.
  - [Authentication](https://developer.cisco.com/docs/thousandeyes/authentication/)
  - [API keys](https://developer.cisco.com/docs/thousandeyes/regenerate-api-key/)
  - [Rate limits](https://developer.cisco.com/docs/thousandeyes/rate-limits/)
- **Behaviour:**
  - [Working with instant tests](https://docs.thousandeyes.com/product-documentation/tests/working-with-instant-tests)
  - [Transaction scripting reference](https://docs.thousandeyes.com/product-documentation/browser-synthetics/transaction-tests/transaction-scripting-reference): markers, `test.getSettings()`, console logs.
- **GitHub Actions:**
  - [Environments](https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment): deployment branch rules, and environment secrets.
  - [Stopping and starting workflow commands](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#stopping-and-starting-workflow-commands)
