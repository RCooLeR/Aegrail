# Dashboard

The dashboard is for quick operational judgement.

It should answer:

- is everything healthy?
- if not, which company, site, node, service, or issue needs attention?
- what evidence supports the issue?
- can the operator mark it reviewed, resolved, or false positive?
- can the operator generate a useful report?

## Views

- Overview: up to six companies sorted by severity, with site summaries.
- Companies: all companies and health counts.
- Sites: company/site drilldown.
- Nodes: instances, agents, services, and issue actions.
- Issues: active queue with details, evidence, action buttons, and report export.
- Issue Details: overview, evidence, timeline, comments, related issues, and LLM analysis generation.
- Signals: readable raw observations for debugging.
- Browser Scripts: script observations, domains, inline hashes, tag-manager IDs, and allowlist actions.
- Deployments: mark a confirmed deployment timeframe after previewing open alerts/warnings in that window.
- Reports: deterministic and model-assisted reports.
- Settings: tabbed profile, Hub scope, triage defaults, companies, sites, nodes, users/access/2FA, and inventory.

The main dashboard surface should stay simple: show what is wrong, where, why, and what action can be taken.

## Development

```powershell
cd dashboard
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173/dashboard/
```

Vite proxies `/api` and `/healthz` to:

```text
http://127.0.0.1:8787
```

Build and serve from Hub:

```powershell
cd dashboard
npm run build
cd ..\app
go run ./cmd/aegrail hub serve --dashboard-dir ..\dashboard\dist
```

Preferred split binary command:

```powershell
cd ..\app
go run ./cmd/aegrail-hub hub serve --dashboard-dir ..\dashboard\dist
```

## Structure

```text
src/App.tsx                  composition root
src/dashboard/controllers/   data loading and actions
src/dashboard/model/         view models and sorting
src/dashboard/pages/         dashboard pages
src/dashboard/components/    shared UI pieces
src/dashboard/utils/         formatting, reports, metadata helpers
```

Rules:

- Detection logic belongs in the Hub, not in browser code.
- Dashboard pages should read Hub APIs and present clear operator actions.
- Issue views should explain why a warning exists and what action is expected.
- The LLM analysis action sends only the selected issue's compact redacted evidence bundle to the configured model gateway, then stores the returned advisory report with prompt and evidence hashes.
- The model returns strict JSON. Hub converts that JSON into escaped, controlled HTML for the dashboard; raw model HTML is not trusted.
- Hub can also analyze the issue queue automatically. `hub serve` starts a background pass by default, controlled by `AEGRAIL_MODEL_ANALYSIS_AUTO`, `AEGRAIL_MODEL_ANALYSIS_INTERVAL`, and `AEGRAIL_MODEL_ANALYSIS_LIMIT`. Keep the limit small for local GPUs.
- Operators can run one pass manually with `aegrail hub model-analysis queue`.
- The Deployments page records a version/note, actor, optional commit SHA, start time, and finish time. It previews open issues that overlap the selected node/timeframe and requires a second confirmation before saving.
- Deployment markers are context, not blanket suppression. Hub scoring may lower expected low/medium rollout drift, but high-risk administrator, payment, persistence, and incident-chain findings stay visible.
- The Browser Scripts page can allowlist a domain, inline SHA-256, or tag-manager ID. It updates Hub allowlist state; it does not edit agent YAML.
- Users & 2FA uses a pending enrollment flow: generate QR, verify the current 6-digit TOTP code, then activate. Pending and active TOTP secrets are encrypted at rest with `AEGRAIL_HUB_USER_SECRET`.

Recommended local investigation model order:

| Rank | Model | Ollama ref | Best use |
| --- | --- | --- | --- |
| 1 | Qwen2.5-Coder-14B-Instruct | `qwen2.5-coder:14b` | Best overall for source-code website security review |
| 2 | Mistral Small 3.2 24B Instruct | `mistral-small3.2:latest` | Better general reasoning, reports, tool/function calling, structured output |
| 3 | DeepSeek-Coder-V2-Lite-Instruct | `deepseek-coder-v2:16b` | Good coding alternative, efficient for local use |
| 4 | Qwen3-14B | `qwen3:14b` | Good reasoning/general analysis, less specifically code-security tuned |
| 5 | StarCoder2-15B | `starcoder2:15b` | Good code model, older and less instruction/security-review friendly |

Set `AEGRAIL_OLLAMA_INVESTIGATION_MODELS` to this comma-separated order. If `AEGRAIL_OLLAMA_INVESTIGATION_MODEL` is empty, Hub selects the first installed model from the ranked list.
Use `AEGRAIL_OLLAMA_TIMEOUT=5m` or higher for the larger local models.
- File issues can create Hub ignore rules for a directory. The dashboard prompts for the path, the Hub suppresses future matching file findings, and the selected issue is marked false positive.
- Node details show a safe agent config snapshot from config coverage, including collector state, database/log/browser counts, and sanitized file paths ignored by the agent.
