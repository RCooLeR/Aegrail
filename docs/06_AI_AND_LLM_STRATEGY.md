# AI And LLM Strategy

## AI Role

AI in Aegrail should make evidence easier to understand. It should not replace collection, normalization, rules, scoring, or correlation.

Good uses:

- summarize deterministic findings
- explain likely incident chains
- draft technical reports
- draft manager summaries
- suggest next checks
- cluster similar evidence
- generate compact evidence overviews
- help compare rule output during evaluation

Risky uses:

- deciding whether a host is compromised without deterministic evidence
- reading raw secrets
- inventing causal chains
- ranking findings live without rule metadata
- producing reports without evidence references

## Model Gateway

All model calls should go through one gateway interface.

Responsibilities:

- route to Ollama or future managed providers
- enforce timeouts
- enforce concurrency
- log latency and errors
- redact or reject sensitive inputs
- normalize response formats
- support offline mode
- support model-set IDs from config

Initial backend:

- Ollama on local GPU hardware

Model names must be config-driven. The code should not hard-code a preferred investigation model or embedding model.

Current implementation:

- `ports.ModelGateway` defines health, generation, and embedding calls.
- `internal/adapters/ollama` implements the gateway using Ollama `/api/tags`, `/api/generate`, and embedding endpoints.
- `internal/adapters/modeltest` provides a deterministic fake gateway for tests.
- `AEGRAIL_OLLAMA_BASE_URL`, `AEGRAIL_OLLAMA_INVESTIGATION_MODEL`, `AEGRAIL_OLLAMA_EMBEDDING_MODEL`, `AEGRAIL_OLLAMA_TIMEOUT`, and `AEGRAIL_OLLAMA_OFFLINE` configure the runtime.
- `aegrail analyze model status` verifies the configured local model gateway without requiring database access.
- `aegrail analyze model prompt` and `aegrail analyze model embed` are gateway smoke-test commands.
- `aegrail report evidence-bundle` exports compact redacted finding evidence for model-assisted analysis.
- `aegrail analyze model report` builds an evidence bundle, sends it to the configured investigation model, and writes a prompt-versioned advisory analysis report.
- `aegrail analyze model report --save` persists the generated report in the Hub.
- `aegrail report model-analysis list` and `aegrail report model-analysis show` inspect saved model reports.

## Evidence Bundle Contract

The model receives a redacted evidence bundle, not arbitrary raw data.

Bundle contents:

- finding summaries
- rule IDs and versions
- severity and confidence
- timeline excerpts
- affected apps, services, hosts, and agents
- deployment context
- redacted event payloads
- evidence references
- operator-provided notes where available

Bundle exclusions:

- plaintext passwords
- session cookies
- authorization headers
- API keys
- full database rows unless explicitly redacted
- full raw logs unless summarized and redacted

Current deterministic bundle:

- schema: `aegrail.evidence_bundle.v1`
- redaction version and rule notes
- source finding IDs, rule IDs, versions, status, severity, confidence, risk score, and risk band
- compact event references from finding metadata
- compact deployment context
- compact rule metadata and risk factors
- redacted metadata excerpts with sensitive keys replaced by `[REDACTED]`
- SHA-256 bundle hash for future prompt/report provenance

## Report Contract

Current deterministic reports:

- JSON Hub findings export for machine use
- Markdown technical report for analyst review, sorted by risk and backed by finding/event references
- Markdown manager summary for non-technical status, impact, and next steps
- CSV timeline export for spreadsheet review and incident handoff

Current model-assisted report:

- schema: `aegrail.model_analysis_report.v1`
- status: `completed`, `offline`, or `failed`
- advisory notice that deterministic findings remain the source of truth
- source finding IDs
- evidence bundle schema, redaction version, generated time, and SHA-256 hash
- prompt template ID, version, and SHA-256 hash
- final prompt SHA-256 hash
- provider, model name, offline flag, generation timing, and token counts where available
- raw generated analysis text, or an error if the model gateway was offline or failed

Saved Hub model reports also store:

- organization, project, environment, and optional app scope
- model report ID and created time
- queryable status, model, prompt, bundle, finding IDs, timing, and token-count columns
- metadata for tool, scope, model base URL, offline state, notice, and deterministic source

Generated analysis should:

- state that it is generated analysis
- cite deterministic finding IDs or event IDs
- separate confirmed evidence from inference
- explain confidence
- include recommended next checks
- stay concise
- avoid claiming certainty when evidence is incomplete

Technical report shape:

```text
Summary
Confirmed evidence
Probable sequence
Affected systems
Recommended containment
Recommended remediation
Evidence references
Tool, rule, model, and prompt versions
```

Manager summary shape:

```text
What happened
Business impact
Current status
Actions taken
Recommended next steps
```

## Embeddings

Embeddings can support:

- compact evidence search
- similar finding lookup
- report chunk retrieval
- analyst query over prior cases

Embeddings should not be required for core detection. If the embedding model is unavailable, deterministic rules and reports should still work.

## Prompt Versioning

Prompts should have stable version IDs.

Cache or report metadata should include:

- model set
- model name
- prompt version
- evidence bundle hash
- source finding IDs
- generated time

When prompt rules change, bump the prompt version.

Current prompt template:

- ID: `aegrail.incident_analysis`
- Version: `2026-05-13.1`
- Output intent: concise Markdown with executive summary, probable incident chain, priority findings, next checks, and uncertainty/gaps.

## Safety

Aegrail should enforce security-specific safety rules:

- do not expose secrets
- do not provide exploit instructions beyond defensive investigation needs
- do not invent evidence
- do not recommend destructive remediation without backups
- distinguish confirmed compromise from suspicious drift
- preserve forensic caution in incident reports

Generated text should help the operator think, not replace the operator.
