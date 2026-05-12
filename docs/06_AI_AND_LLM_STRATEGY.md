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

## Report Contract

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

## Safety

Aegrail should enforce security-specific safety rules:

- do not expose secrets
- do not provide exploit instructions beyond defensive investigation needs
- do not invent evidence
- do not recommend destructive remediation without backups
- distinguish confirmed compromise from suspicious drift
- preserve forensic caution in incident reports

Generated text should help the operator think, not replace the operator.
