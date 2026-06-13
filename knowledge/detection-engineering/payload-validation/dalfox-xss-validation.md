# DalFox — XSS Validation

**Tool:** DalFox · **Type:** XSS scanner · **Concept:** payload validation

DalFox is a modern (Go/Rust) XSS scanner built around **verification**. It pipelines:
parameter analysis → reflection/context discovery → payload selection → **validation**.
Crucially it does not stop at reflection; it confirms the payload by checking the
**parsed-DOM/AST** outcome and, where needed, by triggering execution in a headless
browser (verified/`--verify` mode), so a finding means the script would actually
run, not merely echo. It detects reflected, stored, and DOM XSS, fingerprints WAFs
to adjust payloads, and emits machine-readable output (JSON, **SARIF**) plus a
REST/MCP interface for integration.

**Why it matters for WebHound:** DalFox is the reference for *proof-grade* XSS
validation and for emitting findings in standard formats. Its "verify execution,
then report" stance is exactly the dynamic-proof bar WADE should apply to XSS, and
its SARIF output is a model for how WebHound findings can interoperate with CI and
external tooling.

**Related:** [[dalfox-parameter-mining]], [[dalfox-false-positive-reduction]], [[xsstrike-context-analysis]].
