---
title: Attack Chain Modeling
phase: 8D
created: 2026-06-14
status: LIVE_ADVISORY
---
<!-- WEBHOUND-GENERATED -->

# Attack Chain Modeling

Models plausible multi-step attack paths from finding combinations. ADVISORY ONLY — describes scenarios, not confirmed attacks.

## Location

`scripts/wade/reasoning/attack_chain.py` → `identify_attack_chains(findings)`

## Attack Chain Candidates

| Chain | Entry Point | Impact | Confidence |
|-------|------------|--------|------------|
| `admin_credential_takeover` | `exposed_env` or `wordpress_xmlrpc` | Account Takeover | HIGH (0.85) |
| `supply_chain_client_compromise` | `third_party_script_risk` + `missing_csp` | Client-Side Compromise | HIGH (0.83) |
| `weak_headers_browser_exploitation` | `missing_csp` + `missing_x_frame_options` | XSS Amplification | MEDIUM (0.65) |
| `recon_to_data_exfiltration` | `threat_intel_match` + any API exposure | Data Exfiltration | MEDIUM (0.60) |

## Output: AttackChainCandidate

```python
@dataclass
class AttackChainCandidate:
    chain_name: str
    entry_point: str
    chain_steps: ReasoningChain     # ordered steps with → arrows
    target_impact: str
    matched_findings: list[str]
    explanation: AttackChainExplanation  # steps, mitigations, advisory_note
    confidence: AttackChainConfidence
    advisory_only: bool = True           # always True
```

## Chain Example: Supply Chain Compromise

```
Third-party script loaded from external domain
→ No CSP restricts script sources
→ If external domain is compromised, injected script executes
→ Script runs with full page/DOM access
→ Client-side compromise (skimming, credential theft, redirect)
```

Mitigations included in every chain output.

## Key Properties

- `advisory_only: True` always
- Every chain includes concrete mitigations
- Confidence levels are conservative (no chain exceeds 0.85)
- Provider-only findings never trigger chains (no false escalation)

## See Also

- [[Finding Correlation]] · [[WADE Reasoning Engine]] · [[Confidence Model]]
- [[Root Cause Analysis]] · [[Shadow Mode]]

#webhound #wade #attack-chain #phase8d
