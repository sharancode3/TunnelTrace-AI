# Policy-as-Code Directory — TunnelTrace AI

This directory is reserved for versioned YAML security and compliance rulesets (NIST SP 800-77 Rev. 1, RFC 8221, RFC 8247).

## Implementation Stage
Per the canonical TunnelTrace AI implementation roadmap, declarative Policy-as-Code rules and evaluation logic are implemented during **Stage 6 (Security, Compliance, Evidence & Scoring Engine)**.

## Governance Rule
- Security findings, compliance statuses (PASS/FAIL/UNKNOWN/NA), and deductive score penalties derive strictly from deterministic YAML policies evaluated against reconstructed protocol facts.
- The LLM AI Analyst never asserts or invents security policies.
