# TunnelTrace.AI

## Purpose

Investigate IPsec packet captures. Reconstruct IKE and Child SA state, evaluate cryptographic posture, and link every finding to packet evidence and reproducible lineage.

## Users and use

Security analysts, IPsec VPN engineers, researchers, and students work at a local workstation. The primary workflow is capture ingestion → analysis → detection → evidence review → report export. Monitoring, asset discovery, inventory, vulnerabilities, and controlled lab scenarios are related tools.

## Product truth

- The frontend consumes the existing local FastAPI API and WebSocket services.
- Do not fabricate captures, findings, telemetry, security scores, or service state.
- Scores are withheld by the backend when evidence coverage is insufficient.
- Live capture, discovery, and lab capabilities depend on host services and must show their actual availability.
- The interface must preserve the complete analysis routes and their working interactions.

## New visual brief

The new frontend is an editorial investigation product, not an admin dashboard. Translate the Forma reference through oversized typography, open space, asymmetrical composition, restrained chrome, and large narrative sections. Use warm paper and charcoal as the main surfaces with muted lime as the only accent. Avoid orange, yellow, blue, cyan, purple, violet, pink, magenta, neon treatment, and the old sidebar/cards-first composition. Motion must remain calm and respect reduced motion.
