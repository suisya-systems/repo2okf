---
type: Module
title: Authentication
description: Authenticates incoming requests.
tags:
- authentication
- security
sources:
- id: evidence-65762d61757468
  resource: repo:src/auth.rs#L7
  title: Source evidence ev-auth
  author: process:repo2okf-scanner
  evidence_id: ev-auth
  content_hash: blake3:auth
repo2okf:
  claims:
  - id: validates-credentials
    text: The module validates incoming credentials.
    evidence_ids:
    - ev-auth
    ai_generated: false
  relationships:
  - target: modules/data
    label: Data
    kind: calls
    source_relationship_ids:
    - edge-call
    origin_reference_ids:
    - ref-call
    evidence_ids:
    - ev-auth
---

# Authentication

The module validates incoming credentials.

## Relationships

- [Data](/modules/data.md) — calls[^evidence-65762d61757468]

## Evidence-bound claims

- The module validates incoming credentials.[^evidence-65762d61757468]

[^evidence-65762d61757468]: Source evidence ev-auth
