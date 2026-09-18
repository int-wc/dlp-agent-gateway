# Security policy and threat model

This repository is an educational/reference DLP gateway. Do not put it on a production upload path without an independent security review.

## Trust boundaries

- Client keys authenticate an actor; the client cannot supply a different actor or forwarding URL. Keep admin and client keys separate and out of Git. HTTPS/mTLS and secret rotation are required beyond localhost.
- Configured downstream services and the local Ollama process are trusted operators of any data they receive. Model input is an excerpt of original content, not anonymized.
- Files and model outputs are untrusted. An LLM risk category can increase scrutiny, never override a hard guard. Parse failure and configured-model outage result in review.
- Audit metadata, filenames, justification and exception records can be sensitive; the local SQLite file is not encrypted. The console is not a substitute for proper identity and session management.
- A policy exception is scoped to one actor, destination and exact file digest, expires within 24 hours, and bypasses only configurable policy hits. Production needs dual control and revocation.

## Before any real deployment

Add a TLS reverse proxy with total request-size limits, isolated parsing workers, per-tenant authorization, rate limiting, downstream receiver authentication, durable transaction/outbox handling, audit retention and access control, a full document coverage strategy, malware scanning, monitoring, and an incident response plan. Validate legal basis, notice, minimization and applicable privacy obligations with your organization.

If you find a vulnerability, avoid opening an issue with exploit data or real documents. Contact the maintainer privately through the eventual GitHub repository security advisory channel. Until publication, report it to the repository owner directly.
