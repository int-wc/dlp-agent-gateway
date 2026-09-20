# Security policy and threat model

This repository is an educational/reference DLP gateway. Do not put it on a production upload path without an independent security review.

## Trust boundaries

- Client keys or a verified, explicitly mapped mTLS certificate authenticate an actor; the caller cannot supply a different actor or forwarding URL. Keep all keys, private keys, tokens, and database credentials out of Git. mTLS identity is accepted only from Go's verified certificate chain, never from a forwarded identity header.
- OIDC authenticates console users through authorization code flow with PKCE. Provider roles map to Casbin viewer/operator/admin permissions. The signed cookie is HttpOnly and SameSite=Lax; production must use HTTPS, a random session secret, short provider sessions, revocation, and a reviewed role-claim contract.
- Downstream connector URLs are server-side allowlisted. Optional Bearer credentials are resolved indirectly from environment variables; optional client certificates and private CAs are loaded at startup. Redirects are never followed, and downstream response bodies are discarded.
- Configured downstream services and the local Ollama process are trusted operators of any data they receive. Model input is an excerpt of original content, not anonymized.
- Files and model outputs are untrusted. An LLM risk category can increase scrutiny, never override a hard guard. Parse failure and configured-model outage result in review.
- Audit metadata, filenames, justification and exception records can be sensitive. PostgreSQL provides transactional concurrency but is not automatically encrypted, tamper-proof, backed up, highly available, or compliant. The local atomic JSON fallback remains demo-only. Policy, identity, or exception state read failure fails the upload closed. Authenticated upload decisions and early rejections are recorded, but anonymous authentication failures belong in a rate-limited ingress/access log rather than synchronous application storage.
- A policy exception is scoped to one actor, destination and exact file digest, expires within 24 hours, and bypasses only configurable policy hits. Production needs dual control and revocation.

## Before any real deployment

Review TLS termination and trusted-proxy boundaries; configure production OIDC and PKI; exercise certificate/key rotation; enable PostgreSQL TLS, backups, restore drills, retention, deletion, and immutable export; add isolated parsing workers, per-tenant authorization, rate limiting, durable transaction/outbox handling, a full document coverage strategy, malware scanning, monitoring, and an incident response plan. Validate legal basis, notice, minimization, and applicable privacy obligations with your organization.

If you find a vulnerability, avoid opening an issue with exploit data or real documents. Contact the maintainer privately through the eventual GitHub repository security advisory channel. Until publication, report it to the repository owner directly.
