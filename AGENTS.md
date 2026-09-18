# Repository guidance

- This is a synthetic-data reference implementation, not a production DLP system. Preserve fail-closed upload decisions and the check-before-forward invariant.
- Never commit real documents, secrets, local databases, .env files, or customer-derived fixtures. Tests must use invented data.
- Keep model calls local and advisory; policy/identity guards and destination allowlists cannot be overridden by model output.
- Document newly supported formats and their extraction blind spots. A partially inspected document must not be allowed as fully inspected.
- Run the test suite before claiming a completed change. Treat deployment, production traffic and external repository publication as separate steps.
