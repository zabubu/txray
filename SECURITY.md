# Security policy

## Scope

txray is an analysis aid. A `pass` verdict means no known risky pattern was found, not
that a request is safe. Reports about detection gaps are welcome as regular issues with an
example payload.

Please report privately anything that affects the safety of people running txray, for
example:

- a payload that crashes the analyzer, hangs it or exhausts memory;
- a way to make a request display or decode differently from what it executes or signs
  (decoder or EIP-712 hashing discrepancies);
- authentication or rate-limit bypass in the HTTP API;
- a way to make the server issue requests to a URL chosen by a client (SSRF).

## Reporting

Use GitHub's private vulnerability reporting on this repository ("Security" tab →
"Report a vulnerability"). Include a minimal reproduction and the version or commit.
Please do not open a public issue for these.

## Deployment recommendations

- Always configure API keys; anonymous mode is meant for local development.
- Bind to localhost or put the service behind a TLS-terminating reverse proxy.
- Use an RPC endpoint you trust: on-chain checks (code presence, proxy implementation)
  depend on its answers.
- Keep the denylist and address book under change control; they directly influence
  verdicts.

## Supported versions

Only the latest release receives fixes.
