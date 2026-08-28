# Security policy

## Reporting a vulnerability

Report privately by email to mail@olemeyer.com, or through GitHub's private
vulnerability reporting on this repository. Please do not open a public issue for anything
that could expose someone's memories.

Include what you did, what happened, and what you expected. A proof of concept is welcome but
not required.

## Scope

In scope: anything that lets an unauthorised party read stored content or file names, that
loses data during synchronisation, or that leaks the private key.

Out of scope: attacks that assume an already-compromised machine, and the residual risks
documented and accepted in [docs/threat-model.md](docs/threat-model.md).

## Supported versions

The latest release on `main`.
