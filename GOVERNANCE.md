# Project Governance

This document outlines the governance model for the JA4proxy project.

## Project Vision

JA4proxy aims to be the standard for TLS-aware, high-performance, passthrough security proxies, providing enterprise-grade protection without decryption.

## Maintainers

The project is currently led by its primary maintainers. Maintainers have the following responsibilities:

- Reviewing and merging pull requests.
- Defining the project roadmap and strategic direction.
- Managing security releases and vulnerability disclosures.
- Ensuring compliance with OpenSSF Best Practices.

## Contribution Process

We welcome contributions from the community! Please follow these steps:

1. **Check the Roadmap**: See `docs/phases/TODO.md` for planned features and tasks.
2. **Open an Issue**: For bug reports or feature requests, open a GitHub issue.
3. **Draft a Phase**: Large changes should be documented as a new Phase in `docs/phases/`.
4. **Submit a Pull Request**: Ensure all tests pass (`make test-go test-unit`) and code follows the `docs/developer/STYLE_GUIDE.md`.

## Decision Making

Decisions are made based on technical merit and alignment with the core asymmetry principle (Decision before Decryption). We strive for consensus among maintainers for significant architectural changes.

## Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

## Transparency

Technical decisions and architectural designs are recorded as Architecture Decision Records (ADRs) in `docs/decisions/`.\n