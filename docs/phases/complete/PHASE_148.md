# Phase 148: Repository Brand & Path Alignment

> **Status:** IN_PROGRESS
> **Size:** SMALL
> **Depends on:** Phase 147
> **Owner:** Gemini CLI

## Goal
Align all repository references, Go module paths, and documentation URLs with the new GitHub organization and repository name: `github.com/seanpor/JA4proxy`.

## Scope
- **Go Module**: Update `go.mod` and all internal imports.
- **Docker Metadata**: Update `LABEL` and source URLs in Dockerfiles.
- **Documentation**: Update all URLs and clone instructions in `.md` files.
- **CI/CD**: Update workflow references if any.

## Actions Taken
- [ ] Global search and replace of `github.com/seanpor/ja4proxy` -> `github.com/seanpor/ja4proxy`.
- [ ] Global search and replace of `github.com/seanpor/JA4proxy` -> `github.com/seanpor/JA4proxy`.
- [ ] Verify build and test suite passes with the new module path.
