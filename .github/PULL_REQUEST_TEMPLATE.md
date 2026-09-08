<!--
Before opening a PR, please read CONTRIBUTING.md.
- New features need TDD: failing test first, then minimal implementation.
- core/security.py and core/audit.py must keep >=90% coverage.
-->

## Summary

What does this PR change and why? Link the related issue.

## Checklist

- [ ] Tests added/updated (TDD order followed)
- [ ] `pytest` passes locally with coverage >= 85% overall
- [ ] `ruff check` and `ruff format --check` pass
- [ ] New tools go through `core/security.py` validation and audit logging
- [ ] Subprocess calls use `shell=False` with list-built commands
- [ ] Docs updated (README / design docs) if behavior changed
