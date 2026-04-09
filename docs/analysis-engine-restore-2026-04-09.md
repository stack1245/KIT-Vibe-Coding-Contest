# Analysis Engine Restore Guide

Backups created on 2026-04-09 before runtime-evidence classification changes:

- `docs/analysis-report.js.backup-2026-04-09.js`
- `docs/analysis-report.js.backup-pre-deep-analysis-2026-04-09.js`
- `docs/analysis-prompt.backup-2026-04-09.txt`
- `docs/analysis-prompt.backup-2026-04-09.notes.md`

## Restore `analysis-report.js`

From the repository root:

```bash
cp docs/analysis-report.js.backup-2026-04-09.js lib/server/analysis-report.js
```

## What This Restore Does

- Removes runtime-source classification heuristics
- Removes same-file runtime evidence filtering for rule-based findings
- Removes post-validation of Codex findings against runtime contexts
- Returns the analysis engine to the exact pre-change JavaScript backup above

## Recommended Verification After Restore

```bash
node --check lib/server/analysis-report.js
npm test -- --run tests/analysis-report.test.js
```
