# Cryptographic QA Test Execution Template

This template is derived from the 100-item best-practice checklist in `SECURITY_ANALYSIS.md` (Appendix: 100 Crypto Testing Best-Practice Checks Applied). Use it as the standard record for every cryptographic QA cycle.

## How to use this template
1. **Reference checklist numbers.** Each row should map to one of the 100 checks already documented in `SECURITY_ANALYSIS.md` so findings stay aligned to the canonical list.
2. **Pick a clear outcome.** Use one of: `Pass`, `Attention`, `Fail`, or `N/A` (not applicable for this code path or release).
3. **Cite evidence.** Add code pointers (file path + line) or test artifacts that justify the outcome.
4. **Log remediations.** If the outcome is `Attention` or `Fail`, note the fix owner and ETA.
5. **Reuse per release.** Copy this template into a dated test record (e.g., `qa/runs/2025-02-10.md`) before executing a new round of tests.

## Test run metadata
- **Release / commit:** `<git sha or tag>`
- **Date:** `<YYYY-MM-DD>`
- **Tester:** `<name>`
- **Scope:** `<components / features under test>`

## Outcomes table
Fill one line per checklist item. Add more rows if you split a check into sub-cases.

| # | Outcome | Evidence | Notes / Remediation |
|---|:--------:|---------|---------------------|
| 1 | Pass / Attention / Fail / N/A | `path/to/file.rs:Lxx-Lyy`, test log, or spec reference | Short rationale & owner |
| 2 |  |  |  |
| 3 |  |  |  |
| 4 |  |  |  |
| 5 |  |  |  |
| 6 |  |  |  |
| 7 |  |  |  |
| 8 |  |  |  |
| 9 |  |  |  |
| 10 |  |  |  |
| 11 |  |  |  |
| 12 |  |  |  |
| 13 |  |  |  |
| 14 |  |  |  |
| 15 |  |  |  |
| 16 |  |  |  |
| 17 |  |  |  |
| 18 |  |  |  |
| 19 |  |  |  |
| 20 |  |  |  |
| 21 |  |  |  |
| 22 |  |  |  |
| 23 |  |  |  |
| 24 |  |  |  |
| 25 |  |  |  |
| 26 |  |  |  |
| 27 |  |  |  |
| 28 |  |  |  |
| 29 |  |  |  |
| 30 |  |  |  |
| 31 |  |  |  |
| 32 |  |  |  |
| 33 |  |  |  |
| 34 |  |  |  |
| 35 |  |  |  |
| 36 |  |  |  |
| 37 |  |  |  |
| 38 |  |  |  |
| 39 |  |  |  |
| 40 |  |  |  |
| 41 |  |  |  |
| 42 |  |  |  |
| 43 |  |  |  |
| 44 |  |  |  |
| 45 |  |  |  |
| 46 |  |  |  |
| 47 |  |  |  |
| 48 |  |  |  |
| 49 |  |  |  |
| 50 |  |  |  |
| 51 |  |  |  |
| 52 |  |  |  |
| 53 |  |  |  |
| 54 |  |  |  |
| 55 |  |  |  |
| 56 |  |  |  |
| 57 |  |  |  |
| 58 |  |  |  |
| 59 |  |  |  |
| 60 |  |  |  |
| 61 |  |  |  |
| 62 |  |  |  |
| 63 |  |  |  |
| 64 |  |  |  |
| 65 |  |  |  |
| 66 |  |  |  |
| 67 |  |  |  |
| 68 |  |  |  |
| 69 |  |  |  |
| 70 |  |  |  |
| 71 |  |  |  |
| 72 |  |  |  |
| 73 |  |  |  |
| 74 |  |  |  |
| 75 |  |  |  |
| 76 |  |  |  |
| 77 |  |  |  |
| 78 |  |  |  |
| 79 |  |  |  |
| 80 |  |  |  |
| 81 |  |  |  |
| 82 |  |  |  |
| 83 |  |  |  |
| 84 |  |  |  |
| 85 |  |  |  |
| 86 |  |  |  |
| 87 |  |  |  |
| 88 |  |  |  |
| 89 |  |  |  |
| 90 |  |  |  |
| 91 |  |  |  |
| 92 |  |  |  |
| 93 |  |  |  |
| 94 |  |  |  |
| 95 |  |  |  |
| 96 |  |  |  |
| 97 |  |  |  |
| 98 |  |  |  |
| 99 |  |  |  |
| 100 |  |  |  |

## Sign-off
- **Reviewer:** `<name>`
- **Date:** `<YYYY-MM-DD>`
- **Approval:** `<Approved / Blocked>`
