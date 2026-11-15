# Results

Ground truth: 10 entries. Match rule: same file, lines within ±5, same CWE family.

| Configuration | Findings | TP findings | Truth found | Precision | Recall | Total cost | Cost / TP | Seconds / file |
|---|---|---|---|---|---|---|---|---|
| semgrep | 4 | 4 | 3/10 | 1.00 | 0.30 | n/a | n/a | 0.35 |

Not run (no findings file): llm, hybrid.

## Truth coverage

| ID | File | Lines | CWE | semgrep |
|---|---|---|---|---|
| T01 | routes/login.ts | 34-34 | CWE-89 | yes |
| T02 | routes/search.ts | 23-23 | CWE-89 | yes |
| T03 | routes/updateProductReviews.ts | 18-20 | CWE-943 | no |
| T04 | routes/trackOrder.ts | 15-18 | CWE-943 | no |
| T05 | routes/showProductReviews.ts | 31-36 | CWE-943 | no |
| T06 | routes/b2bOrder.ts | 19-23 | CWE-94 | no |
| T07 | routes/userProfile.ts | 58-65 | CWE-95 | yes |
| T08 | routes/profileImageUrlUpload.ts | 19-24 | CWE-918 | no |
| T09 | routes/fileUpload.ts | 29-34 | CWE-22 | no |
| T10 | routes/basket.ts | 18-19 | CWE-639 | no |

## semgrep

- Found only by this configuration: T01, T02, T07

True positives:
- T01: routes/login.ts:34-34 CWE-89
- T02: routes/search.ts:23-23 CWE-89
- T07: routes/userProfile.ts:65-65 CWE-95
- T07: routes/userProfile.ts:65-65 CWE-95

False positives (unmatched findings; some are real issues outside the 10 truth entries):
- none
