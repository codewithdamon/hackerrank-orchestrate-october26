# Ghost Data Still Exists — offline audit solution

This repository contains a deterministic local auditor for the HackerRank Orchestrate October 2026 challenge. It reads only participant-facing files under `dataset/`, resolves current and historical identities, parses the supplied evidence, applies `deletion_rules.csv`, and writes the submission file at the repository root.

## Requirements

- Node.js 18 or later (no npm packages, network access, credentials, or model API required).
- Optional: Python 3 if you prefer the convenience launcher `python code/main.py`; that launcher delegates to Node.js.

## Generate and validate `output.csv`

Run from the repository root:

```text
node code/main.js
```

The command processes all requests, writes root-level `output.csv`, and validates the written file's header, row count, uniqueness, ordering, JSON arrays, step fields, step numbers, enums, phase order, operation order, and evidence references.

The implementation does not use `sample_output.csv` to produce predictions. It reads that file only in the public evaluator described below.

## Evaluate on the public samples

Run:

```text
node code/evaluation/main.js
```

This compares the algorithm's sample-case results with `dataset/sample_output.csv` and prints status accuracy, step/field comparisons, sequence accuracy, status mismatches, and participant-created intent/identity checks. Sample results are diagnostic only; they do not alter the generated full-dataset predictions.

## Implementation notes and limits

- CSV parsing supports quoted fields; JSON, SQL `INSERT` snapshots, key/value and JSON logs, pipe-delimited handover records, TXT, and basic extractable PDF text are indexed. Evidence capture time and embedded event/update time are checked against each case's `audit_at`.
- Evidence is connected through exact user IDs and normalized current/historical identifiers. Resource IDs are matched exactly. Activity rows can help link a resource to an identity, but activity results are not used as proof of record state.
- PDF text extraction uses a lightweight built-in parser. On Windows, screenshots are also read using the built-in Windows OCR engine; on other platforms, image text metadata is the available fallback, so visual-only evidence may be missed there.
- The latest validated full-dataset run produced 123 `COMPLETE`, 359 `INCOMPLETE`, and 36 `NOT_APPLICABLE` rows. One `COMPLETE` row has no evidence-backed verification step. See `code/evaluation/evaluation_report.md` for current metrics and the evidence audit.
- The challenge's hidden canonical answers are not included or used. Public sample performance is documented in `code/evaluation/evaluation_report.md`.

## Submission package

Create `code.zip` from the repository root. These commands stage only the runnable code, README, and required reports; they place the reports at the required ZIP paths and exclude `dataset/`, `output.csv`, and `log.txt`:

```powershell
$stage = Join-Path $env:TEMP ("ghost-data-package-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path (Join-Path $stage "code\evaluation"), (Join-Path $stage "evaluation") -Force | Out-Null
Copy-Item README.md (Join-Path $stage "README.md")
Copy-Item code\main.js, code\main.py (Join-Path $stage "code")
Copy-Item code\evaluation\main.js, code\evaluation\main.py (Join-Path $stage "code\evaluation")
Copy-Item code\evaluation\evaluation_report.md, code\evaluation\usage_report.md (Join-Path $stage "evaluation")
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath (Join-Path (Get-Location) "code.zip") -Force
```

The three separate submission artifacts are root-level `code.zip`, root-level `output.csv`, and root-level `log.txt` as the chat transcript. The challenge's AI interview is a separate submission component. No dataset, credentials, virtual environments, dependencies, or generated caches belong in the ZIP.
