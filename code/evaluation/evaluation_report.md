# Evaluation report

## Public sample evaluation

Run with `node code/evaluation/main.js`. The prediction pipeline reads only participant-facing inputs. `dataset/sample_output.csv` is loaded by this evaluator solely as the public comparison target and is never consulted to generate predictions.

| Metric | Current validated run |
|---|---:|
| Public status accuracy | 32 / 32 (100%) |
| Exact full-sequence accuracy | 7 / 32 (21.88%) |
| Position-aligned exact-step precision | 65.19% (103 / 158) |
| Position-aligned exact-step recall | 53.37% (103 / 193) |
| Position-aligned field accuracy | 70.91% (958 / 1,351) |

Field accuracy counts each of the seven required fields at the same array position and treats missing positions as incorrect. Exact-step precision/recall also require all seven fields to match at the same position. These are sequence-sensitive measures. No public status or custom-check regression occurred.

## Participant-created checks

The final evaluator runs 11 independent checks covering access/non-deletion intent, Spanish deletion intent, several explicit negative-intent forms, historical email identity resolution, and rejection of partial email matches. All 11 passed.

## Final targeted step-generation pass

Public step differences grouped into missing checks for absent accounts and retained audit records, missing anonymization checks, and a small number of policy classification errors. The main underlying issues and justified fixes were:

- Event rows in multi-system logs inherited a broad filename category. Event/service-aware categorization now recognizes legacy contact-index rows as deletable secondary identifiers and maps replica subsystem names to their canonical service IDs.
- `IDENTIFIABLE` results now count as evidence that identifiers remain exposed for REDACT/ANONYMIZE actions. Completed reads with positive row counts establish presence, and explicit 404 `status_code` establishes absence.
- Analytics contact lookup records that carry an email opt-in field use the marketing-profile DELETE rule. Analytics/telemetry records with a resource ID and all supplied identity fields explicitly null are recognized as anonymized.
- A prohibited downstream record with an explicit `source_resource_id` gets a future source-absence check. An absence lookup from before the deletion request is not treated as current post-request proof.
- Existing phase ordering and operation priorities already placed supported findings, disable/block actions, record operations, and checks in the required sequence; no case-specific ordering exception was needed.

No case IDs, expected labels, or sample-output lookup rules were added to the prediction code. `sample_output.csv` remained evaluator-only. No dataset files changed.

## Full-dataset validation

`node code/main.js` generated 518 sorted unique rows: 123 `COMPLETE`, 359 `INCOMPLETE`, and 36 `NOT_APPLICABLE`. The output validator checked the exact header, count, case uniqueness/order, valid JSON arrays, required step fields, consecutive numbering, allowed enums, phase and operation ordering, and evidence references. No dataset files were modified.

## Remaining risks and hidden-set expectations

The hidden canonical answers were unavailable and were not used. Public sample scores do not predict hidden-set accuracy. One row is currently `COMPLETE` without an evidence-backed verification step.

- `case_39` is classified `INCOMPLETE`: Windows OCR reads the timely connector screenshot, which establishes an active data flow linked to the request identity; the generated steps propose disabling and verifying that flow.
- `case_416` remains `COMPLETE` with no verification steps under the current status rule. Timely logs show profile, audit, index, and connector queries starting, but provide no outcomes or record states. This is an evidence limitation and a remaining risk.
- `case_55` is classified `COMPLETE` with a verification step for the retained archive. Windows OCR identifies the archive record; the screenshot does not show per-archive restore permission, so the restore-state evidence is limited.

Some public verification steps cannot be grounded in participant-facing evidence available by `audit_at`; later snapshots are excluded. Unsupported steps were not fabricated or inferred from workflow activity. The output is structurally valid and public status accuracy is 32/32, while the evidence limitations remain relevant to hidden-set performance.
