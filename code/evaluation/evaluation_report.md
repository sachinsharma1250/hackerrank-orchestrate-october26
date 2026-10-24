# Evaluation Report

This is a deterministic evidence-matching baseline, not a verified ground-truth solver.

- Input cases: 518
- Output rows: 518
- Status counts: `{"COMPLETE": 5, "INCOMPLETE": 507, "NOT_APPLICABLE": 6}`
- Schema/sequence errors: 0
- Custom checks: request classification; evidence cutoff; JSON schema; contiguous step numbering.

## Limitations

- Evidence association relies on literal identity aliases in readable evidence text; binary/image evidence is not OCR-processed.
- A resource-level state may require cross-system correlation or policy interpretation not captured by this baseline.
- Missing evidence is not treated as proof of deletion.
- Review false positives/negatives before submission.

## Validation Errors

- None found.
