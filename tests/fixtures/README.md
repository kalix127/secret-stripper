# Corpus fixtures

Each `corpus/<bucket>.txt` drives the detection and redaction round-trip tests
in `tests/corpus.rs`. `corpus/negatives.txt` drives the zero-false-positive
test. All values are synthetic, structurally valid but non-functional
placeholders; none are live credentials.

## Grammar

A fixture is a sequence of sections. Lines are interpreted as:

- `# === <Section name> ===` starts a new section.
- `# expect: <Pattern name>` declares that the named `SecretPattern` (or
  deep-scan `finding_type`) must fire somewhere in this section's body. Repeat
  the line once per expected pattern. Names must match the Rust `name:` field
  byte for byte.
- `# expect: (none)` documents that a section is expected to produce no
  detections (the harness treats a section with no `# expect:` the same way).
- Any other `#` line is a comment and is ignored.
- Every remaining line is section body: the text that gets scanned.

## What each test asserts

- `corpus_<bucket>_detects_all`: every `# expect:` pattern in every section
  actually fires.
- `corpus_<bucket>_redaction_round_trip_clean`: after redacting a section the
  way the trigger flow does, re-scanning yields no pattern matches and no deep
  findings. High-entropy-only tokens are intentionally not asserted here: a
  high-entropy substring can legitimately survive inside redacted prose.
- `corpus_negatives_zero_detections`: every section in `negatives.txt`
  produces zero pattern matches and zero deep findings.

## Example

```
# === Cloud / AWS ===
# expect: AWS STS Temporary Access Key
Here is a token ASIAIOSFODNN7EXAMPLE embedded in a sentence.
```
