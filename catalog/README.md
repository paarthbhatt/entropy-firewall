# Entropy attack catalog

This directory documents the active prompt-injection catalog and the generated
evaluation expansion. The production source of truth is
`entropy/core/pattern_matcher.py`, specifically `PatternMatcher._RAW_PATTERNS`.
The generator reads that table with Python's AST parser without importing the
runtime application. New production IDs require reviewed English/Hindi attack
and benign seeds; generation fails explicitly if metadata is missing.

## Catalog inventory

The checkout used for this expansion contains **24 active named patterns in 8
families**. The work order describes a 47-pattern catalog, but no 47-pattern
definition exists in this repository state; the table below is the complete
active inventory discovered from the production source. No production rules
were invented or changed to close that count gap.

| Pattern ID | Name | Injection category | Detection heuristic used |
|---|---|---|---|
| `ignore_instructions` | Ignore previous instructions | `direct_injection` | Instruction-discarding verbs (`ignore`, `disregard`, `forget`, `override`) followed by instruction/command/prompt/rule nouns. |
| `new_instructions` | New instructions | `direct_injection` | Claims of `new`, `actual`, `real`, `true`, or `updated` instructions or directives. |
| `act_as` | Act as | `direct_injection` | Role reassignment such as “you are now”, “pretend”, or “assume the role”. The `act as` branch currently requires extra whitespace after its own trailing whitespace token. |
| `system_prompt_extract` | System prompt extraction | `direct_injection` | Requests to reveal, show, display, print, output, repeat, or tell hidden/system instructions. |
| `developer_mode` | Developer mode | `direct_injection` | Privileged mode names (`developer`, `dev`, `debug`, `admin`, `root`, `sudo`, `superuser`, `maintenance`) followed by `mode`. |
| `dan_attack` | DAN jailbreak | `jailbreak` | Known jailbreak persona names, including `DAN`, `Do Anything Now`, `STAN`, `DUDE`, `AIM`, `KEVIN`, `UCAR`, `Maximum`, and `JAILBREAK`. |
| `no_restrictions` | No restrictions | `jailbreak` | Requests for unrestricted, unfiltered, uncensored, or boundary-free operation. |
| `hypothetical_bypass` | Hypothetical bypass | `jailbreak` | Hypothetical, fictional, imaginary, or theoretical framing followed by a bypass premise. |
| `opposite_day` | Opposite-day mode | `jailbreak` | Named inversion modes such as opposite day, bizarro, evil, villain, or chaos mode. |
| `credential_request` | Credential request | `data_exfiltration` | Request verbs followed by passwords, credentials, secrets, API keys, tokens, or private keys. |
| `training_data_extract` | Training-data extraction | `data_exfiltration` | Training-data, memorization, learned-content, or exact-text extraction language. |
| `pii_request` | PII request | `data_exfiltration` | Social-security, credit-card, bank-account, home-address, phone, or birth-detail requests. |
| `exec_call` | Execution call | `code_injection` | `exec`, `eval`, `compile`, `__import__`, subprocess, OS process, or destructive filesystem calls followed by `(`. |
| `template_injection` | Template injection | `code_injection` | Double-curly, `${...}`, or `<%...%>` template expressions. |
| `sql_injection` | SQL injection | `code_injection` | SQL verbs paired with `FROM`, `INTO`, `TABLE`, `SET`, `UNION SELECT`, or destructive statements. |
| `base64_payload` | Base64 payload | `obfuscation` | `base64`, `b64`, `decode`, or `encode` markers followed by a long base64-looking block. |
| `unicode_tricks` | Unicode tricks | `obfuscation` | Zero-width, word-joiner, BOM, and related invisible Unicode characters. |
| `leetspeak_bypass` | Leetspeak bypass | `obfuscation` | Common numeric/symbol substitutions such as `1gn0r3`, `pr0mpt`, `byp4ss`, and `3xpl01t`. |
| `char_split_evasion` | Character-split evasion | `obfuscation` | Letters in `ignore`, `system`, or `prompt` separated by zero or more whitespace characters; also matches unsplit words/substrings. Dot/dash joining is a sanitizer heuristic. |
| `safety_disable` | Safety disable | `constraint_manipulation` | Disable/remove/bypass/skip/ignore verbs applied to safety, security, moderation, filters, guards, or checks. |
| `boundary_test` | Boundary test | `constraint_manipulation` | Probes for limits, boundaries, restrictions, rules, or malicious capability. |
| `infinite_loop_prompt` | Infinite-loop prompt | `resource_abuse` | Requests to repeat or generate forever, infinitely, endlessly, or until exhaustion. |
| `token_waste` | Token waste | `resource_abuse` | Very large word/character requests or attempts to fill the context window/max tokens. |
| `path_traversal` | Path traversal | `file_system` | Parent-directory traversal and sensitive Unix/Windows paths such as `/etc/passwd` or `C:\Windows`. |

## Corpus v2

`data/attack-corpus-v2.jsonl` is a deterministic JSON Lines expansion generated
by `scripts/expand_attack_catalog.py`.

### Count and distribution

| Statistic | Count |
|---|---:|
| Total cases | **10,800** |
| Expected detections (`true`) | 7,200 |
| Safe controls (`false`) | 3,600 |
| Active pattern IDs | 24 |
| Positive cases per pattern | 300 |
| Safe controls per pattern | 150 |

Each pattern uses 3 payload variants × 6 encodings × 5 payload languages × 5
instruction positions: `primary` and `contextual` attack seeds plus a
`negative_control` seed. The control cases use family-specific benign
near-neighbors, so encoding or transport alone is not labeled malicious.

#### By family

| Category | Cases |
|---|---:|
| `direct_injection` | 2,250 |
| `jailbreak` | 1,800 |
| `obfuscation` | 1,800 |
| `data_exfiltration` | 1,350 |
| `code_injection` | 1,350 |
| `constraint_manipulation` | 900 |
| `resource_abuse` | 900 |
| `file_system` | 450 |

#### By difficulty tier

| Tier | Cases | Meaning |
|---|---:|---|
| `obvious` | 144 | Plain English in a system or user position. |
| `obfuscated` | 1,152 | Mixed case, irregular whitespace, code blocks, or translated Hindi. |
| `stealth` | 9,504 | Encoded content, structured smuggling, or tool/image/function transport. |

#### By expansion dimension

| Dimension | Distribution |
|---|---|
| Encoding | `plain`, `base64`, `unicode_escape`, `hex_escape`, `mixed_case`, `whitespace`: 1,800 each |
| Payload language | `english`, `hindi`, `code_block`, `json_smuggling`, `xml_smuggling`: 2,160 each |
| Instruction position | `system`, `user`, `tool_result`, `image_alt_text`, `function_args`: 2,160 each |

### JSONL schema

Every line is an object with these fields:

| Field | Type | Description |
|---|---|---|
| `case_id` | string | Stable compound identifier for the generated case. |
| `input_payload` | string | Payload string placed in the labeled request field and scanned separately for diagnostics. |
| `payload` | string | Compatibility alias of `input_payload`. |
| `request` | object | Complete OpenAI-compatible request carrying the payload in its labeled position. |
| `pattern_id` | string | Active production pattern exercised by this case. |
| `pattern_name` | string | Human-readable pattern name. |
| `category` | string | Production pattern family. |
| `expected_detection` | boolean | Whether the engine should report a detection. |
| `label_reason` | string | Human-readable explanation for the intent label. |
| `difficulty_tier` | string | One of `obvious`, `obfuscated`, or `stealth`. |
| `encoding` | string | Encoding transformation used for the payload. |
| `payload_language` | string | English, Hindi, code block, JSON smuggling, or XML smuggling. |
| `instruction_position` | string | System, user, tool result, image alt text, or function arguments. |
| `payload_variant` | string | `primary`, `contextual`, or `negative_control`. |
| `generator` | string | Generator/version marker for reproducibility. |

### Generation and labeling policy

- IDs are stable `pattern_id:variant:encoding:language:position` keys. Generation
  has no random seed, clock, network access, or detector-derived labels.
- Hindi seeds translate the actual instruction. Code syntax, proper persona
  names, encoded blocks, and filesystem paths remain literal where they are
  the attack vector. Encodings are applied to the translated seed itself.
- `unicode_escape` renders every codepoint as a literal `\uXXXX`; `hex_escape`
  uses `\xNN` for byte-range codepoints and Unicode escapes for other characters.
  Base64 uses UTF-8, mixed case alternates ASCII letter case, and whitespace
  variants insert newlines/tabs between tokens. JSON/XML wrappers preserve the
  payload as a string value; generated code is never executed.
- Attacks are labeled `true` even when current heuristics miss them. Controls
  are labeled `false` because they ask for benign discussion, safe handling, or
  an approved task. They include benign code, public-data, path, and persona-name
  mentions to measure false positives, not just unrelated safe greetings.
- Difficulty tiers describe transport/representation, not measured detector
  performance. Tier labels are identical for attacks and controls.

### Actual request positions

| Position | Payload field |
|---|---|
| `system` | System message `content`; the caller-provided content is treated as subject to inspection. |
| `user` | User message `content`. |
| `tool_result` | Tool message `content`, with a corresponding assistant function call. |
| `image_alt_text` | User multipart `image_url.alt`; this is an application-supplied textual extension, not OCR. |
| `function_args` | Assistant `tool_calls[].function.arguments`, a JSON string with a `document` value. |

The request schema accepts multipart dictionaries and tool-call dictionaries.
The evaluator passes those fields unchanged to the engine; it does not promote
alt text or arguments into `type=text` content. The `.invalid` image URL is
never fetched. These cases intentionally expose the current extraction gaps.

### Generate and evaluate

```bash
python scripts/expand_attack_catalog.py
python scripts/evaluate_attack_corpus.py --test-output reports/test-run.txt

# Repository convention: ordinary pytest collection includes every corpus case
pytest tests/unit/test_attack_corpus.py

# Strict benchmark mode reports existing gaps as a nonzero exit status
python scripts/evaluate_attack_corpus.py --strict
```

The evaluator sends each stored request through `EntropyEngine.analyze_request`
with a deterministic offline profile. It writes raw outcomes to
`reports/attack-corpus-v2-results.json` and the family-level analysis to
[`reports/expansion-gaps.md`](../reports/expansion-gaps.md). The current run
has weak recall (<80%) in all eight families; the report separates extraction,
encoding, language, and rule misses and proposes deltas without modifying
production code. Known per-case mismatches are snapshotted in
`data/attack-corpus-v2-known-gaps.json` so the corpus tests fail on new
regressions while documenting current gaps as xfails.

The deterministic profile enables recursive decoding (depth 5) and indirect
scanning, with threshold 0.7 and blocking enabled. Semantic classification,
conversation-context analysis, and URL fetching are disabled so no optional
model, provider, or remote service affects results. `detected` means any engine
threat; it is separate from blocking or a target-pattern hit. This intentionally
exposes generic encoding false positives as well as missed malicious intent.

Known-gap snapshots are updated only by the explicit command below after review;
the generator and normal pytest runs never update them or change truth labels.
Fixed known gaps pass; a new mismatch fails.

```bash
python scripts/evaluate_attack_corpus.py \
  --snapshot-known-gaps data/attack-corpus-v2-known-gaps.json
```

Current snapshot: **4,875 known mismatches** (3,168 false negatives and 1,707
false positives). Overall recall is **56.0%**. On directly scanned system/user/
tool content recall is 93.3%, while function arguments and image alt text have
0% recall. Full raw/decoded/engine diagnostics are in the results JSON; these
are synthetic correlated variants, not an independent real-world accuracy claim.
