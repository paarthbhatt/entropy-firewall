# Entropy attack-corpus v2 expansion gaps

## Scope and label semantics

- Corpus: `data/attack-corpus-v2.jsonl`; SHA-256: `1f47cc69d02960e76b54e4968f81d89bad13eeecfdca5416b455764c88918e46`.
- **10,800 cases**: 7,200 attack variants and 3,600 benign near-neighbor controls.
- **24 active patterns** in `entropy/core/pattern_matcher.py`; the work order's 47-pattern count does not match this checkout. All active patterns are expanded.
- Labels express intended security behavior. Encodings and translations preserve intent; they are never relabeled according to observed detection.
- Real `ChatCompletionRequest` objects go through `EntropyEngine.analyze_request()` unchanged. No payload is copied into a scanned field to help detection.
- `detected` means at least one engine threat, even if status is allowed/sanitized. Blocking and target-rule hits are separate diagnostics. Generic encoding threats count toward recall but also count as false positives on benign encoded controls.
- Profile: recursive decoding on (depth 5), indirect scanning on, threshold 0.7, block-on-detection on; semantic/context analysis and URL fetching off. Only settings providers are isolated, not detector implementations. No model/provider/network is used.
- Image alt text is stored under `image_url.alt` (an application extension accepted by the request schema); no OCR/pixel inference is claimed. Function arguments use `assistant.tool_calls[].function.arguments`.
- Family PASS/FAIL is recall >=80%/<80%. Pytest xfails represent individually recorded known false positives/negatives, not passing detections.

## Overall benchmark

| Metric | Result |
|---|---:|
| Label matches | 5,925/10,800 |
| Label mismatches | 4,875 |
| Positive recall | 56.0% (4032/7200) |
| False-positive rate | 47.4% (1707/3600) |
| Engine target-rule hit rate | 32.9% |
| Isolated raw / decoded target hits | 42.1% / 54.8% |
| Blocked attacks | 3082 |
| Invalid input cases | 0 |

## Pass/fail by family

| Status | Family | Attacks | TP | FN | Recall | Controls | TN | FP |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| FAIL | `code_injection` | 900 | 540 | 360 | 60.0% | 450 | 183 | 267 |
| FAIL | `constraint_manipulation` | 600 | 324 | 276 | 54.0% | 300 | 144 | 156 |
| FAIL | `data_exfiltration` | 900 | 468 | 432 | 52.0% | 450 | 249 | 201 |
| FAIL | `direct_injection` | 1500 | 810 | 690 | 54.0% | 750 | 450 | 300 |
| FAIL | `file_system` | 300 | 180 | 120 | 60.0% | 150 | 60 | 90 |
| FAIL | `jailbreak` | 1200 | 666 | 534 | 55.5% | 600 | 285 | 315 |
| FAIL | `obfuscation` | 1200 | 720 | 480 | 60.0% | 600 | 345 | 255 |
| FAIL | `resource_abuse` | 600 | 324 | 276 | 54.0% | 300 | 177 | 123 |

## Per-pattern diagnostics

| Status | Pattern | Recall | FN | FP | Engine target | Raw target | Decoded target |
|---|---|---:|---:|---:|---:|---:|---:|
| FAIL | `act_as` | 54.0% | 138 | 54 | 36.0% | 36.7% | 60.0% |
| FAIL | `base64_payload` | 60.0% | 120 | 90 | 0.0% | 60.0% | 0.0% |
| FAIL | `boundary_test` | 54.0% | 138 | 78 | 36.0% | 36.7% | 60.0% |
| FAIL | `char_split_evasion` | 60.0% | 120 | 75 | 54.0% | 70.0% | 90.0% |
| FAIL | `credential_request` | 48.0% | 156 | 45 | 18.0% | 18.3% | 30.0% |
| FAIL | `dan_attack` | 60.0% | 120 | 78 | 47.0% | 48.3% | 78.3% |
| FAIL | `developer_mode` | 54.0% | 138 | 78 | 36.0% | 36.7% | 60.0% |
| FAIL | `exec_call` | 60.0% | 120 | 90 | 0.0% | 50.0% | 0.0% |
| FAIL | `hypothetical_bypass` | 54.0% | 138 | 78 | 36.0% | 36.7% | 60.0% |
| FAIL | `ignore_instructions` | 54.0% | 138 | 45 | 36.0% | 36.7% | 60.0% |
| FAIL | `infinite_loop_prompt` | 54.0% | 138 | 78 | 36.0% | 36.7% | 60.0% |
| FAIL | `leetspeak_bypass` | 60.0% | 120 | 45 | 0.0% | 50.0% | 0.0% |
| FAIL | `new_instructions` | 54.0% | 138 | 78 | 36.0% | 36.7% | 60.0% |
| FAIL | `no_restrictions` | 54.0% | 138 | 81 | 37.0% | 38.3% | 61.7% |
| FAIL | `opposite_day` | 54.0% | 138 | 78 | 36.0% | 36.7% | 60.0% |
| FAIL | `path_traversal` | 60.0% | 120 | 90 | 48.0% | 50.0% | 80.0% |
| FAIL | `pii_request` | 54.0% | 138 | 78 | 36.0% | 36.7% | 60.0% |
| FAIL | `safety_disable` | 54.0% | 138 | 78 | 36.0% | 36.7% | 60.0% |
| FAIL | `sql_injection` | 60.0% | 120 | 87 | 46.0% | 46.7% | 76.7% |
| FAIL | `system_prompt_extract` | 54.0% | 138 | 45 | 36.0% | 36.7% | 60.0% |
| FAIL | `template_injection` | 60.0% | 120 | 90 | 48.0% | 50.0% | 80.0% |
| FAIL | `token_waste` | 54.0% | 138 | 45 | 18.0% | 36.7% | 30.0% |
| FAIL | `training_data_extract` | 54.0% | 138 | 78 | 37.0% | 38.3% | 61.7% |
| FAIL | `unicode_tricks` | 60.0% | 120 | 45 | 40.0% | 50.0% | 66.7% |

## By encoding

| Value | Attacks | Recall | FN | Controls | FP |
|---|---:|---:|---:|---:|---:|
| `base64` | 1200 | 60.0% | 480 | 600 | 360 |
| `hex_escape` | 1200 | 60.0% | 480 | 600 | 360 |
| `mixed_case` | 1200 | 52.0% | 576 | 600 | 225 |
| `plain` | 1200 | 52.0% | 576 | 600 | 225 |
| `unicode_escape` | 1200 | 60.0% | 480 | 600 | 360 |
| `whitespace` | 1200 | 52.0% | 576 | 600 | 177 |

## By payload language

| Value | Attacks | Recall | FN | Controls | FP |
|---|---:|---:|---:|---:|---:|
| `code_block` | 1440 | 59.4% | 585 | 720 | 366 |
| `english` | 1440 | 59.4% | 585 | 720 | 366 |
| `hindi` | 1440 | 41.2% | 846 | 720 | 267 |
| `json_smuggling` | 1440 | 60.0% | 576 | 720 | 333 |
| `xml_smuggling` | 1440 | 60.0% | 576 | 720 | 375 |

## By instruction position

| Value | Attacks | Recall | FN | Controls | FP |
|---|---:|---:|---:|---:|---:|
| `function_args` | 1440 | 0.0% | 1440 | 720 | 0 |
| `image_alt_text` | 1440 | 0.0% | 1440 | 720 | 0 |
| `system` | 1440 | 93.3% | 96 | 720 | 569 |
| `tool_result` | 1440 | 93.3% | 96 | 720 | 569 |
| `user` | 1440 | 93.3% | 96 | 720 | 569 |

## By difficulty tier

| Value | Attacks | Recall | FN | Controls | FP |
|---|---:|---:|---:|---:|---:|
| `obfuscated` | 768 | 75.3% | 190 | 384 | 200 |
| `obvious` | 96 | 97.9% | 2 | 48 | 34 |
| `stealth` | 6336 | 53.0% | 2976 | 3168 | 1473 |

## Cross-family root causes and proposed deltas

1. **Request-field coverage:** extend bounded extraction to image alt text and function argument string values while retaining source/trust metadata. Currently the engine, validator, and indirect detector only extract strings and multipart `type=text` items; `image_url.alt` and assistant tool-call arguments are not inspected. Validate these surfaces with attack and benign controls before enabling them. Evidence: `entropy/core/engine.py:368-378`, `entropy/core/indirect_injection_detector.py:300-334`, `entropy/core/input_validator.py:101-111`.
2. **Unicode escapes:** add bounded `\uXXXX`/`\UXXXXXXXX` decoding (including valid surrogate pairs) and scan each view. NFKC does not decode literal escape strings. Evidence: decoder pipeline at `entropy/core/input_sanitizer.py:139-195`.
3. **Destructive normalization:** keep raw + decoded views; constrain leetspeak rewriting to suspect tokens. Current global substitutions erase execution-call punctuation and large numeric quantities before matching. Evidence: `entropy/core/input_sanitizer.py:56-73,273-281` and sanitizer-before-match order at `entropy/core/engine.py:218-249`.
4. **Language and false positives:** add genuine Hindi intent equivalents with tests for quoted/educational content. Generic decoding alone should not imply maliciousness.

These are proposals only; this work order makes no production-rule or extraction changes.

### `code_injection` — 60.0% recall

- Missed attacks by position: {'function_args': 180, 'image_alt_text': 180}.
- Missed attacks by encoding: {'base64': 60, 'hex_escape': 60, 'mixed_case': 60, 'plain': 60, 'unicode_escape': 60, 'whitespace': 60}.
- Family delta: Keep raw and normalized code views; support escaped code/template/SQL syntax without mutating punctuation, and distinguish execution demands from quoted educational examples.
- `exec_call` delta: Preserve the original payload scan alongside decoded views. The leetspeak decoder rewrites `(` to `c`, removing the call syntax that the execution regex requires. Normalize only attack-word tokens rather than arbitrary code punctuation.
- `sql_injection` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- `template_injection` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- Representative misses (see case IDs in the corpus/results artifact):
  - `exec_call:primary:plain:english:image_alt_text`
  - `exec_call:primary:plain:english:function_args`
  - `exec_call:primary:plain:hindi:image_alt_text`

### `constraint_manipulation` — 54.0% recall

- Missed attacks by position: {'function_args': 120, 'image_alt_text': 120, 'system': 12, 'tool_result': 12, 'user': 12}.
- Missed attacks by encoding: {'base64': 40, 'hex_escape': 40, 'mixed_case': 52, 'plain': 52, 'unicode_escape': 40, 'whitespace': 52}.
- Family delta: Add Hindi safety-disable and capability-probing phrases with negation/context handling so warnings against disabling safety are not themselves treated as attacks.
- `boundary_test` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- `safety_disable` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- Representative misses (see case IDs in the corpus/results artifact):
  - `safety_disable:primary:plain:english:image_alt_text`
  - `safety_disable:primary:plain:english:function_args`
  - `safety_disable:primary:plain:hindi:system`

### `data_exfiltration` — 52.0% recall

- Missed attacks by position: {'function_args': 180, 'image_alt_text': 180, 'system': 24, 'tool_result': 24, 'user': 24}.
- Missed attacks by encoding: {'base64': 60, 'hex_escape': 60, 'mixed_case': 84, 'plain': 84, 'unicode_escape': 60, 'whitespace': 84}.
- Family delta: Match requests for nonpublic data in Hindi and coordinated English verb/noun variants; separate requests to redact or explain data from requests to disclose it.
- `credential_request` delta: Allow carefully bounded determiners such as `every` and coordinated request verbs before credential nouns; add Hindi equivalents for passwords and private access keys.
- `pii_request` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- `training_data_extract` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- Representative misses (see case IDs in the corpus/results artifact):
  - `credential_request:primary:plain:english:image_alt_text`
  - `credential_request:primary:plain:english:function_args`
  - `credential_request:primary:plain:hindi:system`

### `direct_injection` — 54.0% recall

- Missed attacks by position: {'function_args': 300, 'image_alt_text': 300, 'system': 30, 'tool_result': 30, 'user': 30}.
- Missed attacks by encoding: {'base64': 100, 'hex_escape': 100, 'mixed_case': 130, 'plain': 130, 'unicode_escape': 100, 'whitespace': 130}.
- Family delta: Add Hindi instruction-discarding, replacement-authority, and hidden-instruction extraction phrases. Require an attempted authority/action change to distinguish benign roles/modes.
- `act_as` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- `developer_mode` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- `ignore_instructions` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- `new_instructions` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- `system_prompt_extract` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- Representative misses (see case IDs in the corpus/results artifact):
  - `ignore_instructions:primary:plain:english:image_alt_text`
  - `ignore_instructions:primary:plain:english:function_args`
  - `ignore_instructions:primary:plain:hindi:system`

### `file_system` — 60.0% recall

- Missed attacks by position: {'function_args': 60, 'image_alt_text': 60}.
- Missed attacks by encoding: {'base64': 20, 'hex_escape': 20, 'mixed_case': 20, 'plain': 20, 'unicode_escape': 20, 'whitespace': 20}.
- Family delta: Decode escaped paths in bounded secondary views, normalize traversal separators, and require access/disclosure intent rather than flagging cautions about sensitive paths.
- `path_traversal` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- Representative misses (see case IDs in the corpus/results artifact):
  - `path_traversal:primary:plain:english:image_alt_text`
  - `path_traversal:primary:plain:english:function_args`
  - `path_traversal:primary:plain:hindi:image_alt_text`

### `jailbreak` — 55.5% recall

- Missed attacks by position: {'function_args': 240, 'image_alt_text': 240, 'system': 18, 'tool_result': 18, 'user': 18}.
- Missed attacks by encoding: {'base64': 80, 'hex_escape': 80, 'mixed_case': 98, 'plain': 98, 'unicode_escape': 80, 'whitespace': 98}.
- Family delta: Add Hindi restriction-negation and hypothetical-bypass phrases, and correlate persona names with an instruction to bypass policy rather than matching names like `Dan` alone.
- `dan_attack` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- `hypothetical_bypass` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- `no_restrictions` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- `opposite_day` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- Representative misses (see case IDs in the corpus/results artifact):
  - `dan_attack:primary:plain:english:image_alt_text`
  - `dan_attack:primary:plain:english:function_args`
  - `dan_attack:primary:plain:hindi:image_alt_text`

### `obfuscation` — 60.0% recall

- Missed attacks by position: {'function_args': 240, 'image_alt_text': 240}.
- Missed attacks by encoding: {'base64': 80, 'hex_escape': 80, 'mixed_case': 80, 'plain': 80, 'unicode_escape': 80, 'whitespace': 80}.
- Family delta: Decode `\uXXXX`/hex escapes with bounded depth and preserve provenance of encoded blocks, invisible characters, leetspeak, and split words; require malicious decoded intent for benign encoded controls.
- `base64_payload` delta: Record encoded-block provenance and scan both original and decoded views: successful decoding consumes the marker regex's target. Do not treat benign encoded greetings as attacks solely because they decode.
- `char_split_evasion` delta: Use token boundaries/context for split-letter attack words and retain original-view provenance; the current regex also matches normal unsplit `system`/`prompt` text.
- `leetspeak_bypass` delta: Scan the original leetspeak marker as well as the normalized instruction; limit digit substitution to suspicious words so ordinary numbers and code are preserved.
- `unicode_tricks` delta: Decode literal Unicode escapes and build a second view with zero-width separators removed. Correlate markers with hidden instruction intent rather than legitimate script joiners.
- Representative misses (see case IDs in the corpus/results artifact):
  - `base64_payload:primary:plain:english:image_alt_text`
  - `base64_payload:primary:plain:english:function_args`
  - `base64_payload:primary:plain:hindi:image_alt_text`

### `resource_abuse` — 54.0% recall

- Missed attacks by position: {'function_args': 120, 'image_alt_text': 120, 'system': 12, 'tool_result': 12, 'user': 12}.
- Missed attacks by encoding: {'base64': 40, 'hex_escape': 40, 'mixed_case': 52, 'plain': 52, 'unicode_escape': 40, 'whitespace': 52}.
- Family delta: Normalize numeric quantities and Hindi number words in a non-leetspeak view; identify unbounded generation intent and separate educational explanations of loops from demands.
- `infinite_loop_prompt` delta: Add Hindi intent equivalents and escaped/structured secondary views for this rule, plus tests that retain benign-context distinctions.
- `token_waste` delta: Retain numeric quantities before leetspeak normalization (`10000` is currently rewritten), recognize million-word/character Hindi quantities, and distinguish budgets from demands.
- Representative misses (see case IDs in the corpus/results artifact):
  - `infinite_loop_prompt:primary:plain:english:image_alt_text`
  - `infinite_loop_prompt:primary:plain:english:function_args`
  - `infinite_loop_prompt:primary:plain:hindi:system`

## Test-suite evidence

Full captured output: `test-run.txt`.

```text
================ 6062 passed, 4875 xfailed in 115.23s (0:01:55) ================
```
