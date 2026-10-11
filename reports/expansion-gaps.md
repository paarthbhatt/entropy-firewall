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
| Label matches | 7,475/10,800 |
| Label mismatches | 3,325 |
| Positive recall | 93.3% (6720/7200) |
| False-positive rate | 79.0% (2845/3600) |
| Engine target-rule hit rate | 54.8% |
| Isolated raw / decoded target hits | 42.1% / 54.8% |
| Blocked attacks | 5092 |
| Invalid input cases | 0 |

## Pass/fail by family

| Status | Family | Attacks | TP | FN | Recall | Controls | TN | FP |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| PASS | `code_injection` | 900 | 900 | 0 | 100.0% | 450 | 5 | 445 |
| PASS | `constraint_manipulation` | 600 | 540 | 60 | 90.0% | 300 | 40 | 260 |
| PASS | `data_exfiltration` | 900 | 780 | 120 | 86.7% | 450 | 115 | 335 |
| PASS | `direct_injection` | 1500 | 1350 | 150 | 90.0% | 750 | 250 | 500 |
| PASS | `file_system` | 300 | 300 | 0 | 100.0% | 150 | 0 | 150 |
| PASS | `jailbreak` | 1200 | 1110 | 90 | 92.5% | 600 | 75 | 525 |
| PASS | `obfuscation` | 1200 | 1200 | 0 | 100.0% | 600 | 175 | 425 |
| PASS | `resource_abuse` | 600 | 540 | 60 | 90.0% | 300 | 95 | 205 |

## Per-pattern diagnostics

| Status | Pattern | Recall | FN | FP | Engine target | Raw target | Decoded target |
|---|---|---:|---:|---:|---:|---:|---:|
| PASS | `act_as` | 90.0% | 30 | 90 | 60.0% | 36.7% | 60.0% |
| PASS | `base64_payload` | 100.0% | 0 | 150 | 0.0% | 60.0% | 0.0% |
| PASS | `boundary_test` | 90.0% | 30 | 130 | 60.0% | 36.7% | 60.0% |
| PASS | `char_split_evasion` | 100.0% | 0 | 125 | 90.0% | 70.0% | 90.0% |
| PASS | `credential_request` | 80.0% | 60 | 75 | 30.0% | 18.3% | 30.0% |
| PASS | `dan_attack` | 100.0% | 0 | 130 | 78.3% | 48.3% | 78.3% |
| PASS | `developer_mode` | 90.0% | 30 | 130 | 60.0% | 36.7% | 60.0% |
| PASS | `exec_call` | 100.0% | 0 | 150 | 0.0% | 50.0% | 0.0% |
| PASS | `hypothetical_bypass` | 90.0% | 30 | 130 | 60.0% | 36.7% | 60.0% |
| PASS | `ignore_instructions` | 90.0% | 30 | 75 | 60.0% | 36.7% | 60.0% |
| PASS | `infinite_loop_prompt` | 90.0% | 30 | 130 | 60.0% | 36.7% | 60.0% |
| PASS | `leetspeak_bypass` | 100.0% | 0 | 75 | 0.0% | 50.0% | 0.0% |
| PASS | `new_instructions` | 90.0% | 30 | 130 | 60.0% | 36.7% | 60.0% |
| PASS | `no_restrictions` | 90.0% | 30 | 135 | 61.7% | 38.3% | 61.7% |
| PASS | `opposite_day` | 90.0% | 30 | 130 | 60.0% | 36.7% | 60.0% |
| PASS | `path_traversal` | 100.0% | 0 | 150 | 80.0% | 50.0% | 80.0% |
| PASS | `pii_request` | 90.0% | 30 | 130 | 60.0% | 36.7% | 60.0% |
| PASS | `safety_disable` | 90.0% | 30 | 130 | 60.0% | 36.7% | 60.0% |
| PASS | `sql_injection` | 100.0% | 0 | 145 | 76.7% | 46.7% | 76.7% |
| PASS | `system_prompt_extract` | 90.0% | 30 | 75 | 60.0% | 36.7% | 60.0% |
| PASS | `template_injection` | 100.0% | 0 | 150 | 80.0% | 50.0% | 80.0% |
| PASS | `token_waste` | 90.0% | 30 | 75 | 30.0% | 36.7% | 30.0% |
| PASS | `training_data_extract` | 90.0% | 30 | 130 | 61.7% | 38.3% | 61.7% |
| PASS | `unicode_tricks` | 100.0% | 0 | 75 | 66.7% | 50.0% | 66.7% |

## By encoding

| Value | Attacks | Recall | FN | Controls | FP |
|---|---:|---:|---:|---:|---:|
| `base64` | 1200 | 100.0% | 0 | 600 | 600 |
| `hex_escape` | 1200 | 100.0% | 0 | 600 | 600 |
| `mixed_case` | 1200 | 86.7% | 160 | 600 | 375 |
| `plain` | 1200 | 86.7% | 160 | 600 | 375 |
| `unicode_escape` | 1200 | 100.0% | 0 | 600 | 600 |
| `whitespace` | 1200 | 86.7% | 160 | 600 | 295 |

## By payload language

| Value | Attacks | Recall | FN | Controls | FP |
|---|---:|---:|---:|---:|---:|
| `code_block` | 1440 | 99.0% | 15 | 720 | 610 |
| `english` | 1440 | 99.0% | 15 | 720 | 610 |
| `hindi` | 1440 | 68.8% | 450 | 720 | 445 |
| `json_smuggling` | 1440 | 100.0% | 0 | 720 | 555 |
| `xml_smuggling` | 1440 | 100.0% | 0 | 720 | 625 |

## By instruction position

| Value | Attacks | Recall | FN | Controls | FP |
|---|---:|---:|---:|---:|---:|
| `function_args` | 1440 | 93.3% | 96 | 720 | 569 |
| `image_alt_text` | 1440 | 93.3% | 96 | 720 | 569 |
| `system` | 1440 | 93.3% | 96 | 720 | 569 |
| `tool_result` | 1440 | 93.3% | 96 | 720 | 569 |
| `user` | 1440 | 93.3% | 96 | 720 | 569 |

## By difficulty tier

| Value | Attacks | Recall | FN | Controls | FP |
|---|---:|---:|---:|---:|---:|
| `obfuscated` | 768 | 75.3% | 190 | 384 | 200 |
| `obvious` | 96 | 97.9% | 2 | 48 | 34 |
| `stealth` | 6336 | 95.5% | 288 | 3168 | 2611 |

## Cross-family root causes and proposed deltas

1. **Request-field coverage:** extend bounded extraction to image alt text and function argument string values while retaining source/trust metadata. Currently the engine, validator, and indirect detector only extract strings and multipart `type=text` items; `image_url.alt` and assistant tool-call arguments are not inspected. Validate these surfaces with attack and benign controls before enabling them. Evidence: `entropy/core/engine.py:368-378`, `entropy/core/indirect_injection_detector.py:300-334`, `entropy/core/input_validator.py:101-111`.
2. **Unicode escapes:** add bounded `\uXXXX`/`\UXXXXXXXX` decoding (including valid surrogate pairs) and scan each view. NFKC does not decode literal escape strings. Evidence: decoder pipeline at `entropy/core/input_sanitizer.py:139-195`.
3. **Destructive normalization:** keep raw + decoded views; constrain leetspeak rewriting to suspect tokens. Current global substitutions erase execution-call punctuation and large numeric quantities before matching. Evidence: `entropy/core/input_sanitizer.py:56-73,273-281` and sanitizer-before-match order at `entropy/core/engine.py:218-249`.
4. **Language and false positives:** add genuine Hindi intent equivalents with tests for quoted/educational content. Generic decoding alone should not imply maliciousness.

These are proposals only; this work order makes no production-rule or extraction changes.

## Test-suite evidence

Full captured baseline/final outputs are stored under `reports/`.
