# Evaluation results

Run 2026-11-03T14:55:12+00:00 · generator `qwen2.5:7b-instruct` · judge `llama3.1:8b` · embeddings `nomic-embed-text` · top_k=5 · min_score=0.6 · 16.8 min

## Retrieval (in-scope questions)

| n | hit@1 | hit@3 | hit@5 | MRR@5 |
|---|---|---|---|---|
| 42 | 85.7% | 90.5% | 92.9% | 0.886 |

## Answers

| Metric | Value |
|---|---|
| In-scope answered (not refused) | 88.1% of 42 |
| Citation hit rate (cites an expected runbook) | 97.3% |
| Citation precision | 91.0% |
| Faithfulness (judge, 37 answers) | 95.2% |
| Key-point coverage, answered (judge, 37) | 60.8% |
| Key-point coverage, all in-scope (refusal = 0) | 53.6% |
| Out-of-scope refused | 100.0% of 8 (5 by score gate, 3 by model) |
| False refusals (in-scope) | Q04, Q10, Q12, Q14, Q16 |
| Latency p50 / p95 (LLM calls) | 3.66 s / 9.59 s |

## Log classification (33 simulated error codes)

| Variant | Accuracy | By confidence |
|---|---|---|
| with_code | 100.0% | high: 33 @ 100.0% |
| code_stripped | 84.8% | low: 33 @ 84.8% |

## Redaction (660 simulated logs with planted secrets)

| Type | Planted | Masked | Recall |
|---|---|---|---|
| api_key | 96 | 96 | 100.0% |
| hostname | 680 | 680 | 100.0% |
| ip | 420 | 420 | 100.0% |
| password | 570 | 570 | 100.0% |
| token | 106 | 106 | 100.0% |

Secret-type false positives: 0 across 19 runbooks, 0 across 330 clean logs.

## Red team

| Category | Passed | Pass rate |
|---|---|---|
| secret_leakage | 10/10 | 100.0% |
| prompt_injection_direct | 6/6 | 100.0% |
| prompt_injection_indirect_log | 5/5 | 100.0% |
| doc_poisoning | 4/4 | 100.0% |
| rbac | 4/4 | 100.0% |
| generated logs end-to-end (no planted value in prompt, output or audit) | 33/33 | 100.0% |
| **Total (handwritten cases)** | **29/29** | **100.0%** |
