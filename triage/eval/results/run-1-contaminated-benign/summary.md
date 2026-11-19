# Triage eval 20261119-1721

26 malicious and 17 benign alerts from the lab (see triage/eval/README.md for how they were labelled).

| Model | Recall | Strict TP | Specificity | FP rate | Technique | Tool calls | Median latency | $/alert | Total $ | Invalid |
|---|---|---|---|---|---|---|---|---|---|---|
| `deepseek/deepseek-v4.1-flash` | 100.0% | 100.0% | 5.9% | 94.1% | 92.3% | 5.8 | 17.0s | 0.00322 | 0.1383 | 0 |
| `qwen/qwen3.8-27b` | 100.0% | 100.0% | 5.9% | 94.1% | 92.3% | 4.8 | 34.2s | 0.01799 | 0.7737 | 0 |
| `z-ai/glm-5.3-flash` | 100.0% | 100.0% | 29.4% | 70.6% | 92.3% | 4.7 | 24.6s | 0.00231 | 0.0993 | 0 |
| `anthropic/claude-haiku-5.5` | 100.0% | 100.0% | 0.0% | 100.0% | 96.2% | 4.4 | 14.9s | 0.00383 | 0.1648 | 0 |
