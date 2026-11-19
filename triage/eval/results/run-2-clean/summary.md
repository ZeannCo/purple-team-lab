# Triage eval 20261119-1802

26 malicious and 13 benign alerts from the lab (see triage/eval/README.md for how they were labelled).

| Model | Recall | Strict TP | Specificity | FP rate | Technique | Tool calls | Median latency | $/alert | Total $ | Invalid |
|---|---|---|---|---|---|---|---|---|---|---|
| `deepseek/deepseek-v4.1-flash` | 100.0% | 100.0% | 15.4% | 84.6% | 92.3% | 5.4 | 12.3s | 0.00262 | 0.1024 | 0 |
| `qwen/qwen3.8-27b` | 100.0% | 100.0% | 61.5% | 38.5% | 96.2% | 4.5 | 26.2s | 0.01373 | 0.5353 | 0 |
| `z-ai/glm-5.3-flash` | 100.0% | 100.0% | 23.1% | 76.9% | 92.3% | 4.3 | 20.5s | 0.00196 | 0.0765 | 0 |
| `anthropic/claude-haiku-5.5` | 100.0% | 100.0% | 0.0% | 100.0% | 88.5% | 4.3 | 13.0s | 0.00369 | 0.1437 | 0 |
