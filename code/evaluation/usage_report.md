# Northstar Shop Deletion Audit Agent — Usage & Cost Report

## 1. Final Full-Dataset Run Summary (`output.csv`)
The production audit pipeline (`python3 code/main.py`) executes deterministically over all 518 cases in `dataset/deletion_requests.csv` without making runtime external LLM API calls during batch execution. Multimodal PDF and structured evidence extraction is handled directly via deterministic Python parsers (`zlib` + `base64.a85decode` for ReportLab PDF streams, structured SQL/JSON/log parsers for snapshots and observability traces).

| Metric | Value |
| :--- | :--- |
| **Total Requests Audited (`deletion_requests.csv`)** | 518 |
| **Model Provider / Model Name (Runtime Batch Run)** | None (Deterministic Local Execution; 0 runtime LLM calls) |
| **Development / Agentic Coding Assistant Model** | Google DeepMind — Gemini 4 Argon (Medium) via Antigravity |
| **Runtime Model Call Count** | 0 calls |
| **Runtime Input Tokens** | 0 tokens |
| **Runtime Output Tokens** | 0 tokens |
| **Total Runtime Tokens** | 0 tokens |
| **Average Tokens per Request** | 0.00 tokens / request |
| **Estimated Total Runtime Cost (USD)** | $0.00 |
| **Estimated Cost per Request (USD)** | $0.0000 / request |
| **Wall-Clock Execution Time (518 cases)** | < 1.5 seconds |

---

## 2. Output Breakdown Across 518 Cases
- **`INCOMPLETE`**: 280 cases
- **`COMPLETE`**: 228 cases
- **`NOT_APPLICABLE`**: 10 cases (`case_533` through `case_542`)
- **Total Rows Written to `output.csv`**: 518 data rows (+ 1 header row = 519 lines), sorted ascending by `case_id`.
