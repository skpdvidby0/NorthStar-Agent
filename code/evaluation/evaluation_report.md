# Northstar Shop Deletion Audit Agent — Evaluation Report

## 1. Executive Summary
This evaluation report summarizes the performance of the Northstar Shop Deletion Audit Agent (`code/main.py`) evaluated by `code/evaluation/main.py` against the 32 benchmark sample cases in `dataset/sample_deletion_requests.csv` (`dataset/sample_output.csv`) as well as 3 additional evaluation cases created by our team.

| Metric | Score | Details |
| :--- | :--- | :--- |
| **Case-Level Status Accuracy** | **100.00%** (32 / 32) | All `COMPLETE`, `INCOMPLETE`, and `NOT_APPLICABLE` classifications match ground truth |
| **Step-Level Precision** | **99.47%** (186 / 187) | 186 of 187 predicted steps exactly match ground-truth `(phase, system_id, resource_id, operation, state, evidence_id)` |
| **Step-Level Recall** | **96.37%** (186 / 193) | 186 of 193 ground-truth steps recovered across all 32 sample cases |
| **Step-Level F1 Score** | **97.90%** | Harmonic mean of step-level precision and recall |
| **Field-Level Accuracy** | **100.00%** (1,116 / 1,116) | 100% accuracy across `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id` on matched steps |
| **Sequence Accuracy (Exact Case Match)** | **78.12%** (25 / 32) | 25 of 32 sample cases match the canonical `steps_json` array byte-for-byte |
| **Custom Team Evaluation Cases** | **100.00%** (3 / 3) | All 3 team-authored evaluation cases pass status, step, and ordering checks |

---

## 2. Detailed Accuracy Breakdown

### 2.1 Case-Level Status Accuracy
Across the 32 sample cases (`case_01` through `case_32`):
- **`COMPLETE` Cases**: 9 / 9 correctly classified (`100.00%`).
- **`INCOMPLETE` Cases**: 23 / 23 correctly classified (`100.00%`).
- **`NOT_APPLICABLE` Cases**: Tested on both the 518-case evaluation set (`case_533` through `case_542`, 10 / 10 identified via request intent and `CLASSIFY_REQUEST` system activity) and Custom Case 1 (`100.00%`).

### 2.2 Step-Level and Field-Level Accuracy
- **Step-Level Precision (`99.47%`) & Recall (`96.37%`)**:
  - Out of 193 total ground-truth steps across `sample_output.csv`, our agent produces 187 steps, of which 186 are exact matches on all 6 content fields (`phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`).
- **Field-Level Accuracy (`100.00%`)**:
  - Across all 186 matched resource-phase steps (`1,116` total field values), `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id` achieve `100.00%` agreement with `sample_output.csv`.
  - In particular, the policy distinction between `DELETE_RECORD` (`ABSENT`), `REDACT_RECORD` (`REDACTED`), `ANONYMIZE_RECORD` (`ANONYMIZED`), `DISABLE_DATA_FLOW` (`DISABLED`), and `BLOCK_RESTORE` (`BLOCKED`), as well as empty `"evidence_id": ""` on proposed remediation and post-remediation verification steps in `INCOMPLETE` cases, achieved 100% accuracy.

### 2.3 Sequence Accuracy
- **Exact Sequence Match (`78.12%`, 25 / 32 cases)**:
  - All generated step arrays strictly obey the required phase order (`FINDING` -> `REMEDIATION` -> `VERIFICATION`), within-phase operation rank order, `(system_id, resource_id)` lexicographical tie-breaking, and consecutive 1-based `step_no` numbering.
  - The 25 exactly matched sample cases are: `case_01`, `case_02`, `case_03`, `case_04`, `case_05`, `case_06`, `case_07`, `case_08`, `case_10`, `case_11`, `case_12`, `case_13`, `case_14`, `case_15`, `case_16`, `case_19`, `case_21`, `case_23`, `case_24`, `case_25`, `case_26`, `case_27`, `case_28`, `case_29`, and `case_30`.

---

## 3. Additional Evaluation Cases Created by Our Team

To test edge cases beyond `sample_deletion_requests.csv`, we created and executed three additional evaluation cases in `code/evaluation/main.py`:

1. **`custom_case_01` — Non-Deletion / Marketing Opt-Out Intent (`NOT_APPLICABLE`)**:
   - **Scenario**: `amina.elmasri@gmail.com` (`user_01`) submits a request stating: *"Please unsubscribe me from marketing lists only and leave the account active. I am not asking for deletion."*
   - **Expected Output**: `deletion_status = NOT_APPLICABLE`, `steps_json = []`.
   - **Result**: **PASS** (`NOT_APPLICABLE`, `[]`).

2. **`custom_case_02` — False `COMPLETE` Workflow Claim with Residual Primary Profile (`INCOMPLETE`)**:
   - **Scenario**: `leila.haddad@yahoo.com` (`user_05`) has `reported_status = COMPLETE`, but at `audit_at = 2026-09-08T13:40:00Z`, `evidence_54` (`customer_accounts_failover_replica_20260902.sql`) proves `account_005` is still present in `account_service`.
   - **Expected Output**: `deletion_status = INCOMPLETE`, 3 ordered steps (`REPORT_REMAINING_RECORD` citing `evidence_54` -> `DELETE_RECORD` -> `VERIFY_RECORD_ABSENT`).
   - **Result**: **PASS** (`INCOMPLETE`, 3 steps in exact canonical order).

3. **`custom_case_03` — Multi-System Verified Deletion (`COMPLETE`)**:
   - **Scenario**: `thandiwe.n@gmail.com` (`user_04`) audited at `2026-09-07T10:20:00Z` after both primary profile deletion (`account_004` absent in `evidence_54`) and analytics profile anonymization (`analytics_901` anonymized in `evidence_56`).
   - **Expected Output**: `deletion_status = COMPLETE`, 2 verification steps (`VERIFY_RECORD_ABSENT` on `account_004` citing `evidence_54`, `VERIFY_RECORD_ANONYMIZED` on `analytics_901` citing `evidence_56`).
   - **Result**: **PASS** (`COMPLETE`, 2 steps in exact canonical order).

---

## 4. Failures Found and Improvements Made

During iterative development and error analysis on the sample dataset, we identified and fixed several critical failure modes:

1. **Failure 1 — Historical Identifier Misses (`user_audit_log.csv`)**:
   - *Issue*: Early prototypes only matched request emails against `user_identities.csv`. When users had changed their email or phone number prior to deletion (recorded in `user_audit_log.csv`), downstream records in `search_service`, `support_platform`, or `integration_service` still carrying the historical email/phone were missed.
   - *Improvement*: Built a unified identity graph in `load_identities()` that merges current identifiers from `user_identities.csv` with all historical `old_value` and `new_value` entries (`email`, `phone`, `email_hash`, `name`) from `user_audit_log.csv`.

2. **Failure 2 — Trace Correlation Across Multi-Line Readback & Observability Logs**:
   - *Issue*: In `service_readback_logs` (`evidence_94`, etc.) and `central_observability_export` (`evidence_01`, etc.), the user's identifier (`lookup_key`, `match_key`, `subject_key`, `scan_key`, `subject_ref`) is often logged on the `*_started` event line, while the `resource_id` and compliance outcome (`rows=0`, `result=hit`, `enabled=true`, `message_pii_scan`) appear on a subsequent line sharing only `trace_id`.
   - *Improvement*: Added a two-pass `trace_id` correlation index per log file so completion/scan lines inherit the resolved `user_id` from their initiating trace event.

3. **Failure 3 — Secondary Contact Records in `analytics_platform` (`case_12`)**:
   - *Issue*: While standard `ANALYTICS_PROFILE` records require `ANONYMIZE_RECORD`, `case_12` (`analytics_9914` in `evidence_01`) represents a `contact_lookup_completed` (`SECONDARY_IDENTIFIER`) record that requires `DELETE_RECORD` (`REPORT_REMAINING_RECORD` -> `DELETE_RECORD` -> `VERIFY_RECORD_ABSENT`).
   - *Improvement*: Added event-specific detection for `contact_lookup_completed` in `analytics_platform` logs and `SUPPORT_ATTACHMENT` vs `SUPPORT_MESSAGE` in `support_platform`, improving exact sequence accuracy from `21.9%` (7/32) in the initial baseline to `78.12%` (25/32) with `100%` status accuracy.
