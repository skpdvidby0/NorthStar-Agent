#!/usr/bin/env python3
"""
Evaluation runner for Northstar Shop Deletion Audit Agent (code/evaluation/main.py).

Evaluates the pipeline on dataset/sample_deletion_requests.csv against
dataset/sample_output.csv, plus 3 custom team-created evaluation cases,
and generates code/evaluation/evaluation_report.md.
"""

import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import (  # noqa: E402
    DEFAULT_DATASET_DIR,
    audit_request,
    build_resource_to_uid_map,
    load_identities,
    parse_evidence_observations,
)


def evaluate_sample_cases(dataset_dir: Path = DEFAULT_DATASET_DIR):
    users, email_to_uid, phone_to_uid, hash_to_uid = load_identities(dataset_dir)
    rid_to_uid = build_resource_to_uid_map(dataset_dir, users, email_to_uid, phone_to_uid, hash_to_uid)
    observations, uid_known_resources = parse_evidence_observations(
        dataset_dir, users, email_to_uid, phone_to_uid, hash_to_uid, rid_to_uid
    )

    with open(dataset_dir / "sample_deletion_requests.csv", encoding="utf-8") as f:
        sample_reqs = list(csv.DictReader(f))
    with open(dataset_dir / "sample_output.csv", encoding="utf-8") as f:
        sample_out = {r["case_id"]: r for r in csv.DictReader(f)}

    total_cases = len(sample_reqs)
    status_correct = 0
    sequence_exact = 0
    total_gold_steps = 0
    total_pred_steps = 0
    matched_steps = 0
    total_fields = 0
    matched_fields = 0

    for req in sample_reqs:
        cid, pred_status, pred_steps = audit_request(
            req, email_to_uid, observations, uid_known_resources
        )
        gold = sample_out[cid]
        gold_status = gold["deletion_status"]
        gold_steps = json.loads(gold["steps_json"])

        if pred_status == gold_status:
            status_correct += 1
        if pred_status == gold_status and pred_steps == gold_steps:
            sequence_exact += 1

        total_gold_steps += len(gold_steps)
        total_pred_steps += len(pred_steps)

        gold_by_key = {(s["phase"], s["system_id"], s["resource_id"]): s for s in gold_steps}
        for ps in pred_steps:
            key = (ps["phase"], ps["system_id"], ps["resource_id"])
            if key in gold_by_key:
                gs = gold_by_key[key]
                if (
                    ps["operation"] == gs["operation"]
                    and ps["state"] == gs["state"]
                    and ps["evidence_id"] == gs["evidence_id"]
                ):
                    matched_steps += 1
                for fk in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                    total_fields += 1
                    if ps.get(fk) == gs.get(fk):
                        matched_fields += 1

    # Custom evaluation cases created by our team
    custom_cases = [
        {
            "case_id": "custom_case_01",
            "email": "amina.elmasri@gmail.com",
            "requested_at": "2026-09-01T10:00:00Z",
            "reported_status": "NOT_STARTED",
            "reported_at": "2026-09-02T10:00:00Z",
            "audit_at": "2026-09-03T11:30:00Z",
            "request_text": "Please unsubscribe me from marketing lists only and leave the account active. I am not asking for deletion.",
            "expected_status": "NOT_APPLICABLE",
            "expected_steps_len": 0,
        },
        {
            "case_id": "custom_case_02",
            "email": "leila.haddad@yahoo.com",
            "requested_at": "2026-08-29T10:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-08-30T10:00:00Z",
            "audit_at": "2026-09-08T13:40:00Z",
            "request_text": "Please permanently delete my account and all associated personal data.",
            "expected_status": "INCOMPLETE",
            "expected_steps_len": 3,
        },
        {
            "case_id": "custom_case_03",
            "email": "thandiwe.n@gmail.com",
            "requested_at": "2026-08-25T09:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-08-26T09:00:00Z",
            "audit_at": "2026-09-07T10:20:00Z",
            "request_text": "Please erase my personal profile and confirm when deletion is complete.",
            "expected_status": "COMPLETE",
            "expected_steps_len": 2,
        },
    ]

    custom_passed = 0
    for cc in custom_cases:
        _, st, stps = audit_request(cc, email_to_uid, observations, uid_known_resources)
        if st == cc["expected_status"] and len(stps) == cc["expected_steps_len"]:
            custom_passed += 1

    print(f"Sample Cases Evaluated: {total_cases}")
    print(f"Case-Level Status Accuracy: {status_correct}/{total_cases} ({status_correct/total_cases*100:.2f}%)")
    print(f"Exact Sequence Accuracy: {sequence_exact}/{total_cases} ({sequence_exact/total_cases*100:.2f}%)")
    print(f"Step-Level Recall: {matched_steps}/{total_gold_steps} ({matched_steps/total_gold_steps*100:.2f}%)")
    print(f"Field-Level Accuracy (on matched keys): {matched_fields}/{total_fields} ({matched_fields/total_fields*100:.2f}%)")
    print(f"Custom Evaluation Cases Passed: {custom_passed}/{len(custom_cases)}")


if __name__ == "__main__":
    evaluate_sample_cases()
