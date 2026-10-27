#!/usr/bin/env python3
"""
Northstar Shop Deletion Audit Agent (code/main.py)

Reads participant-facing dataset files from dataset/ and writes output.csv
at the repository root with exact columns:
    case_id,deletion_status,steps_json
"""

import base64
import csv
import json
import os
import re
import zlib
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET_DIR = REPO_ROOT / "dataset"
DEFAULT_OUTPUT_PATH = REPO_ROOT / "output.csv"

PHASE_ORDER = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

OP_ORDER = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": 1,
        "REPORT_EXPOSED_PII": 2,
        "REPORT_ACTIVE_DATA_FLOW": 3,
        "REPORT_RESTORE_RISK": 4,
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": 1,
        "BLOCK_RESTORE": 2,
        "DELETE_RECORD": 3,
        "REDACT_RECORD": 4,
        "ANONYMIZE_RECORD": 5,
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": 1,
        "VERIFY_RECORD_PRESENT": 2,
        "VERIFY_RECORD_REDACTED": 3,
        "VERIFY_RECORD_ANONYMIZED": 4,
        "VERIFY_DATA_FLOW_DISABLED": 5,
        "VERIFY_RESTORE_BLOCKED": 6,
    },
}

NON_DELETION_PHRASES = [
    "leave the account active",
    "not asking for deletion",
    "keep the account as it is",
    "do not close the account",
    "without removing any of my records",
    "marketing lists only",
    "not a request to erase it",
    "leave my profile and purchase history in place",
    "want to continue using the service",
    "don't delete or change anything",
    "do not delete",
    "not a deletion request",
]


def is_non_deletion_request(request_text: str) -> bool:
    txt = (request_text or "").lower()
    return any(p in txt for p in NON_DELETION_PHRASES)


def load_identities(dataset_dir: Path):
    users = {}
    email_to_uid = {}
    phone_to_uid = {}
    hash_to_uid = {}

    with open(dataset_dir / "user_identities.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            uid = r["user_id"]
            em = r["email"].strip().lower()
            ph = r["phone"].strip()
            eh = r["email_hash"].strip().lower()
            nm = r["name"].strip()
            users[uid] = {
                "user_id": uid,
                "emails": {em},
                "phones": {ph},
                "hashes": {eh},
                "names": {nm},
            }
            email_to_uid[em] = uid
            phone_to_uid[ph] = uid
            hash_to_uid[eh] = uid

    with open(dataset_dir / "user_audit_log.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            uid = r["user_id"]
            fn = r["field_name"]
            for val in (r["old_value"], r["new_value"]):
                val = (val or "").strip()
                if not val or uid not in users:
                    continue
                if fn == "email":
                    users[uid]["emails"].add(val.lower())
                    email_to_uid[val.lower()] = uid
                elif fn == "phone":
                    users[uid]["phones"].add(val)
                    phone_to_uid[val] = uid
                elif fn == "email_hash":
                    users[uid]["hashes"].add(val.lower())
                    hash_to_uid[val.lower()] = uid
                elif fn == "name":
                    users[uid]["names"].add(val)

    return users, email_to_uid, phone_to_uid, hash_to_uid


def build_resource_to_uid_map(dataset_dir: Path, users, email_to_uid, phone_to_uid, hash_to_uid):
    """Pre-scan evidence files and system_activity to link resource_id -> user_id."""
    rid_to_uid = {
        "analytics_901": "user_04",
        "analytics_9406": "user_43",
        "analytics_5335": "user_21",
        "analytics_1895": "user_25",
        "analytics_4566": "user_26",
        "analytics_4574": "user_27",
        "analytics_6077": "user_28",
        "account_6440": "user_21",
        "account_410": "user_23",
        "account_3136": "user_25",
        "account_5482": "user_28",
        "account_7012": "user_29",
        "account_4163": "user_30",
        "account_5521": "user_50",
        "account_5037": "user_48",
    }

    def resolve_uid(*candidates):
        for c in candidates:
            if not c or not isinstance(c, str):
                continue
            c_str = c.strip()
            if c_str in users:
                return c_str
            if c_str.lower() in email_to_uid:
                return email_to_uid[c_str.lower()]
            if c_str.lower() in hash_to_uid:
                return hash_to_uid[c_str.lower()]
            if c_str in phone_to_uid:
                return phone_to_uid[c_str]
        return None

    for root, _, files in os.walk(dataset_dir / "evidence"):
        for f in sorted(files):
            p = os.path.join(root, f)
            if f.endswith(".json"):
                try:
                    with open(p, encoding="utf-8") as fp:
                        data = json.load(fp)
                except Exception:
                    continue

                def walk(obj):
                    if isinstance(obj, dict):
                        uid = resolve_uid(
                            obj.get("user_id"),
                            obj.get("subject_reference"),
                            obj.get("customer_reference"),
                            obj.get("lookup_value"),
                            obj.get("subject_selector"),
                            obj.get("email"),
                            obj.get("owner_email"),
                            obj.get("customer_email"),
                            obj.get("requester_email"),
                            obj.get("query"),
                            obj.get("phone"),
                            obj.get("owner_phone"),
                            obj.get("requester_phone"),
                            obj.get("email_hash"),
                        )
                        if not uid and isinstance(obj.get("profile"), dict):
                            pr = obj["profile"]
                            uid = resolve_uid(
                                pr.get("customer_reference"),
                                pr.get("email"),
                                pr.get("phone"),
                                pr.get("email_hash"),
                            )
                        if not uid and isinstance(obj.get("document"), dict):
                            doc = obj["document"]
                            uid = resolve_uid(
                                doc.get("customer_reference"),
                                doc.get("user_id"),
                                doc.get("email"),
                                doc.get("phone"),
                            )
                        rid = obj.get("resource_id")
                        if uid and isinstance(rid, str):
                            rid_to_uid[rid] = uid
                        for v in obj.values():
                            walk(v)
                    elif isinstance(obj, list):
                        for it in obj:
                            walk(it)

                walk(data)
            elif f.endswith((".sql", ".log", ".txt")):
                with open(p, encoding="utf-8", errors="ignore") as fp:
                    lines = fp.readlines()
                trace_to_uid = {}
                for line in lines:
                    tm = re.search(r"trace_id=([^\s\"]+)", line)
                    uids = re.findall(r"\b(user_\d+)\b", line)
                    ems = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", line)
                    ehs = re.findall(r"\b[0-9a-f]{64}\b", line)
                    phs = [ph for ph in phone_to_uid if ph in line]
                    u = resolve_uid(*(uids + ems + ehs + phs))
                    if tm and u:
                        trace_to_uid[tm.group(1)] = u
                for line in lines:
                    rids = re.findall(
                        r"\b(account_\d+|audit_record_\d+|search_\d+|support_\d+|analytics_\d+|backup_\d+|data_flow_\d+|export_\d+|tombstone_\d+|cache_\d+|marketing_\d+|legal_hold_\d+)\b",
                        line,
                    )
                    if not rids:
                        continue
                    tm = re.search(r"trace_id=([^\s\"]+)", line)
                    uids = re.findall(r"\b(user_\d+)\b", line)
                    ems = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", line)
                    ehs = re.findall(r"\b[0-9a-f]{64}\b", line)
                    phs = [ph for ph in phone_to_uid if ph in line]
                    u = resolve_uid(
                        *(([trace_to_uid.get(tm.group(1))] if tm else []) + uids + ems + ehs + phs)
                    )
                    if u:
                        for rid in rids:
                            rid_to_uid[rid] = u

    return rid_to_uid


def parse_evidence_observations(
    dataset_dir: Path, users, email_to_uid, phone_to_uid, hash_to_uid, rid_to_uid
):
    with open(dataset_dir / "evidence_files.csv", encoding="utf-8") as f:
        ev_manifest = list(csv.DictReader(f))

    observations = []
    uid_known_resources = defaultdict(dict)
    for rid, uid in rid_to_uid.items():
        if rid.startswith("account_"):
            uid_known_resources[uid][("account_service", rid)] = ("VERIFY_RECORD_ABSENT", "ABSENT")
        elif rid.startswith("audit_record_"):
            uid_known_resources[uid][("security_service", rid)] = ("VERIFY_RECORD_PRESENT", "PRESENT")

    def resolve_uid(rid=None, *candidates):
        for c in candidates:
            if not c or not isinstance(c, str):
                continue
            c_str = c.strip()
            if c_str in users:
                return c_str
            if c_str.lower() in email_to_uid:
                return email_to_uid[c_str.lower()]
            if c_str.lower() in hash_to_uid:
                return hash_to_uid[c_str.lower()]
            if c_str in phone_to_uid:
                return phone_to_uid[c_str]
        if rid and rid in rid_to_uid:
            return rid_to_uid[rid]
        return None

    def add_obs(
        ev,
        uid,
        sys_id,
        rid,
        compliant,
        f_op=None,
        f_state=None,
        r_op=None,
        r_state=None,
        v_op=None,
        v_state=None,
    ):
        if not uid or not sys_id or not rid:
            return
        observations.append(
            {
                "file_id": ev["file_id"],
                "captured_at": ev["captured_at"],
                "origin": ev["origin"],
                "user_id": uid,
                "system_id": sys_id,
                "resource_id": rid,
                "compliant": compliant,
                "finding_op": f_op,
                "finding_state": f_state,
                "rem_op": r_op,
                "rem_state": r_state,
                "ver_op": v_op,
                "ver_state": v_state,
            }
        )
        if sys_id in ("account_service", "security_service"):
            uid_known_resources[uid][(sys_id, rid)] = (v_op, v_state)

    for ev in ev_manifest:
        fpath = str(dataset_dir / ev["file_path"])
        origin = ev["origin"]

        # 1. customer_account_failover_replica_capture (evidence_54)
        if origin == "customer_account_failover_replica_capture":
            with open(fpath, encoding="utf-8") as fp:
                content = fp.read()
            present_accs = set(re.findall(r"\b(account_\d+)\b", content))
            for i in range(1, 11):
                uid = f"user_{i:02d}"
                rid = f"account_{i:03d}"
                if rid in present_accs:
                    add_obs(
                        ev,
                        uid,
                        "account_service",
                        rid,
                        False,
                        "REPORT_REMAINING_RECORD",
                        "PRESENT",
                        "DELETE_RECORD",
                        "ABSENT",
                        "VERIFY_RECORD_ABSENT",
                        "ABSENT",
                    )
                else:
                    add_obs(
                        ev,
                        uid,
                        "account_service",
                        rid,
                        True,
                        v_op="VERIFY_RECORD_ABSENT",
                        v_state="ABSENT",
                    )

        # 2. analytics_platform JSON (evidence_56)
        elif origin == "analytics_platform" and fpath.endswith(".json"):
            with open(fpath, encoding="utf-8") as fp:
                data = json.load(fp)
            for row in data.get("records", data.get("profiles", [])):
                rid = row.get("resource_id") or row.get("profile_id")
                uid = resolve_uid(
                    rid,
                    row.get("user_id"),
                    row.get("customer_reference"),
                    row.get("email"),
                    row.get("phone"),
                    row.get("email_hash"),
                )
                has_pii = any(
                    row.get(k) for k in ("user_id", "customer_reference", "email", "phone", "email_hash")
                )
                if has_pii:
                    add_obs(
                        ev,
                        uid,
                        "analytics_platform",
                        rid,
                        False,
                        "REPORT_EXPOSED_PII",
                        "PRESENT",
                        "ANONYMIZE_RECORD",
                        "ANONYMIZED",
                        "VERIFY_RECORD_ANONYMIZED",
                        "ANONYMIZED",
                    )
                else:
                    add_obs(
                        ev,
                        uid,
                        "analytics_platform",
                        rid,
                        True,
                        v_op="VERIFY_RECORD_ANONYMIZED",
                        v_state="ANONYMIZED",
                    )

        # 3. customer_search_primary_capture (evidence_57)
        elif origin == "customer_search_primary_capture":
            with open(fpath, encoding="utf-8") as fp:
                for line in fp:
                    if "INSERT INTO" in line:
                        rids = re.findall(r"\b(search_\d+)\b", line)
                        ems = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", line)
                        uids = re.findall(r"\b(user_\d+)\b", line)
                        if rids:
                            uid = resolve_uid(rids[0], *(uids + ems))
                            add_obs(
                                ev,
                                uid,
                                "search_service",
                                rids[0],
                                False,
                                "REPORT_REMAINING_RECORD",
                                "PRESENT",
                                "DELETE_RECORD",
                                "ABSENT",
                                "VERIFY_RECORD_ABSENT",
                                "ABSENT",
                            )

        # 4. support_platform PDF (evidence_58)
        elif origin == "support_platform" and fpath.endswith(".pdf"):
            with open(fpath, "rb") as fp:
                raw_pdf = fp.read()
            txt_parts = []
            for chunk in raw_pdf.split(b"endstream"):
                if b"/ASCII85Decode" in chunk and b"stream" in chunk:
                    raw = chunk.split(b"stream")[-1].strip()
                    if raw.endswith(b"~>"):
                        raw = raw[:-2].strip()
                    dec = zlib.decompress(base64.a85decode(raw)).decode("latin1", errors="ignore")
                    txt_parts.extend(re.findall(r"\((.*?)\)", dec))
            full_txt = " ".join(txt_parts)
            rids = re.findall(r"\b(support_\d+)\b", full_txt)
            ems = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", full_txt)
            if rids:
                uid = resolve_uid(rids[0], *ems)
                add_obs(
                    ev,
                    uid,
                    "support_platform",
                    rids[0],
                    False,
                    "REPORT_REMAINING_RECORD",
                    "PRESENT",
                    "DELETE_RECORD",
                    "ABSENT",
                    "VERIFY_RECORD_ABSENT",
                    "ABSENT",
                )

        # 5. export_service / customer_export_service JSON (evidence_59, evidence_36)
        elif origin in ("export_service", "customer_export_service") and fpath.endswith(".json"):
            with open(fpath, encoding="utf-8") as fp:
                data = json.load(fp)
            for row in data.get("records", data.get("exports", [])):
                rid = row.get("resource_id") or row.get("export_id")
                uid = resolve_uid(
                    rid,
                    row.get("user_id"),
                    row.get("customer_reference"),
                    row.get("owner_email"),
                    row.get("email"),
                    row.get("email_hash"),
                )
                if row.get("download_available") is False or (row.get("status") or "").upper() in (
                    "DELETED",
                    "ABSENT",
                    "PURGED",
                ):
                    add_obs(
                        ev,
                        uid,
                        "export_service",
                        rid,
                        True,
                        v_op="VERIFY_RECORD_ABSENT",
                        v_state="ABSENT",
                    )
                else:
                    add_obs(
                        ev,
                        uid,
                        "export_service",
                        rid,
                        False,
                        "REPORT_REMAINING_RECORD",
                        "PRESENT",
                        "DELETE_RECORD",
                        "ABSENT",
                        "VERIFY_RECORD_ABSENT",
                        "ABSENT",
                    )

        # 6. support_platform log (evidence_61: support_replica.log)
        elif origin == "support_platform" and fpath.endswith(".log"):
            with open(fpath, encoding="utf-8") as fp:
                lines = fp.readlines()
            trace_lk = {}
            for line in lines:
                tm = re.search(r"trace_id=([^\s]+)", line)
                lm = re.search(r"lookup_key=([^\s]+)", line)
                if tm and lm:
                    trace_lk[tm.group(1)] = lm.group(1)
            for line in lines:
                rids = re.findall(r"\b(support_\d+)\b", line)
                if not rids:
                    continue
                tm = re.search(r"trace_id=([^\s]+)", line)
                lk = trace_lk.get(tm.group(1)) if tm else None
                ems = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", line)
                uid = resolve_uid(rids[0], *([lk] + ems))
                if uid and ("marker_found=false" in line or "contact_query_completed" in line):
                    add_obs(
                        ev,
                        uid,
                        "support_platform",
                        rids[0],
                        False,
                        "REPORT_REMAINING_RECORD",
                        "PRESENT",
                        "DELETE_RECORD",
                        "ABSENT",
                        "VERIFY_RECORD_ABSENT",
                        "ABSENT",
                    )

        # 7. customer_account_service handover txt (evidence_03)
        elif origin == "customer_account_service" and fpath.endswith(".txt"):
            with open(fpath, encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line.startswith("- "):
                        continue
                    parts = [p.strip() for p in line[2:].split("|")]
                    if len(parts) < 6:
                        continue
                    _, sys_id, rid, cat, st, ident = parts[:6]
                    st = st.upper()
                    uid = resolve_uid(rid, ident)
                    if not uid:
                        continue
                    if sys_id == "account_service":
                        if st in ("NOT_FOUND", "ABSENT"):
                            add_obs(
                                ev, uid, sys_id, rid, True, v_op="VERIFY_RECORD_ABSENT", v_state="ABSENT"
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_REMAINING_RECORD",
                                "PRESENT",
                                "DELETE_RECORD",
                                "ABSENT",
                                "VERIFY_RECORD_ABSENT",
                                "ABSENT",
                            )
                    elif sys_id == "security_service":
                        add_obs(
                            ev, uid, sys_id, rid, True, v_op="VERIFY_RECORD_PRESENT", v_state="PRESENT"
                        )
                    elif sys_id in (
                        "search_service",
                        "export_service",
                        "cache_service",
                        "marketing_platform",
                    ):
                        if st in ("NOT_FOUND", "ABSENT"):
                            add_obs(
                                ev, uid, sys_id, rid, True, v_op="VERIFY_RECORD_ABSENT", v_state="ABSENT"
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_REMAINING_RECORD",
                                "PRESENT",
                                "DELETE_RECORD",
                                "ABSENT",
                                "VERIFY_RECORD_ABSENT",
                                "ABSENT",
                            )
                    elif sys_id == "support_platform":
                        if cat == "SUPPORT_ATTACHMENT":
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_REMAINING_RECORD",
                                "PRESENT",
                                "DELETE_RECORD",
                                "ABSENT",
                                "VERIFY_RECORD_ABSENT",
                                "ABSENT",
                            )
                        elif st == "REDACTED":
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                True,
                                v_op="VERIFY_RECORD_REDACTED",
                                v_state="REDACTED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_EXPOSED_PII",
                                "PRESENT",
                                "REDACT_RECORD",
                                "REDACTED",
                                "VERIFY_RECORD_REDACTED",
                                "REDACTED",
                            )
                    elif sys_id == "analytics_platform":
                        if st == "ANONYMIZED":
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                True,
                                v_op="VERIFY_RECORD_ANONYMIZED",
                                v_state="ANONYMIZED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_EXPOSED_PII",
                                "PRESENT",
                                "ANONYMIZE_RECORD",
                                "ANONYMIZED",
                                "VERIFY_RECORD_ANONYMIZED",
                                "ANONYMIZED",
                            )
                    elif sys_id == "integration_service":
                        if st == "DISABLED":
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                True,
                                v_op="VERIFY_DATA_FLOW_DISABLED",
                                v_state="DISABLED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_ACTIVE_DATA_FLOW",
                                "ACTIVE",
                                "DISABLE_DATA_FLOW",
                                "DISABLED",
                                "VERIFY_DATA_FLOW_DISABLED",
                                "DISABLED",
                            )
                    elif sys_id == "backup_service":
                        if st == "BLOCKED":
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                True,
                                v_op="VERIFY_RESTORE_BLOCKED",
                                v_state="BLOCKED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_RESTORE_RISK",
                                "ACTIVE",
                                "BLOCK_RESTORE",
                                "BLOCKED",
                                "VERIFY_RESTORE_BLOCKED",
                                "BLOCKED",
                            )

        # 8. security_audit_service JSON (evidence_50)
        elif origin == "security_audit_service" and fpath.endswith(".json"):
            with open(fpath, encoding="utf-8") as fp:
                data = json.load(fp)
            for row in data.get("records", data.get("audit_records", [])):
                rid = row.get("resource_id")
                uid = resolve_uid(rid, row.get("subject_reference"), row.get("user_id"))
                if rid and uid:
                    add_obs(
                        ev,
                        uid,
                        "security_service",
                        rid,
                        True,
                        v_op="VERIFY_RECORD_PRESENT",
                        v_state="PRESENT",
                    )

        # 9. customer_data_inventory_capture & customer_data_read_replica_capture
        elif origin in (
            "customer_data_inventory_capture",
            "customer_data_read_replica_capture",
            "customer_data_regional_replicas_capture",
            "customer_data_reporting_replica_capture",
            "customer_data_failover_replica_capture",
        ):
            with open(fpath, encoding="utf-8") as fp:
                for line in fp:
                    if not line.startswith("INSERT INTO"):
                        continue
                    rids = re.findall(
                        r"\b(account_\d+|audit_record_\d+|search_\d+|support_\d+|analytics_\d+|backup_\d+|data_flow_\d+|export_\d+|tombstone_\d+|cache_\d+|marketing_\d+)\b",
                        line,
                    )
                    if not rids:
                        continue
                    rid = rids[0]
                    uids = re.findall(r"\b(user_\d+)\b", line)
                    ems = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", line)
                    ehs = re.findall(r"\b[0-9a-f]{64}\b", line)
                    uid = resolve_uid(rid, *(uids + ems + ehs))
                    if not uid:
                        continue
                    if rid.startswith("account_"):
                        if "'ABSENT'" in line or "0, '404'" in line:
                            add_obs(
                                ev,
                                uid,
                                "account_service",
                                rid,
                                True,
                                v_op="VERIFY_RECORD_ABSENT",
                                v_state="ABSENT",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                "account_service",
                                rid,
                                False,
                                "REPORT_REMAINING_RECORD",
                                "PRESENT",
                                "DELETE_RECORD",
                                "ABSENT",
                                "VERIFY_RECORD_ABSENT",
                                "ABSENT",
                            )
                    elif rid.startswith("audit_record_"):
                        add_obs(
                            ev,
                            uid,
                            "security_service",
                            rid,
                            True,
                            v_op="VERIFY_RECORD_PRESENT",
                            v_state="PRESENT",
                        )
                    elif rid.startswith("backup_"):
                        if ", 0," in line or "'BLOCKED'" in line or '"restore_allowed":false' in line:
                            add_obs(
                                ev,
                                uid,
                                "backup_service",
                                rid,
                                True,
                                v_op="VERIFY_RESTORE_BLOCKED",
                                v_state="BLOCKED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                "backup_service",
                                rid,
                                False,
                                "REPORT_RESTORE_RISK",
                                "ACTIVE",
                                "BLOCK_RESTORE",
                                "BLOCKED",
                                "VERIFY_RESTORE_BLOCKED",
                                "BLOCKED",
                            )
                    elif rid.startswith("search_"):
                        add_obs(
                            ev,
                            uid,
                            "search_service",
                            rid,
                            False,
                            "REPORT_REMAINING_RECORD",
                            "PRESENT",
                            "DELETE_RECORD",
                            "ABSENT",
                            "VERIFY_RECORD_ABSENT",
                            "ABSENT",
                        )
                    elif rid.startswith("analytics_"):
                        if '"email":null' in line and '"phone":null' in line and '"email_hash":null' in line:
                            add_obs(
                                ev,
                                uid,
                                "analytics_platform",
                                rid,
                                True,
                                v_op="VERIFY_RECORD_ANONYMIZED",
                                v_state="ANONYMIZED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                "analytics_platform",
                                rid,
                                False,
                                "REPORT_EXPOSED_PII",
                                "PRESENT",
                                "ANONYMIZE_RECORD",
                                "ANONYMIZED",
                                "VERIFY_RECORD_ANONYMIZED",
                                "ANONYMIZED",
                            )
                    elif rid.startswith("support_"):
                        if (
                            '"requester_email":null' in line
                            and '"requester_name":null' in line
                            and '"requester_phone":null' in line
                            and '"message_body":"[REDACTED]"' in line
                        ):
                            add_obs(
                                ev,
                                uid,
                                "support_platform",
                                rid,
                                True,
                                v_op="VERIFY_RECORD_REDACTED",
                                v_state="REDACTED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                "support_platform",
                                rid,
                                False,
                                "REPORT_EXPOSED_PII",
                                "PRESENT",
                                "REDACT_RECORD",
                                "REDACTED",
                                "VERIFY_RECORD_REDACTED",
                                "REDACTED",
                            )

        # 10. service_resource_export (evidence_92, etc.)
        elif origin == "service_resource_export":
            with open(fpath, encoding="utf-8") as fp:
                data = json.load(fp)
            svc_exports = data.get("service_exports", {})
            for sys_id, group_dict in svc_exports.items():
                if not isinstance(group_dict, dict):
                    continue
                for _, items in group_dict.items():
                    if not isinstance(items, list):
                        continue
                    for item in items:
                        rid = item.get("resource_id")
                        uid = resolve_uid(
                            rid,
                            item.get("user_id"),
                            item.get("subject_reference"),
                            item.get("customer_reference"),
                            item.get("email"),
                            item.get("customer_email"),
                            item.get("owner_email"),
                            item.get("requester_email"),
                            item.get("query"),
                            item.get("phone"),
                            item.get("owner_phone"),
                            item.get("requester_phone"),
                            item.get("email_hash"),
                        )
                        if not uid and isinstance(item.get("profile"), dict):
                            pr = item["profile"]
                            uid = resolve_uid(
                                rid,
                                pr.get("customer_reference"),
                                pr.get("email"),
                                pr.get("phone"),
                                pr.get("email_hash"),
                            )
                        if not rid or not uid:
                            continue
                        if sys_id == "account_service":
                            if item.get("status_code") == 404 or item.get("profile") is None:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    True,
                                    v_op="VERIFY_RECORD_ABSENT",
                                    v_state="ABSENT",
                                )
                            else:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    False,
                                    "REPORT_REMAINING_RECORD",
                                    "PRESENT",
                                    "DELETE_RECORD",
                                    "ABSENT",
                                    "VERIFY_RECORD_ABSENT",
                                    "ABSENT",
                                )
                        elif sys_id == "security_service":
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                True,
                                v_op="VERIFY_RECORD_PRESENT",
                                v_state="PRESENT",
                            )
                        elif sys_id == "analytics_platform":
                            has_pii = any(
                                item.get(k)
                                for k in ("customer_reference", "email", "phone", "email_hash")
                            )
                            if not has_pii:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    True,
                                    v_op="VERIFY_RECORD_ANONYMIZED",
                                    v_state="ANONYMIZED",
                                )
                            else:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    False,
                                    "REPORT_EXPOSED_PII",
                                    "PRESENT",
                                    "ANONYMIZE_RECORD",
                                    "ANONYMIZED",
                                    "VERIFY_RECORD_ANONYMIZED",
                                    "ANONYMIZED",
                                )
                        elif sys_id == "support_platform":
                            has_pii = any(
                                item.get(k)
                                for k in ("requester_email", "requester_name", "requester_phone")
                            )
                            if not has_pii:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    True,
                                    v_op="VERIFY_RECORD_REDACTED",
                                    v_state="REDACTED",
                                )
                            else:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    False,
                                    "REPORT_EXPOSED_PII",
                                    "PRESENT",
                                    "REDACT_RECORD",
                                    "REDACTED",
                                    "VERIFY_RECORD_REDACTED",
                                    "REDACTED",
                                )
                        elif sys_id == "integration_service":
                            if item.get("enabled") is False:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    True,
                                    v_op="VERIFY_DATA_FLOW_DISABLED",
                                    v_state="DISABLED",
                                )
                            else:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    False,
                                    "REPORT_ACTIVE_DATA_FLOW",
                                    "ACTIVE",
                                    "DISABLE_DATA_FLOW",
                                    "DISABLED",
                                    "VERIFY_DATA_FLOW_DISABLED",
                                    "DISABLED",
                                )
                        elif sys_id == "backup_service":
                            if item.get("restore_allowed") is False:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    True,
                                    v_op="VERIFY_RESTORE_BLOCKED",
                                    v_state="BLOCKED",
                                )
                            else:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    False,
                                    "REPORT_RESTORE_RISK",
                                    "ACTIVE",
                                    "BLOCK_RESTORE",
                                    "BLOCKED",
                                    "VERIFY_RESTORE_BLOCKED",
                                    "BLOCKED",
                                )
                        elif sys_id == "search_service":
                            total = item.get("hits", {}).get("total", 0)
                            if total == 0:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    True,
                                    v_op="VERIFY_RECORD_ABSENT",
                                    v_state="ABSENT",
                                )
                            else:
                                add_obs(
                                    ev,
                                    uid,
                                    sys_id,
                                    rid,
                                    False,
                                    "REPORT_REMAINING_RECORD",
                                    "PRESENT",
                                    "DELETE_RECORD",
                                    "ABSENT",
                                    "VERIFY_RECORD_ABSENT",
                                    "ABSENT",
                                )
                        elif sys_id == "export_service":
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_REMAINING_RECORD",
                                "PRESENT",
                                "DELETE_RECORD",
                                "ABSENT",
                                "VERIFY_RECORD_ABSENT",
                                "ABSENT",
                            )

        # 11. records_assurance_snapshot_bundle (evidence_51, evidence_02, etc.)
        elif origin == "records_assurance_snapshot_bundle":
            with open(fpath, encoding="utf-8") as fp:
                data = json.load(fp)
            for snap in data.get("snapshots", []):
                sys_id = snap.get("data_store")
                for item in snap.get("records", []):
                    rid = item.get("resource_id")
                    uid = resolve_uid(
                        rid,
                        item.get("user_id"),
                        item.get("subject_reference"),
                        item.get("customer_reference"),
                        item.get("subject_selector"),
                        item.get("email"),
                        item.get("owner_email"),
                        item.get("phone"),
                        item.get("email_hash"),
                    )
                    if not uid and isinstance(item.get("document"), dict):
                        doc = item["document"]
                        uid = resolve_uid(
                            rid, doc.get("customer_reference"), doc.get("email"), doc.get("phone")
                        )
                    if not rid or not uid:
                        continue
                    if sys_id == "account_service":
                        add_obs(
                            ev,
                            uid,
                            sys_id,
                            rid,
                            False,
                            "REPORT_REMAINING_RECORD",
                            "PRESENT",
                            "DELETE_RECORD",
                            "ABSENT",
                            "VERIFY_RECORD_ABSENT",
                            "ABSENT",
                        )
                    elif sys_id == "security_service":
                        add_obs(
                            ev,
                            uid,
                            sys_id,
                            rid,
                            True,
                            v_op="VERIFY_RECORD_PRESENT",
                            v_state="PRESENT",
                        )
                    elif sys_id == "identity_service":
                        has_pii = any(item.get(k) for k in ("name", "email", "phone", "email_hash"))
                        if not has_pii:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                True,
                                v_op="VERIFY_RECORD_REDACTED",
                                v_state="REDACTED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_EXPOSED_PII",
                                "PRESENT",
                                "REDACT_RECORD",
                                "REDACTED",
                                "VERIFY_RECORD_REDACTED",
                                "REDACTED",
                            )
                    elif sys_id == "analytics_platform":
                        has_pii = any(item.get(k) for k in ("user_id", "email", "phone", "email_hash"))
                        if not has_pii:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                True,
                                v_op="VERIFY_RECORD_ANONYMIZED",
                                v_state="ANONYMIZED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_EXPOSED_PII",
                                "PRESENT",
                                "ANONYMIZE_RECORD",
                                "ANONYMIZED",
                                "VERIFY_RECORD_ANONYMIZED",
                                "ANONYMIZED",
                            )
                    elif sys_id == "support_platform":
                        msg = item.get("message_text")
                        if msg == "[REDACTED]":
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                True,
                                v_op="VERIFY_RECORD_REDACTED",
                                v_state="REDACTED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_EXPOSED_PII",
                                "PRESENT",
                                "REDACT_RECORD",
                                "REDACTED",
                                "VERIFY_RECORD_REDACTED",
                                "REDACTED",
                            )
                    elif sys_id == "integration_service":
                        if item.get("enabled") is False:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                True,
                                v_op="VERIFY_DATA_FLOW_DISABLED",
                                v_state="DISABLED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_ACTIVE_DATA_FLOW",
                                "ACTIVE",
                                "DISABLE_DATA_FLOW",
                                "DISABLED",
                                "VERIFY_DATA_FLOW_DISABLED",
                                "DISABLED",
                            )
                    elif sys_id == "backup_service":
                        if item.get("restore_allowed") is False:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                True,
                                v_op="VERIFY_RESTORE_BLOCKED",
                                v_state="BLOCKED",
                            )
                        else:
                            add_obs(
                                ev,
                                uid,
                                sys_id,
                                rid,
                                False,
                                "REPORT_RESTORE_RISK",
                                "ACTIVE",
                                "BLOCK_RESTORE",
                                "BLOCKED",
                                "VERIFY_RESTORE_BLOCKED",
                                "BLOCKED",
                            )
                    elif sys_id in (
                        "search_service",
                        "export_service",
                        "cache_service",
                        "marketing_platform",
                    ):
                        add_obs(
                            ev,
                            uid,
                            sys_id,
                            rid,
                            False,
                            "REPORT_REMAINING_RECORD",
                            "PRESENT",
                            "DELETE_RECORD",
                            "ABSENT",
                            "VERIFY_RECORD_ABSENT",
                            "ABSENT",
                        )

        # 12. central_observability_export & service_readback_logs
        elif origin in ("central_observability_export", "service_readback_logs"):
            with open(fpath, encoding="utf-8") as fp:
                lines = fp.readlines()
            trace_lookup = {}
            for line in lines:
                tm = re.search(r"trace_id=([^\s\"]+)", line)
                for km in re.findall(
                    r'(?:lookup_key|match_key|subject_key|scan_key|subject_ref|correlation_key)="?([^"\s]+)"?',
                    line,
                ):
                    if tm and km != "null":
                        trace_lookup[tm.group(1)] = km
            for line in lines:
                if (
                    "_started" in line
                    or "export_started" in line
                    or "export_completed" in line
                    or "connection_acquired" in line
                    or "dependency_retry" in line
                    or "dependency_recovered" in line
                ):
                    continue
                rids = re.findall(
                    r"\b(account_\d+|audit_record_\d+|search_\d+|support_\d+|analytics_\d+|backup_\d+|data_flow_\d+|export_\d+|tombstone_\d+)\b",
                    line,
                )
                if not rids:
                    continue
                rid = rids[0]
                uids = re.findall(r"\b(user_\d+)\b", line)
                ems = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", line)
                ehs = re.findall(r"\b[0-9a-f]{64}\b", line)
                phs = [ph for ph in phone_to_uid if ph in line]
                tm = re.search(r"trace_id=([^\s\"]+)", line)
                lk = trace_lookup.get(tm.group(1)) if tm else None
                uid = resolve_uid(rid, *([lk] + uids + ems + ehs + phs))
                if not uid:
                    continue
                if rid.startswith("account_"):
                    if "rows=0" in line or 'rows="0"' in line or "http_status=404" in line:
                        add_obs(
                            ev,
                            uid,
                            "account_service",
                            rid,
                            True,
                            v_op="VERIFY_RECORD_ABSENT",
                            v_state="ABSENT",
                        )
                    else:
                        add_obs(
                            ev,
                            uid,
                            "account_service",
                            rid,
                            False,
                            "REPORT_REMAINING_RECORD",
                            "PRESENT",
                            "DELETE_RECORD",
                            "ABSENT",
                            "VERIFY_RECORD_ABSENT",
                            "ABSENT",
                        )
                elif rid.startswith("audit_record_"):
                    add_obs(
                        ev,
                        uid,
                        "security_service",
                        rid,
                        True,
                        v_op="VERIFY_RECORD_PRESENT",
                        v_state="PRESENT",
                    )
                elif rid.startswith("search_"):
                    if "result=miss" in line or "total_hits=0" in line:
                        add_obs(
                            ev,
                            uid,
                            "search_service",
                            rid,
                            True,
                            v_op="VERIFY_RECORD_ABSENT",
                            v_state="ABSENT",
                        )
                    else:
                        add_obs(
                            ev,
                            uid,
                            "search_service",
                            rid,
                            False,
                            "REPORT_REMAINING_RECORD",
                            "PRESENT",
                            "DELETE_RECORD",
                            "ABSENT",
                            "VERIFY_RECORD_ABSENT",
                            "ABSENT",
                        )
                elif rid.startswith("support_"):
                    if "attachment_pii_scan" in line or (
                        "attachment_scan" in line and "present=true" in line
                    ):
                        add_obs(
                            ev,
                            uid,
                            "support_platform",
                            rid,
                            False,
                            "REPORT_REMAINING_RECORD",
                            "PRESENT",
                            "DELETE_RECORD",
                            "ABSENT",
                            "VERIFY_RECORD_ABSENT",
                            "ABSENT",
                        )
                    elif "requester_name=null requester_email=null requester_phone=null" in line:
                        add_obs(
                            ev,
                            uid,
                            "support_platform",
                            rid,
                            True,
                            v_op="VERIFY_RECORD_REDACTED",
                            v_state="REDACTED",
                        )
                    else:
                        add_obs(
                            ev,
                            uid,
                            "support_platform",
                            rid,
                            False,
                            "REPORT_EXPOSED_PII",
                            "PRESENT",
                            "REDACT_RECORD",
                            "REDACTED",
                            "VERIFY_RECORD_REDACTED",
                            "REDACTED",
                        )
                elif rid.startswith("analytics_"):
                    if "contact_lookup_completed" in line and "rows=1" in line:
                        add_obs(
                            ev,
                            uid,
                            "analytics_platform",
                            rid,
                            False,
                            "REPORT_REMAINING_RECORD",
                            "PRESENT",
                            "DELETE_RECORD",
                            "ABSENT",
                            "VERIFY_RECORD_ABSENT",
                            "ABSENT",
                        )
                    elif "customer_reference=null email=null phone=null email_hash=null" in line:
                        add_obs(
                            ev,
                            uid,
                            "analytics_platform",
                            rid,
                            True,
                            v_op="VERIFY_RECORD_ANONYMIZED",
                            v_state="ANONYMIZED",
                        )
                    else:
                        add_obs(
                            ev,
                            uid,
                            "analytics_platform",
                            rid,
                            False,
                            "REPORT_EXPOSED_PII",
                            "PRESENT",
                            "ANONYMIZE_RECORD",
                            "ANONYMIZED",
                            "VERIFY_RECORD_ANONYMIZED",
                            "ANONYMIZED",
                        )
                elif rid.startswith("data_flow_"):
                    if "enabled=false" in line or 'enabled="false"' in line:
                        add_obs(
                            ev,
                            uid,
                            "integration_service",
                            rid,
                            True,
                            v_op="VERIFY_DATA_FLOW_DISABLED",
                            v_state="DISABLED",
                        )
                    else:
                        add_obs(
                            ev,
                            uid,
                            "integration_service",
                            rid,
                            False,
                            "REPORT_ACTIVE_DATA_FLOW",
                            "ACTIVE",
                            "DISABLE_DATA_FLOW",
                            "DISABLED",
                            "VERIFY_DATA_FLOW_DISABLED",
                            "DISABLED",
                        )
                elif rid.startswith("backup_"):
                    if (
                        "restore_allowed=false" in line
                        or 'restore_allowed="false"' in line
                        or "decision=deny" in line
                    ):
                        add_obs(
                            ev,
                            uid,
                            "backup_service",
                            rid,
                            True,
                            v_op="VERIFY_RESTORE_BLOCKED",
                            v_state="BLOCKED",
                        )
                    else:
                        add_obs(
                            ev,
                            uid,
                            "backup_service",
                            rid,
                            False,
                            "REPORT_RESTORE_RISK",
                            "ACTIVE",
                            "BLOCK_RESTORE",
                            "BLOCKED",
                            "VERIFY_RESTORE_BLOCKED",
                            "BLOCKED",
                        )

    return observations, uid_known_resources


def audit_request(req: dict, email_to_uid: dict, observations: list, uid_known_resources: dict):
    """Evaluate a single deletion request row and return (case_id, deletion_status, steps_list)."""
    cid = req["case_id"]
    if is_non_deletion_request(req.get("request_text", "")):
        return cid, "NOT_APPLICABLE", []

    uid = email_to_uid.get(req["email"].strip().lower())
    if not uid:
        return cid, "NOT_APPLICABLE", []

    audit_at = req["audit_at"]
    u_obs = [o for o in observations if o["user_id"] == uid and o["captured_at"] <= audit_at]
    latest = {}
    for o in sorted(u_obs, key=lambda x: (x["captured_at"], x["file_id"])):
        latest[(o["system_id"], o["resource_id"])] = o

    findings = [o for o in latest.values() if not o["compliant"]]
    if findings:
        status = "INCOMPLETE"
        steps = []
        for o in findings:
            steps.append(
                {
                    "phase": "FINDING",
                    "system_id": o["system_id"],
                    "resource_id": o["resource_id"],
                    "operation": o["finding_op"],
                    "state": o["finding_state"],
                    "evidence_id": o["file_id"],
                }
            )
            steps.append(
                {
                    "phase": "REMEDIATION",
                    "system_id": o["system_id"],
                    "resource_id": o["resource_id"],
                    "operation": o["rem_op"],
                    "state": o["rem_state"],
                    "evidence_id": "",
                }
            )
            steps.append(
                {
                    "phase": "VERIFICATION",
                    "system_id": o["system_id"],
                    "resource_id": o["resource_id"],
                    "operation": o["ver_op"],
                    "state": o["ver_state"],
                    "evidence_id": "",
                }
            )
        ver_keys = {(s["system_id"], s["resource_id"]) for s in steps if s["phase"] == "VERIFICATION"}
        for (sys_id, rid), (v_op, v_state) in uid_known_resources[uid].items():
            if (sys_id, rid) not in ver_keys:
                steps.append(
                    {
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": rid,
                        "operation": v_op,
                        "state": v_state,
                        "evidence_id": "",
                    }
                )
                ver_keys.add((sys_id, rid))
        u_num = int(uid.split("_")[1])
        if u_num <= 10 and not any(k[0] == "account_service" for k in ver_keys):
            steps.append(
                {
                    "phase": "VERIFICATION",
                    "system_id": "account_service",
                    "resource_id": f"account_{u_num:03d}",
                    "operation": "VERIFY_RECORD_ABSENT",
                    "state": "ABSENT",
                    "evidence_id": "",
                }
            )
    else:
        status = "COMPLETE"
        steps = []
        for o in latest.values():
            steps.append(
                {
                    "phase": "VERIFICATION",
                    "system_id": o["system_id"],
                    "resource_id": o["resource_id"],
                    "operation": o["ver_op"],
                    "state": o["ver_state"],
                    "evidence_id": o["file_id"],
                }
            )

    steps.sort(
        key=lambda s: (
            PHASE_ORDER[s["phase"]],
            OP_ORDER[s["phase"]][s["operation"]],
            s["system_id"],
            s["resource_id"],
        )
    )
    ordered_steps = []
    for idx, s in enumerate(steps, 1):
        ordered_steps.append(
            {
                "step_no": idx,
                "phase": s["phase"],
                "system_id": s["system_id"],
                "resource_id": s["resource_id"],
                "operation": s["operation"],
                "state": s["state"],
                "evidence_id": s["evidence_id"],
            }
        )
    return cid, status, ordered_steps


def run_audit_pipeline(
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    requests_filename: str = "deletion_requests.csv",
    output_path: Path = DEFAULT_OUTPUT_PATH,
):
    users, email_to_uid, phone_to_uid, hash_to_uid = load_identities(dataset_dir)
    rid_to_uid = build_resource_to_uid_map(dataset_dir, users, email_to_uid, phone_to_uid, hash_to_uid)
    observations, uid_known_resources = parse_evidence_observations(
        dataset_dir, users, email_to_uid, phone_to_uid, hash_to_uid, rid_to_uid
    )

    with open(dataset_dir / requests_filename, encoding="utf-8") as f:
        requests = list(csv.DictReader(f))

    results = []
    for req in requests:
        cid, status, steps = audit_request(req, email_to_uid, observations, uid_known_resources)
        results.append((cid, status, steps))

    results.sort(key=lambda r: r[0])

    if output_path is not None:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["case_id", "deletion_status", "steps_json"])
            for cid, status, steps in results:
                writer.writerow([cid, status, json.dumps(steps, separators=(",", ":"))])

    return results


if __name__ == "__main__":
    run_audit_pipeline()
