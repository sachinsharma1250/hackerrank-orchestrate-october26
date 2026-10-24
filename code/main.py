import csv
import json
import re
import zipfile
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
EVIDENCE = DATA / "evidence"
OUT = ROOT / "output.csv"
STEPS_FIELDS = [
    "step_no", "phase", "system_id", "resource_id",
    "operation", "state", "evidence_id"
]

def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

def pick(row, *names, default=""):
    normalized = {str(k).strip().lower(): v for k, v in row.items()}
    for name in names:
        if normalized.get(name.lower()) not in (None, ""):
            return str(normalized[name.lower()]).strip()
    return default

def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None

def norm(value):
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()

def read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""

def build_manifest():
    path = DATA / "evidence_files.csv"
    if not path.exists():
        return []
    return read_csv(path)

def evidence_id_from_name(path, manifest):
    relative = str(path.relative_to(DATA)).replace("\\", "/")
    for row in manifest:
        manifest_path = pick(row, "file_path").replace("\\", "/").lstrip("./")
        if manifest_path == relative or Path(manifest_path).name == path.name:
            return pick(row, "file_id")
    m = re.search(r"evidence[_-]?(\d+)", path.name, re.I)
    return f"evidence_{int(m.group(1)):02d}" if m else ""

def collect_evidence(manifest):
    records = []
    by_path = {
        pick(row, "file_path").replace("\\", "/").lstrip("./"): row
        for row in manifest
    }

    for path in sorted(EVIDENCE.rglob("*")):
        if not path.is_file():
            continue

        text = read_text(path)
        if not text:
            continue

        relative = str(path.relative_to(DATA)).replace("\\", "/")
        row = by_path.get(relative, {})
        eid = pick(row, "file_id") or evidence_id_from_name(path, manifest)

        # The manifest capture time is authoritative.
        captured = parse_time(pick(row, "captured_at"))

        records.append({
            "id": eid,
            "path": path,
            "text": text,
            "lower": text.lower(),
            "captured": captured
        })

    return records

def get_subject(case, identities, audit_rows):
    email = norm(pick(case, "email"))
    aliases = {email} if email else set()
    user_ids = set()
    resource_ids = set()

    for row in identities:
        row_email = norm(pick(row, "email", "current_email", "identity_email"))
        if email and row_email == email:
            uid = pick(row, "user_id", "identity_id", "customer_id")
            if uid:
                user_ids.add(uid)
            for key in ("account_id", "profile_id", "customer_id",
                        "export_id", "analytics_id"):
                value = pick(row, key)
                if value:
                    resource_ids.add(value)
            for key in ("email", "old_email", "previous_email", "phone",
                        "email_hash", "user_id", "account_id"):
                value = norm(pick(row, key))
                if value:
                    aliases.add(value)

    # Historical identity values may connect a former email to a user.
    changed = True
    while changed:
        changed = False
        for row in audit_rows:
            uid = pick(row, "user_id", "subject_user_id", "identity_id")
            old = norm(pick(row, "old_value", "previous_value", "old_email",
                            "previous_email", "before_value"))
            new = norm(pick(row, "new_value", "current_value", "new_email",
                            "after_value"))
            field = norm(pick(row, "field", "field_name", "attribute", "event_type"))
            identity_field = any(x in field for x in
                                 ("email", "identity", "user", "account", "phone"))
            if uid and (uid in user_ids or old in aliases or new in aliases):
                if uid not in user_ids:
                    user_ids.add(uid)
                    changed = True
                if identity_field:
                    for value in (old, new):
                        if value and value not in aliases:
                            aliases.add(value)
                            changed = True
            if uid in user_ids:
                for key in ("resource_id", "account_id", "profile_id",
                            "export_id", "analytics_id", "record_id"):
                    value = pick(row, key)
                    if value:
                        resource_ids.add(value)

    return aliases, user_ids, resource_ids

def is_deletion_request(case):
    text = norm(pick(case, "request_text", "request", "description", "message"))

    # Explicit requests to keep, change, export, or recover an account
    # are not deletion requests.
    non_deletion = [
        r"\bdownload\b",
        r"\breset(?:ting)? (?:the )?(?:login|password)\b",
        r"\b(?:change|replace|correct|update)\b.{0,50}\b(?:email|surname|phone|mobile number)\b",
        r"\bwithout removing\b",
        r"\bdo not close\b",
        r"\bleave the account active\b",
        r"\bcontinue using the service\b",
        r"\bleave my profile\b",
        r"\bkeep the account as it is\b",
    ]
    if any(re.search(p, text, re.I) for p in non_deletion):
        return False

    deletion = [
        r"\bdelete\b",
        r"\bdeleted\b",
        r"\bdeletion\b",
        r"\berase\b",
        r"\berased\b",
        r"\berasure\b",
        r"\bremove\b",
        r"\bremoval\b",
        r"\bpermanently deleted\b",
        r"\bpermanent(?:ly)? account[- ]deletion\b",
        r"\bclose (?:this|my|the) account\b",
        r"\baccount associated with .{0,80} erased\b",
        r"\baccount linked to .{0,80} erased\b",
        r"\bpersonal data deleted\b",
        r"\bpersonal information\b.{0,80}\bdeleted\b",
        r"\bdata deletion\b",
        r"eliminaci[oó]n|eliminar|borrar|suprimir",
        r"exclus[aã]o|excluir|apagar",
        r"suppression|supprimer|effacer",
        r"l[oö]schen|l[oö]schung",
        r"削除|消去|삭제|删除|刪除",
        r"удалить|удаление|حذف|डिलीट|हटा दो",
    ]
    return any(re.search(p, text, re.I) for p in deletion)

def before_audit(ev, audit_time):
    if not audit_time:
        return False
    if not ev["captured"]:
        # A file without trustworthy capture time cannot prove the state
        # at the audit deadline.
        return False
    try:
        return ev["captured"] <= audit_time
    except TypeError:
        return False

def resource_ids_in_text(text):
    patterns = [
        r"\b(?:account|profile|export|analytics|support|search|audit|"
        r"record|data_flow|flow|backup|replica|restore|ticket|message)"
        r"[_-]?\d{2,}\b",
        r"\buser[_-]\d+\b",
    ]
    found = []
    for pattern in patterns:
        found.extend(re.findall(pattern, text, re.I))
    return list(dict.fromkeys(found))




def identity_records(text, aliases, audit_time):
    """Return resource records whose own data contains a matching identity."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []

    aliases = {norm(a) for a in aliases if a and len(norm(a)) >= 5}
    found = []
    identity_keys = {
        "email", "requester_email", "customer_email", "owner_email",
        "current_email", "old_email", "previous_email", "phone",
        "user_id", "subject_reference", "customer_reference",
        "email_hash", "lookup_value", "identity_reference",
        "requester_id", "owner_id", "subject_selector"
    }
    resource_keys = {"resource_id", "record_id", "id"}
    time_keys = ("recorded_at", "timestamp", "event_time", "created_at")

    def contains_identity(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key.lower() in identity_keys and value not in (None, ""):
                    if norm(value) in aliases:
                        return True
                if isinstance(value, (dict, list)) and contains_identity(value):
                    return True
        elif isinstance(obj, list):
            return any(contains_identity(item) for item in obj)
        return False

    def walk(obj):
        if isinstance(obj, dict):
            # Return the nearest resource-bearing object when its own subtree
            # contains the requested identity, including nested document data.
            has_resource = any(
                obj.get(key) not in (None, "")
                for key in resource_keys
            )
            if has_resource and contains_identity(obj):
                recorded = parse_time(pick(obj, *time_keys))
                if recorded is None:
                    if audit_time is not None:
                        found.append(obj)
                else:
                    try:
                        if audit_time is not None and recorded <= audit_time:
                            found.append(obj)
                    except TypeError:
                        pass
                return

            for value in obj.values():
                walk(value)

        elif isinstance(obj, list):
            for value in obj:
                walk(value)

    walk(data)

    # Deduplicate records that may appear more than once in the same JSON file.
    unique = {}
    for record in found:
        key = (
            str(pick(record, "resource_id", "record_id", "id")),
            json.dumps(record, sort_keys=True, default=str)
        )
        unique[key] = record
    return list(unique.values())

def sql_records(text):
    """Read structured records from SQLite-compatible SQL snapshots."""
    import sqlite3

    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(text)
        records = []

        for table in ("customer_data_primary", "customer_data_read_replica"):
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,)
            ).fetchone()
            if not exists:
                continue

            columns = {
                row[1] for row in conn.execute(
                    f'PRAGMA table_info("{table}")'
                )
            }
            required = {
                "resource_id", "origin_system", "collection_name",
                "record_json", "updated_at"
            }
            if not required.issubset(columns):
                continue

            query = (
                f'SELECT resource_id, origin_system, collection_name, '
                f'record_json, updated_at FROM "{table}"'
            )
            for resource_id, system, collection, payload, updated_at in conn.execute(query):
                try:
                    record = json.loads(payload)
                except (ValueError, TypeError):
                    continue

                if not isinstance(record, dict):
                    continue

                record.setdefault("resource_id", resource_id)
                record["_origin_system"] = system
                record["_collection_name"] = collection
                record["_source_table"] = table
                record["recorded_at"] = updated_at
                records.append(record)

        return records
    except sqlite3.Error as exc:
        print(f"SQL evidence parse warning: {exc}")
        return []
    finally:
        conn.close()


def classify_record(record):
    """Classify structured evidence using explicit resource fields."""
    result = norm(pick(record, "result", "status", "state", "outcome")).upper()
    rtype = norm(pick(record, "record_type", "resource_type", "type")).upper()

    # Explicit result fields take precedence.
    if result in {"NOT_FOUND", "ABSENT", "DELETED", "HTTP 404"}:
        return "ABSENT"
    if result in {"ANONYMIZED", "ANONYMISED"}:
        return "ANONYMIZED"
    if result in {"REDACTED", "MASKED"}:
        return "REDACTED"
    if result == "DISABLED":
        return "DISABLED"
    if result == "BLOCKED":
        return "BLOCKED"

    if result in {"FOUND", "PRESENT", "IDENTIFIABLE", "ACTIVE"}:
        if rtype in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
            return "RETAINED"
        return "PRESENT"

    # Resource-specific fields in snapshot records.
    restore_allowed = norm(pick(record, "restore_allowed")).lower()
    if restore_allowed in {"false", "0", "no"}:
        return "BLOCKED"
    if restore_allowed in {"true", "1", "yes"}:
        return "PRESENT"

    enabled = norm(pick(record, "enabled")).lower()
    if enabled in {"false", "0", "no"}:
        return "DISABLED"
    if enabled in {"true", "1", "yes"}:
        return "ACTIVE_FLOW"

    message = norm(pick(record, "message_text"))
    if "[redacted]" in message or "[REDACTED]".lower() in message:
        return "REDACTED"

    # An audit event is not proof that data has been deleted.
    if rtype in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
        return "RETAINED"

    return "UNKNOWN"

def state_for_evidence(text):
    """Fallback classifier for line-level text evidence only."""
    low = text.lower()
    if any(x in low for x in ("not found", "rows=0", "rows = 0",
                              "http 404", "status=404", "state=absent")):
        return "ABSENT"
    if "anonymized" in low or "anonymised" in low:
        return "ANONYMIZED"
    if "redacted" in low:
        return "REDACTED"
    return "PRESENT"


def make_step(n, phase, system, resource, operation, state, eid=""):
    return {
        "step_no": n, "phase": phase, "system_id": system or "unknown",
        "resource_id": resource or "unknown", "operation": operation,
        "state": state, "evidence_id": eid
    }

def main():
    requests_path = DATA / "deletion_requests.csv"
    if not requests_path.exists():
        raise SystemExit(f"Missing {requests_path}")

    requests = read_csv(requests_path)
    identities = []
    for name in ("user_identities.csv", "user_identity.csv", "identities.csv"):
        if (DATA / name).exists():
            identities = read_csv(DATA / name)
            break

    audit_rows = []
    for name in ("user_audit_log.csv", "user_audit_logs.csv", "identity_audit_log.csv"):
        if (DATA / name).exists():
            audit_rows = read_csv(DATA / name)
            break

    manifest = build_manifest()
    evidence = collect_evidence(manifest)
    output = []

    for case in requests:
        cid = pick(case, "case_id", "id")
        audit_time = parse_time(pick(case, "audit_at"))
        aliases, user_ids, known_resources = get_subject(case, identities, audit_rows)

        if not is_deletion_request(case):
            output.append({
                "case_id": cid, "deletion_status": "NOT_APPLICABLE",
                "steps_json": "[]"
            })
            continue


        steps = []
        # Keep only the latest explicit state per resource as of audit time.
        latest = {}
        for ev in evidence:
            if not before_audit(ev, audit_time):
                continue
            suffix = ev["path"].suffix.lower()

            if suffix == ".json":
                records = identity_records(ev["text"], aliases, audit_time)
            elif suffix == ".sql":
                records = []
                for sql_record in sql_records(ev["text"]):
                    updated = parse_time(pick(sql_record, "recorded_at"))
                    if updated is not None:
                        try:
                            if updated > audit_time:
                                continue
                        except TypeError:
                            continue
                    matched = identity_records(
                        json.dumps(sql_record), aliases, audit_time
                    )
                    records.extend(matched)
            else:
                continue

            for record in records:
                resource = pick(record, "resource_id", "record_id", "id")
                if not resource:
                    continue

                recorded = parse_time(pick(record, "recorded_at", "timestamp",
                                           "event_time", "created_at"))
                rtype = pick(
                    record, "record_type", "resource_type", "type",
                    "_collection_name"
                )
                system = pick(
                    record, "system", "system_id", "_origin_system"
                ) or ev["path"].parent.name
                state = classify_record(record)

                # If the same resource appears more than once, prefer the
                # newest record timestamp; manifest capture time breaks ties.
                source_table = pick(record, "_source_table") or "json"
                rank = (recorded or ev["captured"], ev["captured"])
                state = classify_record(record)
                system = pick(
                    record, "system", "system_id", "_origin_system"
                ) or ev["path"].parent.name
                rtype = pick(
                    record, "record_type", "resource_type", "type",
                    "_collection_name"
                )

                # Merge exact primary/replica copies, not conflicting records.
                signature = (
                    resource, system, rtype, state, recorded,
                    json.dumps(
                        {k: v for k, v in record.items()
                         if k not in {"_source_table"}},
                        sort_keys=True, ensure_ascii=False
                    )
                )
                key = resource
                old = latest.get(key)
                if old is None or rank >= old["rank"]:
                    latest[key] = {
                        "rank": rank, "resource": resource, "system": system,
                        "type": rtype, "state": state, "evidence": ev["id"]
                    }

        unresolved = False
        for item in latest.values():
            state = item["state"]
            resource = item["resource"]
            system = item["system"]
            eid = item["evidence"]
            rtype = norm(item["type"]).upper()

            if state == "ABSENT":
                operation, phase, step_state = "VERIFY_RECORD_ABSENT", "VERIFICATION", "ABSENT"
            elif state == "ANONYMIZED":
                operation, phase, step_state = "VERIFY_RECORD_ANONYMIZED", "VERIFICATION", "ANONYMIZED"
            elif state == "REDACTED":
                operation, phase, step_state = "VERIFY_RECORD_REDACTED", "VERIFICATION", "REDACTED"
            elif state == "DISABLED":
                operation, phase, step_state = "VERIFY_DATA_FLOW_DISABLED", "VERIFICATION", "DISABLED"
            elif state == "BLOCKED":
                operation, phase, step_state = "VERIFY_RESTORE_BLOCKED", "VERIFICATION", "BLOCKED"
            elif state == "RETAINED":
                operation, phase, step_state = "VERIFY_RETAINED_BY_RULE", "VERIFICATION", "RETAINED"
            else:
                operation, phase, step_state = "REPORT_REMAINING_RECORD", "FINDING", state
                unresolved = True

            steps.append(make_step(
                len(steps) + 1, phase, system, resource,
                operation, step_state, eid
            ))

        # A case with no matching evidence is not proof of deletion.
        # Any explicit unresolved record prevents COMPLETE.
        verified = any(
            s["phase"] == "VERIFICATION"
            and s["operation"] in {
                "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_REDACTED",
                "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED",
                "VERIFY_RESTORE_BLOCKED"
            }
            for s in steps
        )
        status = "COMPLETE" if verified and not unresolved else "INCOMPLETE"

        for i, step in enumerate(steps, 1):
            step["step_no"] = i

        output.append({
            "case_id": cid,
            "deletion_status": status,
            "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))
        })

    output.sort(key=lambda r: r["case_id"])
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["case_id", "deletion_status", "steps_json"]
        )
        writer.writeheader()
        writer.writerows(output)

    # Basic schema/sequence checks.
    valid_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    errors = []
    for row in output:
        if row["deletion_status"] not in valid_statuses:
            errors.append(f"{row['case_id']}: invalid status")
        try:
            steps = json.loads(row["steps_json"])
            if not isinstance(steps, list):
                errors.append(f"{row['case_id']}: steps_json is not an array")
                continue
            for i, step in enumerate(steps, 1):
                if set(step) != set(STEPS_FIELDS):
                    errors.append(f"{row['case_id']}: wrong step fields")
                if step.get("step_no") != i:
                    errors.append(f"{row['case_id']}: non-contiguous step_no")
        except json.JSONDecodeError:
            errors.append(f"{row['case_id']}: invalid JSON")

    counts = {}
    for row in output:
        counts[row["deletion_status"]] = counts.get(row["deletion_status"], 0) + 1

    eval_dir = ROOT / "code" / "evaluation"
    eval_dir.mkdir(parents=True, exist_ok=True)
    (eval_dir / "evaluation_report.md").write_text(
        "# Evaluation Report\n\n"
        "This is a deterministic evidence-matching baseline, not a verified "
        "ground-truth solver.\n\n"
        f"- Input cases: {len(requests)}\n"
        f"- Output rows: {len(output)}\n"
        f"- Status counts: `{json.dumps(counts, sort_keys=True)}`\n"
        f"- Schema/sequence errors: {len(errors)}\n"
        f"- Custom checks: request classification; evidence cutoff; JSON schema; "
        "contiguous step numbering.\n\n"
        "## Limitations\n\n"
        "- Evidence association relies on literal identity aliases in readable "
        "evidence text; binary/image evidence is not OCR-processed.\n"
        "- A resource-level state may require cross-system correlation or "
        "policy interpretation not captured by this baseline.\n"
        "- Missing evidence is not treated as proof of deletion.\n"
        "- Review false positives/negatives before submission.\n\n"
        "## Validation Errors\n\n" +
        ("\n".join(f"- {e}" for e in errors) if errors else "- None found.")
        + "\n",
        encoding="utf-8"
    )
    (eval_dir / "usage_report.md").write_text(
        "# Model Usage Report\n\n"
        "- Provider: None\n- Model: None\n- Model calls: 0\n"
        "- Input tokens: 0\n- Output tokens: 0\n- Estimated model cost: $0.00\n\n"
        "The solution runs locally with Python and does not call a hosted model.\n",
        encoding="utf-8"
    )

    archive = ROOT / "code.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for path in [ROOT / "README.md", ROOT / "code"]:
            if path.is_file():
                z.write(path, path.relative_to(ROOT))
            elif path.exists():
                for child in path.rglob("*"):
                    if not child.is_file():
                        continue
                    if any(part in {".git", "__pycache__", ".venv", "venv"} for part in child.parts):
                        continue
                    z.write(child, child.relative_to(ROOT))

    print(f"Output: {OUT}")
    print(f"Rows: {len(output)}")
    print(f"Status counts: {counts}")
    print(f"Validation errors: {len(errors)}")
    print(f"Archive: {archive}")
    if errors:
        raise SystemExit("Validation failed; review code/evaluation/evaluation_report.md")

if __name__ == "__main__":
    main()
