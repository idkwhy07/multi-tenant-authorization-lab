"""
Umber Desk 12 -- toy reference implementation for the synthetic case study
"One Authorization Assessment, Five Failures".

WHY THIS EXISTS
----------------
The blog post describes fictional HTTP traffic. This file is a real, running
server that reproduces the exact same requests and responses, so you can
capture real traffic with curl or Burp instead of hand-writing it.

DELIBERATE SIMPLIFICATIONS (all noted so you know they are not the point)
---------------------------------------------------------------------------
- In-memory dict storage, no real database. Restarting the process resets
  everything. Use POST /api/v1/_reset to reset without restarting.
- No real JWT / bearer tokens -- session cookies are opaque strings mapped
  directly to a fixed set of 6 users.
- The export "worker" runs synchronously inside the request instead of on a
  queue. The authorization logic is identical to a real async worker; only
  the transport is simplified.
- Runs plain HTTP/1.1 (the Flask dev server does not speak HTTP/2). If you
  captured traffic showing HTTP/2 anywhere, replace it with HTTP/1.1.

TOGGLE
------
VULNERABLE_MODE = True   -> reproduces Tests 1-5 (the five findings)
VULNERABLE_MODE = False  -> reproduces the "After repair" column of the
                             retest table (Secure redesign applied)

RUN
---
    pip install flask --break-system-packages
    python app.py

Then log in as any of the 6 fixture users and replay the requests from the
case study. See USERS below for emails/passwords/sessions.
"""

from dataclasses import dataclass
from enum import StrEnum
from itertools import count

from flask import Flask, request, jsonify, make_response

VULNERABLE_MODE = False  # flip to False to reproduce the corrected build

app = Flask(__name__)


class Role(StrEnum):
    ANALYST = "analyst"
    MANAGER = "manager"
    OWNER = "owner"


# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

USERS = {
    # user_id: (display_name, email, password, session_token)
    "usr_01": ("Emma Carter", "emma.carter@meldran.test", "fixture-password", "sess_ec_1"),
    "usr_02": ("Daniel Reed", "daniel.reed@meldran.test", "fixture-password", "sess_dr_1"),
    "usr_03": ("Ben Miller", "ben.miller@meldran.test", "fixture-password", "sess_bm_1"),
    "usr_04": ("Alex Turner", "alex.turner@meldran.test", "fixture-password", "sess_at_1"),
    "usr_05": ("Maya Collins", "maya.collins@ternwick.test", "fixture-password", "sess_mc_1"),
    "usr_06": ("Leo Foster", "leo.foster@ternwick.test", "fixture-password", "sess_lf_1"),
}


def seed() -> dict:
    return {
        "organizations": {
            "org_01": {"id": "org_01", "name": "Meldran Biomedical Works"},
            "org_02": {"id": "org_02", "name": "Ternwick Transit Cooperative"},
        },
        "memberships": {
            "usr_01": [{"organization_id": "org_01", "role": Role.OWNER, "state": "active"}],
            "usr_02": [{"organization_id": "org_01", "role": Role.MANAGER, "state": "active"}],
            "usr_03": [{"organization_id": "org_01", "role": Role.ANALYST, "state": "active"}],
            "usr_04": [{"organization_id": "org_01", "role": Role.ANALYST, "state": "active"}],
            "usr_05": [{"organization_id": "org_02", "role": Role.OWNER, "state": "active"}],
            "usr_06": [{"organization_id": "org_02", "role": Role.ANALYST, "state": "active"}],
        },
        "cases": {
            "case_01": {"id": "case_01", "organization_id": "org_01", "title": "Valve Recall Review",
                        "assigned_analyst_id": "usr_03", "summary": "Review opened.", "version": 1},
            "case_02": {"id": "case_02", "organization_id": "org_01", "title": "Sterility Audit",
                        "assigned_analyst_id": "usr_04", "summary": "Audit opened.", "version": 1},
            "case_03": {"id": "case_03", "organization_id": "org_02", "title": "Brake Sensor Certification",
                        "assigned_analyst_id": "usr_06", "summary": "Certification evidence pending.", "version": 1},
        },
        "notes": {
            "note_01": {"id": "note_01", "organization_id": "org_01", "case_id": "case_01", "owner_id": "usr_03",
                        "title": "Valve lot inspection", "body": "Initial inspection recorded.",
                        "review_status": "draft", "status_changed_by": None, "version": 1},
            "note_02": {"id": "note_02", "organization_id": "org_01", "case_id": "case_02", "owner_id": "usr_04",
                        "title": "Sterility lot review", "body": "Lot 7 requires a second sample.",
                        "review_status": "draft", "status_changed_by": None, "version": 1},
            "note_03": {"id": "note_03", "organization_id": "org_02", "case_id": "case_03", "owner_id": "usr_06",
                        "title": "Brake sensor note", "body": "Awaiting calibration log.",
                        "review_status": "draft", "status_changed_by": None, "version": 1},
        },
        "evidence": {
            "evidence_01": {"id": "evidence_01", "organization_id": "org_01", "case_id": "case_01",
                             "label": "Valve lot photograph", "sha256": "fixture-evidence-01", "version": 1},
            "evidence_02": {"id": "evidence_02", "organization_id": "org_01", "case_id": "case_02",
                             "label": "Sterility sample manifest", "sha256": "fixture-evidence-02", "version": 1},
            "evidence_03": {"id": "evidence_03", "organization_id": "org_02", "case_id": "case_03",
                             "label": "Brake sensor calibration log", "sha256": "fixture-evidence-03", "version": 1},
        },
        "export_jobs": {},
        "audit_events": [],
        "job_counter": count(1),
        "event_counter": count(1),
        "request_counter": count(1),
    }


DB = seed()
SESSIONS = {token: user_id for user_id, (_, _, _, token) in USERS.items()}
EMAIL_TO_USER = {email: user_id for user_id, (_, email, _, _) in USERS.items()}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def current_user_id() -> str | None:
    token = request.cookies.get("umberdesk12_session")
    return SESSIONS.get(token)


def active_membership(user_id: str, organization_id: str) -> dict | None:
    for m in DB["memberships"].get(user_id, []):
        if m["organization_id"] == organization_id and m["state"] == "active":
            return m
    return None


def can_read_evidence(user_id: str, evidence: dict) -> bool:
    membership = active_membership(user_id, evidence["organization_id"])
    if membership is None:
        return False
    if membership["role"] in (Role.MANAGER, Role.OWNER):
        return True
    case = DB["cases"].get(evidence["case_id"])
    return case is not None and case["assigned_analyst_id"] == user_id


def audit_write(org_id: str, action: str, resource_id: str, job_id: str, actor_user_id: str) -> None:
    event_id = f"event_{next(DB['event_counter']):02d}"
    actor_memberships = DB["memberships"].get(actor_user_id, [])
    actor_org = actor_memberships[0]["organization_id"] if actor_memberships else None
    DB["audit_events"].append({
        "id": event_id, "organization_id": org_id, "action": action,
        "resource_id": resource_id, "job_id": job_id,
        "actor_user_id": actor_user_id, "actor_organization_id": actor_org,
    })


def problem(status: int, title: str):
    slug = title.lower().replace(" ", "-")
    resp = jsonify({"type": f"https://api.umber-desk-12.test/problems/{slug}", "title": title, "status": status})
    resp.status_code = status
    resp.headers["Content-Type"] = "application/problem+json"
    return resp


def etag(prefix: str, version: int) -> str:
    return f'"{prefix}-v{version}"'


@app.after_request
def add_request_id(resp):
    resp.headers["X-Request-Id"] = f"req_{next(DB['request_counter']):02d}"
    return resp


def serialize(obj: dict) -> dict:
    return {k: (v.value if isinstance(v, Role) else v) for k, v in obj.items()}


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

@app.route("/api/v1/session", methods=["POST"])
def login():
    body = request.get_json(force=True, silent=True) or {}
    user_id = EMAIL_TO_USER.get(body.get("email", ""))
    if user_id is None or body.get("password") != USERS[user_id][2]:
        return problem(401, "Unauthorized")
    token = USERS[user_id][3]
    resp = make_response(jsonify({"user_id": user_id, "session_state": "fully_authenticated"}), 201)
    resp.set_cookie("umberdesk12_session", token, httponly=True, samesite="Lax")
    return resp


@app.route("/api/v1/me", methods=["GET"])
def me():
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    memberships = [{"organization_id": m["organization_id"], "role": m["role"].value, "state": m["state"]}
                   for m in DB["memberships"][user_id]]
    return jsonify({"user_id": user_id, "display_name": USERS[user_id][0], "memberships": memberships})


# ---------------------------------------------------------------------------
# Notes -- F-01 (ownership) and F-02 (mass assignment)
# ---------------------------------------------------------------------------

@app.route("/api/v1/notes/<note_id>", methods=["GET"])
def read_note(note_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    note = DB["notes"].get(note_id)
    if note is None:
        return problem(404, "Not Found")
    membership = active_membership(user_id, note["organization_id"])
    if membership is None:
        return problem(404, "Not Found")

    if VULNERABLE_MODE:
        allowed = True  # F-01: membership checked, ownership is not
    else:
        allowed = membership["role"] in (Role.MANAGER, Role.OWNER) or note["owner_id"] == user_id

    if not allowed:
        return problem(404, "Not Found")

    resp = jsonify(serialize(note))
    resp.headers["ETag"] = etag(note_id, note["version"])
    return resp


@app.route("/api/v1/notes/<note_id>", methods=["PATCH"])
def update_note(note_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    note = DB["notes"].get(note_id)
    if note is None:
        return problem(404, "Not Found")
    membership = active_membership(user_id, note["organization_id"])
    if membership is None:
        return problem(404, "Not Found")

    is_owner = note["owner_id"] == user_id
    is_privileged = membership["role"] in (Role.MANAGER, Role.OWNER)
    if not (is_owner or is_privileged):
        return problem(403, "Forbidden")

    if_match = request.headers.get("If-Match")
    if if_match and if_match != etag(note_id, note["version"]):
        return problem(412, "Precondition Failed")

    body = request.get_json(force=True, silent=True) or {}

    if VULNERABLE_MODE:
        # F-02: entire body bound to the model, review_status not allowlisted
        if "title" in body:
            note["title"] = body["title"]
        if "body" in body:
            note["body"] = body["body"]
        if "review_status" in body:
            note["review_status"] = body["review_status"]
            note["status_changed_by"] = user_id
    else:
        writable = {"title", "body"}
        privileged = {"review_status"}
        for key in body:
            if key in privileged and not is_privileged:
                return problem(422, "Unprocessable Entity")
            if key not in writable | privileged:
                return problem(422, "Unprocessable Entity")
        if "title" in body:
            note["title"] = body["title"]
        if "body" in body:
            note["body"] = body["body"]
        if "review_status" in body and is_privileged:
            note["review_status"] = body["review_status"]
            note["status_changed_by"] = user_id

    note["version"] += 1
    resp = jsonify(serialize(note))
    resp.headers["ETag"] = etag(note_id, note["version"])
    return resp


@app.route("/api/v1/review-queue/notes/<note_id>", methods=["GET"])
def review_queue_note(note_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    note = DB["notes"].get(note_id)
    if note is None:
        return problem(404, "Not Found")
    membership = active_membership(user_id, note["organization_id"])
    if membership is None or membership["role"] not in (Role.MANAGER, Role.OWNER):
        return problem(403, "Forbidden")
    resp = jsonify({
        "id": note["id"], "organization_id": note["organization_id"],
        "review_status": note["review_status"], "status_changed_by": note["status_changed_by"],
        "version": note["version"],
    })
    resp.headers["ETag"] = etag(note_id, note["version"])
    return resp


# ---------------------------------------------------------------------------
# Cases -- F-03 (tenant scope) and batch read
# ---------------------------------------------------------------------------

@app.route("/api/v1/manager/cases/<case_id>", methods=["GET"])
def manager_read_case(case_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    case = DB["cases"].get(case_id)
    if case is None:
        return problem(404, "Not Found")

    manager_memberships = [m for m in DB["memberships"][user_id]
                            if m["role"] in (Role.MANAGER, Role.OWNER) and m["state"] == "active"]
    if not manager_memberships:
        return problem(403, "Forbidden")

    if VULNERABLE_MODE:
        allowed = True  # F-03: role checked, tenant scope is not
    else:
        allowed = any(m["organization_id"] == case["organization_id"] for m in manager_memberships)

    if not allowed:
        return problem(404, "Not Found")

    resp = jsonify(serialize(case))
    resp.headers["ETag"] = etag(case_id, case["version"])
    return resp


@app.route("/api/v1/manager/cases/batch", methods=["POST"])
def batch_read_cases():
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    body = request.get_json(force=True, silent=True) or {}
    case_ids = body.get("case_ids", [])
    manager_memberships = [m for m in DB["memberships"][user_id]
                            if m["role"] in (Role.MANAGER, Role.OWNER) and m["state"] == "active"]
    if not manager_memberships:
        return problem(403, "Forbidden")
    manager_org_ids = {m["organization_id"] for m in manager_memberships}

    cases = []
    for cid in case_ids:
        case = DB["cases"].get(cid)
        if case is None or case["organization_id"] not in manager_org_ids:
            return problem(403, "Forbidden")  # fail closed: one bad ID denies the whole batch
        cases.append(serialize(case))
    return jsonify({"cases": cases})


@app.route("/api/v1/cases/<case_id>", methods=["PATCH"])
def update_case(case_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    case = DB["cases"].get(case_id)
    if case is None:
        return problem(404, "Not Found")
    membership = active_membership(user_id, case["organization_id"])
    if membership is None or membership["role"] not in (Role.MANAGER, Role.OWNER):
        return problem(403, "Forbidden")

    if_match = request.headers.get("If-Match")
    if if_match and if_match != etag(case_id, case["version"]):
        return problem(412, "Precondition Failed")

    body = request.get_json(force=True, silent=True) or {}
    if "summary" in body:
        case["summary"] = body["summary"]
    case["version"] += 1
    resp = jsonify(serialize(case))
    resp.headers["ETag"] = etag(case_id, case["version"])
    return resp


# ---------------------------------------------------------------------------
# Evidence -- F-04 (nested relationship) and the correctly-scoped direct route
# ---------------------------------------------------------------------------

@app.route("/api/v1/orgs/<org_id>/cases/<case_id>/evidence/<evidence_id>", methods=["GET"])
def nested_evidence_read(org_id, case_id, evidence_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    case = DB["cases"].get(case_id)
    if case is None or case["organization_id"] != org_id:
        return problem(404, "Not Found")
    membership = active_membership(user_id, org_id)
    if membership is None:
        return problem(404, "Not Found")
    if membership["role"] == Role.ANALYST and case["assigned_analyst_id"] != user_id:
        return problem(404, "Not Found")

    evidence = DB["evidence"].get(evidence_id)
    if evidence is None:
        return problem(404, "Not Found")

    if VULNERABLE_MODE:
        allowed = evidence["organization_id"] == org_id  # F-04: case_id relationship not checked
    else:
        allowed = evidence["organization_id"] == org_id and evidence["case_id"] == case_id

    if not allowed:
        return problem(404, "Not Found")

    resp = jsonify(serialize(evidence))
    resp.headers["ETag"] = etag(evidence_id, evidence["version"])
    return resp


@app.route("/api/v1/orgs/<org_id>/cases/<case_id>/evidence/<evidence_id>", methods=["PATCH"])
def nested_evidence_update(org_id, case_id, evidence_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    case = DB["cases"].get(case_id)
    if case is None or case["organization_id"] != org_id:
        return problem(404, "Not Found")
    membership = active_membership(user_id, org_id)
    if membership is None:
        return problem(404, "Not Found")
    if membership["role"] == Role.ANALYST and case["assigned_analyst_id"] != user_id:
        return problem(403, "Forbidden")

    # the update path is always correctly scoped, in both modes
    evidence = DB["evidence"].get(evidence_id)
    if evidence is None or evidence["organization_id"] != org_id or evidence["case_id"] != case_id:
        return problem(404, "Not Found")

    if_match = request.headers.get("If-Match")
    if if_match and if_match != etag(evidence_id, evidence["version"]):
        return problem(412, "Precondition Failed")

    body = request.get_json(force=True, silent=True) or {}
    if "label" in body:
        evidence["label"] = body["label"]
    evidence["version"] += 1
    resp = jsonify(serialize(evidence))
    resp.headers["ETag"] = etag(evidence_id, evidence["version"])
    return resp


@app.route("/api/v1/evidence/<evidence_id>", methods=["GET"])
def direct_evidence_read(evidence_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    evidence = DB["evidence"].get(evidence_id)
    if evidence is None:
        return problem(404, "Not Found")
    if not can_read_evidence(user_id, evidence):
        return problem(403, "Forbidden")
    resp = jsonify(serialize(evidence))
    resp.headers["ETag"] = etag(evidence_id, evidence["version"])
    return resp


# ---------------------------------------------------------------------------
# GraphQL -- always correctly scoped; used as the F-05 contrast, not a bug
# ---------------------------------------------------------------------------

@app.route("/api/v1/graphql", methods=["POST"])
def graphql():
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    body = request.get_json(force=True, silent=True) or {}
    evidence_id = (body.get("variables") or {}).get("evidenceId")
    evidence = DB["evidence"].get(evidence_id)
    if evidence is None:
        return jsonify({"data": {"evidence": None}})
    if not can_read_evidence(user_id, evidence):
        return jsonify({"data": {"evidence": None}, "errors": [{"message": "Forbidden"}]})
    return jsonify({"data": {"evidence": serialize(evidence)}})


# ---------------------------------------------------------------------------
# Exports -- F-05 (indirect path / worker re-authorization)
# ---------------------------------------------------------------------------

@app.route("/api/v1/exports", methods=["POST"])
def create_export():
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    body = request.get_json(force=True, silent=True) or {}
    if body.get("source_type") != "evidence":
        return problem(400, "Bad Request")
    evidence = DB["evidence"].get(body.get("source_id"))
    if evidence is None:
        return problem(404, "Not Found")

    if not VULNERABLE_MODE and not can_read_evidence(user_id, evidence):
        # F-05 fixed: authorized before a job is ever queued -- no job created
        return problem(403, "Forbidden")

    job_id = f"job_{next(DB['job_counter']):02d}"
    job = {"job_id": job_id, "state": "queued", "source_id": evidence["id"],
           "actor_user_id": user_id, "version": 1}
    DB["export_jobs"][job_id] = job

    # Synchronous stand-in for an async worker. Vulnerable build trusts the
    # queued job; fixed build re-authorizes against current state.
    worker_authorized = True if VULNERABLE_MODE else can_read_evidence(user_id, evidence)
    if worker_authorized:
        job["state"] = "completed"
        job["version"] = 2
        job["download_path"] = f"/api/v1/exports/{job_id}/download"
        audit_write(evidence["organization_id"], "export.completed", evidence["id"], job_id, user_id)
    else:
        job["state"] = "failed"
        job["version"] = 2

    resp = make_response(jsonify({"job_id": job_id, "state": "queued", "version": 1}), 202)
    resp.headers["Location"] = f"/api/v1/exports/{job_id}"
    return resp


@app.route("/api/v1/exports/<job_id>", methods=["GET"])
def get_export(job_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    job = DB["export_jobs"].get(job_id)
    if job is None or job["actor_user_id"] != user_id:
        return problem(404, "Not Found")
    payload = {"job_id": job["job_id"], "state": job["state"], "source_id": job["source_id"], "version": job["version"]}
    if job["state"] == "completed":
        payload["download_path"] = job["download_path"]
    return jsonify(payload)


@app.route("/api/v1/exports/<job_id>/download", methods=["GET"])
def download_export(job_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    job = DB["export_jobs"].get(job_id)
    if job is None or job["actor_user_id"] != user_id:
        return problem(404, "Not Found")
    if job["state"] != "completed":
        return problem(409, "Conflict")
    evidence = DB["evidence"].get(job["source_id"])
    if evidence is None:
        return problem(404, "Not Found")
    if not VULNERABLE_MODE and not can_read_evidence(user_id, evidence):
        return problem(403, "Forbidden")
    resp = jsonify(serialize(evidence))
    resp.headers["Content-Disposition"] = f'attachment; filename="{job["source_id"]}.json"'
    return resp


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@app.route("/api/v1/orgs/<org_id>/audit-events", methods=["GET"])
def audit_events(org_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    membership = active_membership(user_id, org_id)
    if membership is None or membership["role"] not in (Role.MANAGER, Role.OWNER):
        return problem(403, "Forbidden")
    resource_id = request.args.get("resource_id")
    events = [e for e in DB["audit_events"] if e["organization_id"] == org_id]
    if resource_id:
        events = [e for e in events if e["resource_id"] == resource_id]
    return jsonify({"events": events})


# ---------------------------------------------------------------------------
# Membership administration (matrix rows not exercised as findings, but must
# still enforce the policy correctly so extra probing during a live
# walkthrough behaves as documented, not just the 5 tested paths)
# ---------------------------------------------------------------------------

@app.route("/api/v1/organizations/<org_id>/members/<target_user_id>", methods=["PATCH"])
def update_membership_state(org_id, target_user_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    membership = active_membership(user_id, org_id)
    if membership is None or membership["role"] not in (Role.MANAGER, Role.OWNER):
        return problem(403, "Forbidden")
    target = next((m for m in DB["memberships"].get(target_user_id, []) if m["organization_id"] == org_id), None)
    if target is None:
        return problem(404, "Not Found")
    if target["role"] != Role.ANALYST:
        return problem(403, "Forbidden")  # Managers may only suspend/restore Analysts
    body = request.get_json(force=True, silent=True) or {}
    new_state = body.get("state")
    if new_state not in ("suspended", "active"):
        return problem(400, "Bad Request")
    target["state"] = new_state
    return jsonify({"user_id": target_user_id, "organization_id": org_id, "state": new_state})


@app.route("/api/v1/organizations/<org_id>/members/<target_user_id>/role", methods=["PUT"])
def assign_role(org_id, target_user_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    membership = active_membership(user_id, org_id)
    if membership is None or membership["role"] != Role.OWNER:
        return problem(403, "Forbidden")  # only Owner assigns roles
    body = request.get_json(force=True, silent=True) or {}
    new_role = body.get("role")
    if new_role not in (Role.MANAGER.value, Role.ANALYST.value):
        return problem(422, "Unprocessable Entity")  # assigning Owner is out of scope
    target = next((m for m in DB["memberships"].get(target_user_id, []) if m["organization_id"] == org_id), None)
    if target is None:
        return problem(404, "Not Found")
    target["role"] = Role(new_role)
    return jsonify({"user_id": target_user_id, "organization_id": org_id, "role": new_role})


@app.route("/api/v1/organizations/<org_id>", methods=["DELETE"])
def delete_organization(org_id):
    user_id = current_user_id()
    if user_id is None:
        return problem(401, "Unauthorized")
    membership = active_membership(user_id, org_id)
    if membership is None or membership["role"] != Role.OWNER:
        return problem(403, "Forbidden")
    if org_id not in DB["organizations"]:
        return problem(404, "Not Found")
    del DB["organizations"][org_id]
    return "", 204


# ---------------------------------------------------------------------------
# Test convenience only -- not part of the case study
# ---------------------------------------------------------------------------

@app.route("/api/v1/_reset", methods=["POST"])
def reset_fixture():
    global DB
    DB = seed()
    return "", 204


if __name__ == "__main__":
    mode = "VULNERABLE" if VULNERABLE_MODE else "FIXED"
    print(f"Umber Desk 12 fixture running in {mode} mode -- http://127.0.0.1:5000")
    print("Login as e.g. ben.miller@meldran.test / fixture-password")
    app.run(host="127.0.0.1", port=5000, debug=False)
