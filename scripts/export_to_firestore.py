import json
import os
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta

import firebase_admin
from firebase_admin import credentials, firestore


def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def safe_id(value):
    value = str(value or "unknown")
    value = value.replace("/", "_").replace("\\", "_")
    value = re.sub(r"[^A-Za-z0-9_.-]", "_", value)
    return value[:140]


def strip_archive_ext(name):
    name = os.path.basename(str(name))
    for ext in [".tar.gz", ".tgz", ".whl", ".zip", ".tar"]:
        if name.endswith(ext):
            return name[:-len(ext)]
    return os.path.splitext(name)[0]


def find_latest_ml_log(package_file):
    pkg_stem = strip_archive_ext(package_file)
    ml_dir = Path("decoy_logs/ml_logs")
    candidates = []

    if ml_dir.exists():
        for p in ml_dir.glob("*.json"):
            data = read_json(p, {})
            data_pkg = os.path.basename(str(data.get("package", "")))
            if data_pkg == package_file or pkg_stem in p.name or pkg_stem in data_pkg:
                candidates.append((p.stat().st_mtime, p, data))

        if not candidates:
            for p in ml_dir.glob("*.json"):
                data = read_json(p, {})
                candidates.append((p.stat().st_mtime, p, data))

    if not candidates:
        return {}, ""

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][2], str(candidates[0][1])


def find_runtime_log(package_file, run_number):
    pkg_stem = strip_archive_ext(package_file)
    safe_stem = safe_id(pkg_stem)

    ptr = Path(f"decoy_logs/ptr_{package_file}.txt")
    if ptr.exists():
        target = Path(ptr.read_text(encoding="utf-8").strip())
        data = read_json(target, {})
        if data:
            return data, str(target)

    decoy_dir = Path("decoy_logs/decoy_runs")
    possible = [
        decoy_dir / f"{safe_stem}_run{run_number}_sandbox.json",
        decoy_dir / f"{pkg_stem}_run{run_number}_sandbox.json",
    ]

    for p in possible:
        data = read_json(p, {})
        if data:
            return data, str(p)

    candidates = []
    if decoy_dir.exists():
        for p in decoy_dir.glob("*_sandbox.json"):
            if safe_stem in p.name or pkg_stem in p.name:
                data = read_json(p, {})
                candidates.append((p.stat().st_mtime, p, data))

    if not candidates:
        latest = Path("decoy_logs/latest.json")
        data = read_json(latest, {})
        if data:
            return data, str(latest)
        return {}, ""

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][2], str(candidates[0][1])


def find_ebpf_log(package_file, run_number):
    pkg_stem = strip_archive_ext(package_file)
    safe_stem = safe_id(pkg_stem)

    decoy_dir = Path("decoy_logs/decoy_runs")
    possible = [
        decoy_dir / f"{safe_stem}_run{run_number}_ebpf.json",
        decoy_dir / f"{pkg_stem}_run{run_number}_ebpf.json",
    ]

    for p in possible:
        data = read_json(p, {})
        if data:
            return data, str(p)

    candidates = []
    if decoy_dir.exists():
        for p in decoy_dir.glob("*_ebpf.json"):
            if safe_stem in p.name or pkg_stem in p.name:
                data = read_json(p, {})
                candidates.append((p.stat().st_mtime, p, data))

    if not candidates:
        return {}, ""

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][2], str(candidates[0][1])


def summarize_honeytokens(runtime_log):
    hits = runtime_log.get("honeytoken_hits", []) or []
    types = []

    for h in hits:
        s = str(h).lower()
        if ".aws" in s or "credential" in s:
            types.append("fake_aws_credentials")
        elif ".env" in s:
            types.append("fake_env_file")
        elif ".ssh" in s or "id_rsa" in s:
            types.append("fake_ssh_key")
        elif "config" in s:
            types.append("fake_config_file")
        else:
            types.append("honeytoken_file")

    return {
        "triggered": len(hits) > 0,
        "hit_count": len(hits),
        "types": sorted(set(types))
    }


def summarize_network(runtime_log, ebpf_log):
    net = runtime_log.get("network_analysis", {}) or {}
    external_ips = net.get("external_ips", []) or []

    countries = []
    isps = []
    orgs = []

    for item in external_ips:
        if isinstance(item, dict):
            if item.get("country"):
                countries.append(item.get("country"))
            if item.get("isp"):
                isps.append(item.get("isp"))
            if item.get("org"):
                orgs.append(item.get("org"))

    ebpf_features = ebpf_log.get("ebpf_features", {}) or {}

    return {
        "external_ips_count": len(external_ips),
        "domains_count": len(net.get("real_domains", []) or []),
        "dns_queries_count": len(runtime_log.get("dns_queries", []) or runtime_log.get("dns", []) or []),
        "http_requests_count": len(runtime_log.get("http_requests", []) or []),
        "countries": sorted(set(countries)),
        "isps": sorted(set(isps)),
        "orgs": sorted(set(orgs)),
        "ebpf_network_activity": bool(ebpf_features.get("ebpf_network_activity", False)),
        "ebpf_remote_ips_count": ebpf_features.get("ebpf_remote_ips_count", 0)
    }


def decide_result(ml_log, runtime_log, ebpf_log):
    prediction = ml_log.get("prediction")
    probability = float(ml_log.get("risk_probability", 0) or 0)

    runtime_verdict = str(runtime_log.get("verdict", "CLEAN")).upper()
    runtime_score = int(runtime_log.get("score", 0) or 0)

    ebpf_features = ebpf_log.get("ebpf_features", {}) or {}
    ebpf_bad = any([
        ebpf_features.get("ebpf_privilege_escalation") is True,
        ebpf_features.get("ebpf_network_activity") is True,
        ebpf_features.get("ebpf_spawned_process") is True,
        ebpf_features.get("pattern_c2_communication") is True,
        ebpf_features.get("pattern_process_injection") is True,
        ebpf_features.get("pattern_privilege_escalation") is True,
    ])

    if prediction == 1 or probability >= 0.50:
        return "MALICIOUS"

    if runtime_verdict in ["SUSPICIOUS", "MALICIOUS", "CRITICAL"]:
        return "MALICIOUS"

    if runtime_score >= 1:
        return "MALICIOUS"

    if ebpf_bad:
        return "MALICIOUS"

    return "BENIGN"


def risk_level(final_result, probability, runtime_score):
    if final_result == "BENIGN":
        return "LOW"
    if probability >= 0.85 or runtime_score >= 20:
        return "CRITICAL"
    if probability >= 0.65 or runtime_score >= 10:
        return "HIGH"
    return "MEDIUM"


def trim_list(items, limit=50):
    if not isinstance(items, list):
        return []
    return items[:limit]


def init_firestore():
    service_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()

    if not service_json:
        raise RuntimeError("FIREBASE_SERVICE_ACCOUNT_JSON secret is missing.")

    service_account = json.loads(service_json)

    if not firebase_admin._apps:
        cred = credentials.Certificate(service_account)
        firebase_admin.initialize_app(cred)

    return firestore.client()


def main():
    package_file = os.environ.get("PACKAGE_FILE", "").strip()
    github_run_id = os.environ.get("GITHUB_RUN_ID", "").strip()
    github_run_number = os.environ.get("GITHUB_RUN_NUMBER", "").strip()
    github_sha = os.environ.get("GITHUB_SHA", "").strip()
    github_ref = os.environ.get("GITHUB_REF_NAME", "").strip()

    if not package_file:
        raise RuntimeError("PACKAGE_FILE is missing.")

    db = init_firestore()

    now = datetime.now(timezone.utc)
    raw_expires = now + timedelta(days=30)
    summary_expires = now + timedelta(days=180)

    run_id = f"{safe_id(package_file)}_{github_run_number or safe_id(github_run_id) or int(now.timestamp())}"

    ml_log, ml_source = find_latest_ml_log(package_file)
    runtime_log, runtime_source = find_runtime_log(package_file, github_run_number)
    ebpf_log, ebpf_source = find_ebpf_log(package_file, github_run_number)

    final_result = decide_result(ml_log, runtime_log, ebpf_log)
    probability = float(ml_log.get("risk_probability", 0) or 0)
    runtime_score = int(runtime_log.get("score", 0) or 0)

    behavior_findings = runtime_log.get("behavior_findings", []) or []
    processes = runtime_log.get("processes", []) or []
    accessed_files = runtime_log.get("accessed_files", []) or []
    dynamic_features = runtime_log.get("dynamic_features", {}) or {}
    ebpf_features = ebpf_log.get("ebpf_features", {}) or {}

    public_doc = {
        "run_id": run_id,
        "package": package_file,
        "package_stem": strip_archive_ext(package_file),
        "final_result": final_result,
        "is_malicious": final_result == "MALICIOUS",
        "risk_level": risk_level(final_result, probability, runtime_score),
        "risk_probability": probability,
        "ml_prediction": ml_log.get("prediction"),
        "runtime_verdict": runtime_log.get("verdict", "NO_RUNTIME_LOG"),
        "runtime_score": runtime_score,
        "findings_count": len(behavior_findings),
        "processes_count": len(processes),
        "accessed_files_count": len(accessed_files),
        "network_summary": summarize_network(runtime_log, ebpf_log),
        "honeytoken_summary": summarize_honeytokens(runtime_log),
        "top_findings": [
            {
                "tier": f.get("tier"),
                "label": f.get("label"),
                "weight": f.get("weight")
            }
            for f in behavior_findings[:10]
            if isinstance(f, dict)
        ],
        "dynamic_features": dynamic_features,
        "ebpf_features": ebpf_features,
        "sources": {
            "ml_log": ml_source,
            "runtime_log": runtime_source,
            "ebpf_log": ebpf_source
        },
        "updated_at": now,
        "expires_at": summary_expires,
    }

    analysis_doc = {
        "run_id": run_id,
        "package": package_file,
        "final_result": final_result,
        "risk_probability": probability,
        "runtime_score": runtime_score,
        "github_run_id": github_run_id,
        "github_run_number": github_run_number,
        "github_sha": github_sha,
        "github_ref": github_ref,
        "created_at": now,
        "expires_at": summary_expires,
    }

    raw_meta_doc = {
        "run_id": run_id,
        "package": package_file,
        "github_run_id": github_run_id,
        "github_run_number": github_run_number,
        "github_sha": github_sha,
        "github_ref": github_ref,
        "final_result": final_result,
        "sources": {
            "ml_log": ml_source,
            "runtime_log": runtime_source,
            "ebpf_log": ebpf_source
        },
        "created_at": now,
        "expires_at": raw_expires,
    }

    raw_ml_doc = {
        "run_id": run_id,
        "package": package_file,
        "source": ml_source,
        "data": ml_log,
        "created_at": now,
        "expires_at": raw_expires,
    }

    raw_runtime_doc = {
        "run_id": run_id,
        "package": package_file,
        "source": runtime_source,
        "data": {
            "verdict": runtime_log.get("verdict"),
            "score": runtime_log.get("score"),
            "behavior_findings": trim_list(behavior_findings, 100),
            "processes": trim_list(processes, 100),
            "accessed_files": trim_list(accessed_files, 100),
            "network_analysis": runtime_log.get("network_analysis", {}),
            "dns": trim_list(runtime_log.get("dns", []) or runtime_log.get("dns_queries", []), 100),
            "http_requests": trim_list(runtime_log.get("http_requests", []), 100),
            "dynamic_features": dynamic_features,
            "timeline": trim_list(runtime_log.get("timeline", []), 200),
        },
        "created_at": now,
        "expires_at": raw_expires,
    }

    raw_ebpf_doc = {
        "run_id": run_id,
        "package": package_file,
        "source": ebpf_source,
        "data": ebpf_log,
        "created_at": now,
        "expires_at": raw_expires,
    }

    batch = db.batch()

    batch.set(db.collection("analysis_runs").document(run_id), analysis_doc)

    batch.set(db.collection("raw_logs").document(run_id), raw_meta_doc)
    batch.set(db.collection("raw_ml_logs").document(run_id), raw_ml_doc)
    batch.set(db.collection("raw_runtime_logs").document(run_id), raw_runtime_doc)
    batch.set(db.collection("raw_ebpf_logs").document(run_id), raw_ebpf_doc)

    batch.set(db.collection("dashboard_public_runs").document(run_id), public_doc)
    batch.set(db.collection("dashboard_public").document("latest"), public_doc)

    batch.commit()

    print("Firestore export completed")
    print("run_id:", run_id)
    print("package:", package_file)
    print("final_result:", final_result)
    print("dashboard_public/latest updated")
    print("dashboard_public_runs/" + run_id + " created")
    print("restricted raw logs saved")


if __name__ == "__main__":
    main()