import json
import os
import re
import math
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
        "ebpf_remote_ips_count": ebpf_features.get("ebpf_remote_ips_count", 0),
    }


# NEW FUNCTION: ML-only decision
def ml_final_result(ml_log):
    prediction = ml_log.get("prediction")
    
    if str(prediction).upper() == "MALICIOUS" or prediction == 1:
        return "MALICIOUS"
    
    return "BENIGN"


# IMPROVED risk_level function
def risk_level(final_result, probability):
    if final_result == "BENIGN":
        return "LOW"
    
    if probability >= 0.85:
        return "CRITICAL"
    
    if probability >= 0.65:
        return "HIGH"
    
    return "MEDIUM"


def trim_list(items, limit=50):
    if not isinstance(items, list):
        return []
    return items[:limit]


def sanitize_for_firestore(value, depth=0):
    """
    Firestore rejects some Python/JSON structures, especially nested arrays.
    This function converts logs into Firestore-safe values.
    """
    if depth > 20:
        return str(value)

    if value is None:
        return None

    if isinstance(value, (str, bool, int)):
        return value

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return value

    if isinstance(value, datetime):
        return value

    if isinstance(value, dict):
        clean = {}
        for k, v in value.items():
            key = str(k).strip()
            if not key:
                key = "unknown_key"

            key = key.replace(".", "_").replace("/", "_").replace("\\", "_")

            clean[key] = sanitize_for_firestore(v, depth + 1)

        return clean

    if isinstance(value, (list, tuple, set)):
        clean_list = []

        for item in list(value)[:300]:
            # Firestore does not allow arrays directly inside arrays.
            if isinstance(item, (list, tuple, set)):
                clean_list.append({
                    "items": sanitize_for_firestore(list(item), depth + 1)
                })
            else:
                clean_list.append(sanitize_for_firestore(item, depth + 1))

        return clean_list

    return str(value)


# ============================================================

def safe_list(value, limit=20):
    if not value:
        return []
    if isinstance(value, list):
        out = []
        for item in value:
            if item is None:
                continue
            s = str(item).strip()
            if s and s not in out:
                out.append(s)
        return out[:limit]
    s = str(value).strip()
    return [s] if s else []


def compact_dict(d):
    """
    Keep only meaningful public values.
    Remove empty, false, zero, none-like values.
    """
    if not isinstance(d, dict):
        return {}

    cleaned = {}
    for k, v in d.items():
        if v is None:
            continue

        if isinstance(v, bool):
            if v is True:
                cleaned[k] = v
            continue

        if isinstance(v, (int, float)):
            if v != 0:
                cleaned[k] = v
            continue

        if isinstance(v, str):
            s = v.strip()
            if s and s.lower() not in {"none", "null", "undefined", "false", "0", "—"}:
                cleaned[k] = s
            continue

        if isinstance(v, list):
            arr = safe_list(v)
            if arr:
                cleaned[k] = arr
            continue

        if isinstance(v, dict):
            nested = compact_dict(v)
            if nested:
                cleaned[k] = nested

    return cleaned


def extract_top_shap(raw_ml_doc, limit=10):
    """
    Extract SHAP values from ML document with support for multiple formats.
    Returns list of dicts with 'feature' and 'value' keys.
    """
    raw_ml_doc = raw_ml_doc or {}

    if isinstance(raw_ml_doc, dict) and isinstance(raw_ml_doc.get("data"), dict):
        raw_ml_doc = raw_ml_doc.get("data") or {}

    candidates = [
        raw_ml_doc.get("top_shap"),
        raw_ml_doc.get("top_features"),
        raw_ml_doc.get("shap_values"),
        raw_ml_doc.get("shap_explanations"),
        raw_ml_doc.get("explanations"),
        raw_ml_doc.get("feature_importance"),
        raw_ml_doc.get("ml_explanation", {}).get("top_features") if isinstance(raw_ml_doc.get("ml_explanation"), dict) else None,
        raw_ml_doc.get("ml_explanation", {}).get("top_shap") if isinstance(raw_ml_doc.get("ml_explanation"), dict) else None,
    ]

    def to_number(value):
        try:
            if value is None:
                return None
            return float(value)
        except Exception:
            return None

    def add_item(out, name, value):
        value = to_number(value)
        if name is None or value is None:
            return


        out.append({
            "feature": str(name),
            "value": value
        })

    for item in candidates:
        if not item:
            continue

        out = []

        if isinstance(item, list):
            for x in item:
                if isinstance(x, dict):
                    if "items" in x and isinstance(x.get("items"), list) and len(x.get("items")) >= 2:
                        add_item(out, x["items"][0], x["items"][1])
                        continue

                    name = (
                        x.get("feature")
                        or x.get("name")
                        or x.get("key")
                        or x.get("feature_name")
                    )

                    value = (
                        x.get("value")
                        if x.get("value") is not None
                        else x.get("shap_value")
                        if x.get("shap_value") is not None
                        else x.get("impact")
                        if x.get("impact") is not None
                        else x.get("score")
                    )

                    add_item(out, name, value)

                elif isinstance(x, (list, tuple)) and len(x) >= 2:
                    add_item(out, x[0], x[1])

            if out:
                out.sort(key=lambda x: abs(x["value"]), reverse=True)
                return out[:limit]

        if isinstance(item, dict):
            for k, v in item.items():
                add_item(out, k, v)

            if out:
                out.sort(key=lambda x: abs(x["value"]), reverse=True)
                return out[:limit]

    return []


def extract_paths_matching(events, keywords, limit=20):
    """
    Extract file paths from runtime/eBPF events using keywords.
    Example keywords: ['.ssh', 'authorized_keys']
    """
    found = []
    keywords = [k.lower() for k in keywords]

    for item in events or []:
        text = item.get("event") if isinstance(item, dict) else str(item)
        text = str(text)

        if not any(k in text.lower() for k in keywords):
            continue

        matches = re.findall(r'(/[A-Za-z0-9._@%+=:,/~\-]+)', text)
        for m in matches:
            if any(k in m.lower() for k in keywords):
                if m not in found:
                    found.append(m)

    return found[:limit]


def extract_remote_ports(events, limit=30):
    found = []

    for item in events or []:
        text = item.get("event") if isinstance(item, dict) else str(item)
        text = str(text)

        # Match common socket/connect traces with ports
        for p in re.findall(r'htons\((\d+)\)', text):
            if p not in found:
                found.append(p)

        # Match plain suspicious ports if logged directly
        for p in re.findall(r'\b(21|22|23|25|53|80|443|4444|5555|6667|8080|9001)\b', text):
            if p not in found:
                found.append(p)

    return found[:limit]


def extract_ips_from_anything(obj, limit=30):
    text = str(obj)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

    cleaned = []
    for ip in ips:
        if ip.startswith("127.") or ip == "0.0.0.0":
            continue
        if ip not in cleaned:
            cleaned.append(ip)

    return cleaned[:limit]


def extract_public_runtime_values(raw_runtime_doc):
    """
    Extract meaningful public-safe values from restricted raw_runtime_logs.
    No full raw logs are exposed.
    """
    raw_runtime_doc = raw_runtime_doc or {}

    timeline = raw_runtime_doc.get("timeline") or []
    accessed_files = safe_list(raw_runtime_doc.get("accessed_files"), 30)
    processes = safe_list(raw_runtime_doc.get("processes"), 20)
    http_requests = raw_runtime_doc.get("http_requests") or []
    dns = raw_runtime_doc.get("dns") or []
    network = raw_runtime_doc.get("network_analysis") or {}

    ssh_paths = extract_paths_matching(timeline, [".ssh", "authorized_keys", "id_rsa"])
    env_paths = extract_paths_matching(timeline, [".env", "credentials", "secrets"])
    passwd_paths = extract_paths_matching(timeline, ["/etc/passwd", "/etc/shadow"])
    tmp_paths = extract_paths_matching(timeline, ["/tmp"], limit=10)

    remote_ips = []
    if isinstance(network, dict):
        for item in network.get("external_ips", []) or []:
            if isinstance(item, dict) and item.get("ip"):
                remote_ips.append(str(item.get("ip")))
            elif item:
                remote_ips.append(str(item))

    remote_ips += extract_ips_from_anything(raw_runtime_doc)
    remote_ips = safe_list(remote_ips, 20)

    remote_ports = extract_remote_ports(timeline)

    public_runtime_values = {
        "accessed_files": accessed_files[:20],
        "processes": processes[:20],
        "ssh_paths_accessed": ssh_paths,
        "secret_paths_accessed": env_paths,
        "system_sensitive_paths_accessed": passwd_paths,
        "tmp_paths_accessed": tmp_paths,
        "remote_ips": remote_ips,
        "remote_ports": remote_ports,
        "dns_queries": safe_list(dns, 20),
        "http_requests": [
            {
                "method": r.get("method", "GET"),
                "path": r.get("path", ""),
                "host": r.get("host", ""),
            }
            for r in http_requests[:15]
            if isinstance(r, dict)
        ],
    }

    return compact_dict(public_runtime_values)


def extract_public_ebpf_values(raw_ebpf_doc):
    """
    Extract meaningful public-safe values from restricted raw_ebpf_logs.
    """
    raw_ebpf_doc = raw_ebpf_doc or {}

    features = (
        raw_ebpf_doc.get("dynamic_features")
        or raw_ebpf_doc.get("ebpf_features")
        or raw_ebpf_doc
        or {}
    )

    public_ebpf_values = {}

    if isinstance(features, dict):
        remote_ips = features.get("ebpf_remote_ips") or features.get("remote_ips")
        remote_ports = features.get("ebpf_remote_ports") or features.get("remote_ports")

        public_ebpf_values.update({
            "cloud_remote_ips": safe_list(remote_ips, 20),
            "cloud_remote_ports": safe_list(remote_ports, 20),
            "cloud_security_ops": features.get("ebpf_security_ops"),
            "cloud_network_ops": features.get("ebpf_network_ops"),
            "cloud_process_ops": features.get("ebpf_process_ops"),
            "cloud_file_ops": features.get("ebpf_file_ops"),
            "root_dir_access_count": features.get("root_dir_access"),
            "home_dir_access_count": features.get("home_dir_access"),
            "etc_dir_access_count": features.get("etc_dir_access"),
            "tmp_dir_access_count": features.get("tmp_dir_access"),
            "other_dir_access_count": features.get("other_dir_access"),
        })

    return compact_dict(public_ebpf_values)


# ============================================================


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
# ECC 2:2024 control 2.12.3.5 requires cybersecurity event logs
# to be retained for at least 12 months. 
    CYBERSECURITY_EVENT_LOG_RETENTION_DAYS = 365
    SUMMARY_RETENTION_DAYS = 365
    
    raw_expires = now + timedelta(days=CYBERSECURITY_EVENT_LOG_RETENTION_DAYS)
    summary_expires = now + timedelta(days=SUMMARY_RETENTION_DAYS)

    run_id = f"{safe_id(package_file)}_{github_run_number or safe_id(github_run_id) or int(now.timestamp())}"

    ml_log, ml_source = find_latest_ml_log(package_file)
    runtime_log, runtime_source = find_runtime_log(package_file, github_run_number)
    ebpf_log, ebpf_source = find_ebpf_log(package_file, github_run_number)

    top_shap_values = extract_top_shap(ml_log)

    # MODIFIED: Use ml_final_result instead of decide_result
    final_result = ml_final_result(ml_log)
    probability = float(ml_log.get("risk_probability", 0) or 0)

    processes = runtime_log.get("processes", []) or []
    accessed_files = runtime_log.get("accessed_files", []) or []
    dynamic_features = runtime_log.get("dynamic_features", {}) or {}
    ebpf_features = ebpf_log.get("ebpf_features", {}) or {}

    # ============================================================
    public_runtime_values = extract_public_runtime_values(runtime_log)
    public_ebpf_values = extract_public_ebpf_values(ebpf_log)

    public_doc = {
        "run_id": run_id,
        "package": package_file,
        "package_stem": strip_archive_ext(package_file),
        "final_result": final_result,
        "is_malicious": final_result == "MALICIOUS",
        "risk_level": risk_level(final_result, probability),
        "risk_probability": probability,
        "ml_prediction": ml_log.get("prediction"),
        "processes_count": len(processes),
        "accessed_files_count": len(accessed_files),
        "network_summary": summarize_network(runtime_log, ebpf_log),
        "dynamic_features": compact_dict(dynamic_features),
        "ebpf_features": compact_dict(ebpf_features),
        "public_runtime_values": public_runtime_values,
        "public_ebpf_values": public_ebpf_values,
        "sources": {
            "ml_log": ml_source,
            "runtime_log": runtime_source,
            "ebpf_log": ebpf_source,
        },
        "updated_at": now,
        "expires_at": summary_expires,
        "top_shap": top_shap_values,
    }

    analysis_doc = {
        "run_id": run_id,
        "package": package_file,
        "final_result": final_result,
        "risk_probability": probability,
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
            "ebpf_log": ebpf_source,
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

    analysis_doc = sanitize_for_firestore(analysis_doc)
    raw_meta_doc = sanitize_for_firestore(raw_meta_doc)
    raw_ml_doc = sanitize_for_firestore(raw_ml_doc)
    raw_runtime_doc = sanitize_for_firestore(raw_runtime_doc)
    raw_ebpf_doc = sanitize_for_firestore(raw_ebpf_doc)
    public_doc = sanitize_for_firestore(public_doc)

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
    print(f"top_shap extracted: {len(top_shap_values)} features")


if __name__ == "__main__":
    main()
